"""Collect historical reviewed Git trees without repeated repository archives.

All Git commands are local and disable lazy fetching. Missing objects are listed
for an explicit external bulk fetch; no credentials or package code are used.
"""
from __future__ import annotations

import argparse
import base64
from bisect import bisect_right
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "src"))
from pcom01.advisories import AdvisorySnapshot, _build_snapshot, utc
from pcom01.git_evidence import SOURCE_KIND, object_id, tree_entries, _inventory, _blob_fact, _shard, clear_inventory_cache
from pcom01.io import now, read_json, save_json, sha256
from pcom01.release import select_anchor


class LocalGit:
    def __init__(self, path):
        self.path = Path(path)
        self.env = {**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"}

    def run(self, *arguments, input=None):
        return subprocess.check_output(["git", "--git-dir=" + str(self.path), *arguments],
                                       input=input, env=self.env, stderr=subprocess.PIPE)


class BatchObjects:
    def __init__(self, git):
        self.process = subprocess.Popen(["git", "--git-dir=" + str(git.path), "cat-file", "--batch"],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, env=git.env)

    def read(self, oid, expected_kind=None):
        self.process.stdin.write(oid.encode() + b"\n")
        self.process.stdin.flush()
        header = self.process.stdout.readline().split()
        if len(header) != 3 or header[1] == b"missing":
            raise ValueError("Missing local Git object: " + oid)
        actual, kind, size = header[0].decode(), header[1].decode(), int(header[2])
        raw = self.process.stdout.read(size)
        if self.process.stdout.read(1) != b"\n" or len(raw) != size:
            raise ValueError("Truncated Git object batch response")
        if (expected_kind and kind != expected_kind) or actual != oid or object_id(kind, raw) != oid:
            raise ValueError("Git object type or digest mismatch")
        return raw

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=30)


def planned_packages(root):
    selected = [item["name"] for item in read_json(root / "config/packages.json")["packages"]]
    original = read_json(root / "data/provenance/acquisition.json")
    if original["selection_sha256"] != sha256(root / "config/packages.json"):
        raise ValueError("Expanded selection differs from its registry acquisition")
    decisions, boundaries = {}, set()
    for package in selected:
        info = original["packages"][package]["registry"]
        if sha256(root / info["path"]) != info["stored_sha256"]:
            raise ValueError("Original registry source digest mismatch")
        decision = select_anchor(read_json(root / info["path"]), package, "supplied")
        if not decision["origin"] or not decision["supplied_record_count"]:
            raise ValueError("Selected expanded package has no valid supplied anchor: " + package)
        decisions[package] = decision
        boundaries.update((decision["origin"], decision["outcome_end"]))
    return selected, decisions, sorted(boundaries)


def resolve_boundaries(git, boundaries, comparison_root):
    """Resolve against recorded main history and cross-check all known API facts."""
    head = git.run("rev-parse", "HEAD").decode().strip()
    lines = git.run("log", "--format=%H%x09%cI", "--since-as-filter=2025-05-01T00:00:00Z", head).decode().splitlines()
    history = [(line.split("\t")[0], line.split("\t")[1]) for line in lines]

    def resolve(boundary):
        edge = utc(boundary)
        found = next(((oid, stamp) for oid, stamp in history if utc(stamp) < edge), None)
        if found is None:
            raise ValueError("Local main history does not cover boundary " + boundary)
        oid, stamp = found
        return {"sha": oid, "committed_at": utc(stamp).isoformat().replace("+00:00", "Z"),
                "html_url": "https://github.com/github/advisory-database/commit/" + oid}

    checks = []
    historical = read_json(comparison_root / "data/provenance/release-resolutions.json")["resolutions"]
    for boundary, entry in historical.items():
        actual = resolve(boundary)
        expected = entry["commit"]
        equal = actual["sha"] == expected["sha"] and utc(actual["committed_at"]) == utc(expected["committed_at"])
        checks.append({"boundary": boundary, "local_commit": actual["sha"],
                       "api_commit": expected["sha"], "matched": equal})
    if not all(item["matched"] for item in checks):
        raise ValueError("Local Git boundary resolution differs from retained GitHub API evidence: "
                         + json.dumps([item for item in checks if not item["matched"]]))
    return {boundary: resolve(boundary) for boundary in boundaries}, {
        "method": "first pre-boundary commit in local git log traversal of official main",
        "source": "https://github.com/github/advisory-database.git", "head_commit": head,
        "history_lower_filter": "2025-05-01T00:00:00Z", "strict_boundary": True,
        "known_api_comparisons": checks, "all_known_api_comparisons_match": True,
        "new_boundary_resolution": "Local official Git mirror; not a new GitHub API observation."}


def inventory_at(git, commit):
    raw = git.run("ls-tree", "-r", "-z", commit, "--", "advisories/github-reviewed")
    prefix, entries = "advisories/github-reviewed/", []
    for token in raw.split(b"\0"):
        if not token:
            continue
        description, path = token.split(b"\t", 1)
        mode, kind, oid = description.decode().split()
        path = path.decode("utf-8")
        if not path.startswith(prefix) or kind != "blob" or mode not in ("100644", "100755"):
            raise ValueError("Unexpected entry in the complete reviewed Git subtree")
        entries.append({"path": path[len(prefix):], "mode": mode, "blob_sha": oid})
    if not entries:
        raise ValueError("Reviewed Git subtree is empty")
    return sorted(entries, key=lambda item: item["path"])


def bounded_inventories(pool, git, commits):
    for start in range(0, len(commits), 4):
        futures = [pool.submit(inventory_at, git, item["sha"]) for item in commits[start:start + 4]]
        for future in futures:
            yield future.result()


def prepare(root, git, comparison_root):
    packages, decisions, boundaries = planned_packages(root)
    resolutions, audit = resolve_boundaries(git, boundaries, comparison_root)
    save_json(root / "data/provenance/git-resolution-audit.json", audit)
    unique = sorted({item["sha"]: item for item in resolutions.values()}.values(), key=lambda item: item["committed_at"])
    reader, captures, all_blobs = BatchObjects(git), {}, set()
    previous, previous_tree, previous_digest = {}, None, None
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            for index, (commit, entries) in enumerate(zip(unique, bounded_inventories(pool, git, unique))):
                commit_raw = reader.read(commit["sha"], "commit")
                root_sha = next(line[5:].decode() for line in commit_raw.splitlines() if line.startswith(b"tree "))
                root_raw = reader.read(root_sha, "tree")
                advisory_sha = tree_entries(root_raw)["advisories"][1]
                advisory_raw = reader.read(advisory_sha, "tree")
                reviewed_sha = tree_entries(advisory_raw)["github-reviewed"][1]
                current = {item["path"]: item for item in entries}
                document = {"schema_version": 1, "tree_sha": reviewed_sha, "entries": entries}
                if previous_tree and index % 24:
                    document.update(base_tree_sha=previous_tree, base_sha256=previous_digest,
                                    deleted=sorted(set(previous) - set(current)),
                                    entries=[current[path] for path in sorted(current) if current[path] != previous.get(path)])
                path = root / "data/raw/git-reviewed-trees" / (reviewed_sha + ".json.gz")
                if not path.exists():
                    save_json(path, document)
                digest = sha256(path)
                captures[commit["sha"]] = {"commit_object_base64": base64.b64encode(commit_raw).decode(),
                    "root_tree_base64": base64.b64encode(root_raw).decode(),
                    "advisories_tree_base64": base64.b64encode(advisory_raw).decode(),
                    "reviewed_tree_sha": reviewed_sha, "inventory_path": path.relative_to(root).as_posix(),
                    "inventory_sha256": digest}
                all_blobs.update(item["blob_sha"] for item in entries if item["path"].endswith(".json"))
                previous, previous_tree, previous_digest = current, reviewed_sha, digest
                if index % 25 == 0:
                    print(json.dumps({"trees_prepared": index + 1, "total_trees": len(unique), "unique_blobs": len(all_blobs)}), flush=True)
    finally:
        reader.close()
    plan = {"schema_version": 1, "prepared_at": now(), "selection_sha256": sha256(root / "config/packages.json"),
            "packages": packages, "resolutions": resolutions, "git_sources": captures,
            "resolution_audit_sha256": sha256(root / "data/provenance/git-resolution-audit.json"),
            "blob_ids": sorted(all_blobs)}
    save_json(root / "data/provenance/git-capture-plan.json", plan)
    checked = git.run("cat-file", "--batch-check=%(objectname) %(objecttype)",
                      input=("\n".join(sorted(all_blobs)) + "\n").encode()).decode().splitlines()
    missing = [line.split()[0] for line in checked if line.endswith(" missing")]
    path = root / "data/provenance/git-missing-blobs.txt"
    path.write_text("\n".join(missing) + ("\n" if missing else ""), encoding="ascii")
    print(json.dumps({"packages": len(packages), "boundaries": len(boundaries), "unique_commits": len(unique),
                      "unique_reviewed_blobs": len(all_blobs), "missing_local_blobs": len(missing),
                      "missing_blob_list": str(path)}, indent=2), flush=True)
    return plan


def retain_blobs(root, git, plan):
    """Retain exact original bytes once per object, in bounded gzip shards."""
    groups = {}
    for oid in plan["blob_ids"]:
        groups.setdefault(oid[:2], []).append(oid)
    reader, shards = BatchObjects(git), {}
    try:
        for prefix, ids in sorted(groups.items()):
            path = root / "data/raw/git-blob-shards" / (prefix + ".json.gz")
            objects = {}
            for oid in ids:
                raw = reader.read(oid, "blob")
                if len(raw) > 16 * 1024 * 1024:
                    raise ValueError("Unexpected advisory Git blob size")
                objects[oid] = base64.b64encode(raw).decode("ascii")
            save_json(path, {"schema_version": 1, "objects": objects})
            if path.stat().st_size >= 90 * 1024 * 1024:
                raise ValueError("Original Git object shard exceeds repository file limit")
            shards[prefix] = {"path": path.relative_to(root).as_posix(), "sha256": sha256(path),
                              "objects": len(objects), "bytes": path.stat().st_size}
            if int(prefix, 16) % 16 == 0:
                print(json.dumps({"blob_shards_written": len(shards), "total_shards": len(groups)}), flush=True)
    finally:
        reader.close()
    inventory = {"schema_version": 1, "source_kind": "original_git_blob_objects",
                 "source": "https://github.com/github/advisory-database.git", "shards": shards,
                 "unique_objects": sum(item["objects"] for item in shards.values())}
    save_json(root / "data/provenance/git-blob-shards.json", inventory)
    return inventory


def capture(root, git, *, seal=False):
    plan = read_json(root / "data/provenance/git-capture-plan.json")
    packages, decisions, boundaries = planned_packages(root)
    if (plan["selection_sha256"] != sha256(root / "config/packages.json")
            or plan["packages"] != packages or sorted(plan["resolutions"]) != boundaries):
        raise ValueError("Expanded registry selection/origins changed since Git preparation")
    blob_index_path = root / "data/provenance/git-blob-shards.json"
    if not blob_index_path.exists():
        retain_blobs(root, git, plan)
    blob_index = read_json(blob_index_path)
    blob_digest = sha256(blob_index_path)
    original_path = root / "data/provenance/acquisition.json"
    manifest_path = root / "data/provenance/release-acquisition.json"
    manifest = {"started_at": now(), "selection_sha256": plan["selection_sha256"],
                "original_acquisition_sha256": sha256(original_path), "source_kind": SOURCE_KIND,
                "claim": "Complete historical reviewed Git trees; not an exact historical GitHub service export.",
                "requested_scopes": ["supplied"], "requested_boundaries": boundaries,
                "snapshots": {}, "failures": [], "requested_sources_complete": False,
                "resolution_audit_sha256": sha256(root / "data/provenance/git-resolution-audit.json"),
                "git_capture_plan_sha256": sha256(root / "data/provenance/git-capture-plan.json")}
    if manifest_path.exists():
        previous = read_json(manifest_path)
        if previous.get("selection_sha256") != plan["selection_sha256"]:
            raise ValueError("Refusing to replace a different Git source cohort")
        manifest["snapshots"] = previous.get("snapshots", {})
        for boundary, old in manifest["snapshots"].items():
            if boundary not in boundaries or sha256(root / old["bundle_path"]) != old["bundle_sha256"]:
                raise ValueError("Previously captured Git source changed; refusing overwrite")
    save_json(manifest_path, manifest)
    selected = set(packages)
    root_string = str(root.resolve())
    clear_inventory_cache()
    ordered = sorted(boundaries, key=lambda edge: (plan["resolutions"][edge]["committed_at"], edge))
    for index, boundary in enumerate(ordered):
        if boundary in manifest["snapshots"]:
            continue
        commit = plan["resolutions"][boundary]
        source = dict(plan["git_sources"][commit["sha"]])
        source.update(selection_sha256=plan["selection_sha256"], blob_index_sha256=blob_digest)
        inventory = _inventory(root_string, source["reviewed_tree_sha"], source["inventory_sha256"])

        matched, all_ids = [], set()
        reviewed_count = 0
        for item in inventory:
            if not item["path"].endswith(".json"):
                continue
            reviewed_count += 1
            oid = item["blob_sha"]
            identity, names, digest, projection = _blob_fact(root_string, oid, blob_index["shards"][oid[:2]]["sha256"])
            if identity != Path(item["path"]).stem or identity in all_ids:
                raise ValueError("Original reviewed filename/advisory identity disagreement or duplicate")
            all_ids.add(identity)
            if names & selected or "*" in names:
                raw = base64.b64decode(_shard(root_string, oid[:2], blob_index["shards"][oid[:2]]["sha256"])[oid])
                matched.append(("advisories/github-reviewed/" + item["path"], json.loads(raw)))
        # Every original blob and package mapping was checked above. Only the
        # selected documents need repeated boundary-specific timestamp checks.
        snapshot = (_build_snapshot(matched, packages, boundary, commit["sha"], commit["committed_at"], None)
                    if matched else AdvisorySnapshot(utc(boundary), commit["sha"], utc(commit["committed_at"]),
                        frozenset(packages), {}, frozenset(), 0, None))
        snapshot.reviewed_files_scanned = reviewed_count
        snapshot.all_ghsa_ids = frozenset(all_ids)
        proof = snapshot.provenance()
        proof.update(source_kind=SOURCE_KIND, git_source=source,
                     method="complete reviewed Git subtree verified by commit/tree/blob object identities")
        path = root / "data/raw/release-advisories" / (hashlib.sha256(boundary.encode()).hexdigest()[:24] + ".json.gz")
        save_json(path, {"provenance": proof, "records": snapshot.raw_records()})
        manifest["snapshots"][boundary] = {"boundary": boundary, "commit": commit,
            "source_kind": SOURCE_KIND, "git_source": source, "archive_sha256": None,
            "resolution": {"method": "local_official_git_main_history", "strictly_before": boundary,
                           "audit_path": "data/provenance/git-resolution-audit.json"},
            "bundle_path": path.relative_to(root).as_posix(), "bundle_sha256": sha256(path)}
        if index % 20 == 0:
            save_json(manifest_path, manifest)
            print(json.dumps({"snapshots_retained": len(manifest["snapshots"]), "requested": len(boundaries),
                              "boundary": boundary, "blocked_packages_in_snapshot": len(snapshot.issues)}), flush=True)
    # Registry/download collection may have continued during this local Git scan.
    # Only an explicit final seal can bind the completed acquisition file.
    manifest["missing_requested_boundaries"] = sorted(set(boundaries) - set(manifest["snapshots"]))
    manifest["requested_sources_complete"] = bool(seal and not manifest["missing_requested_boundaries"])
    manifest["final_source_binding_sealed"] = bool(seal)
    manifest["original_acquisition_sha256"] = sha256(original_path)
    manifest["completed_at"] = now()
    if seal:
        current_packages, _, current_boundaries = planned_packages(root)
        original = read_json(original_path)
        if current_packages != packages or current_boundaries != boundaries:
            raise ValueError("Expanded package origins changed before final source seal")
        for package in packages:
            download = original["packages"][package].get("downloads", {})
            if "path" not in download or sha256(root / download["path"]) != download["stored_sha256"]:
                raise ValueError("Expanded download capture is incomplete: " + package)
    save_json(manifest_path, manifest)
    print(json.dumps({"snapshots": len(manifest["snapshots"]), "sealed": manifest["final_source_binding_sealed"]}), flush=True)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "capture", "seal"))
    parser.add_argument("--root", type=Path, default=REPOSITORY / "datasets/training")
    parser.add_argument("--git", type=Path, default=REPOSITORY.parent / ".source-cache/advisory-database.git")
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args.root, LocalGit(args.git), REPOSITORY)
    else:
        capture(args.root, LocalGit(args.git), seal=args.command == "seal")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
