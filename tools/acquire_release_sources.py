"""Capture complete historical GHSA trees as hashed measurement projections.

Full archives are scanned in a temporary cache. Missing snapshots are not
replaced by current advisory state; original captures remain separate.
"""
from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, ThreadPoolExecutor, wait
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcom01.advisories import HistoricalEvidenceError, SHA_RE, load_snapshot_archive, utc
from pcom01.io import AcquisitionError, PublicClient, now, read_json, save_json, sha256
from pcom01.pipeline import selected_packages


def resolution_url(boundary):
    """Git's second-precision lookup must remain strictly before the boundary."""
    instant = utc(boundary)
    # Git commit timestamps are whole seconds. Include the previous whole
    # second, or the same second when the release has a fractional component.
    before = (instant - timedelta(microseconds=1)).replace(microsecond=0)
    return ("https://api.github.com/repos/github/advisory-database/commits?until="
            + before.isoformat().replace("+00:00", "Z") + "&per_page=1")


def _project_commit_response(payload):
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        raise AcquisitionError("Expected exactly one pre-origin Git commit object")
    item = payload[0]
    details = item.get("commit")
    committer = details.get("committer") if isinstance(details, dict) else None
    if not isinstance(committer, dict):
        raise AcquisitionError("Git commit response has no committer object")
    commit = {"sha": item.get("sha"), "committed_at": committer.get("date"),
              "html_url": item.get("html_url")}
    if not isinstance(commit["sha"], str) or not SHA_RE.fullmatch(commit["sha"]):
        raise AcquisitionError("Git commit response requires an immutable full SHA")
    utc(commit["committed_at"])
    if commit["html_url"] != "https://github.com/github/advisory-database/commit/" + commit["sha"]:
        raise AcquisitionError("Git commit URL identifies a different repository or revision")
    return commit


def cached_resolution(root, boundary):
    """Validate a cached GitHub connector response against its request and hash.

    Invalid cached evidence fails without falling back to a fresh HTTP lookup.
    """
    path = Path(root) / "data/provenance/release-resolutions.json"
    if not path.exists():
        return None
    cache = read_json(path)
    if not isinstance(cache, dict) or cache.get("schema_version") != 1 or not isinstance(cache.get("resolutions"), dict):
        raise AcquisitionError("Invalid release resolution cache schema")
    entry = cache["resolutions"].get(boundary)
    if entry is None:
        return None
    if not isinstance(entry, dict):
        raise AcquisitionError("Release resolution cache entry must be an object")
    response, resolution, commit = entry.get("response"), entry.get("resolution"), entry.get("commit")
    if not isinstance(response, list) or len(response) != 1 or not isinstance(response[0], dict):
        raise AcquisitionError("Cached resolution requires exactly one complete commit response")
    if not isinstance(resolution, dict) or not isinstance(commit, dict):
        raise AcquisitionError("Cached resolution metadata or commit is missing")
    digest = hashlib.sha256(json.dumps(response, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()
    if resolution.get("response_sha256") != digest:
        raise AcquisitionError("Cached commit response digest mismatch")
    if resolution.get("url") != resolution_url(boundary):
        raise AcquisitionError("Cached commit request does not match the strict pre-boundary query")
    if resolution.get("retrieved_via") != "GitHub connector":
        raise AcquisitionError("Cached resolution does not identify its GitHub connector provenance")
    fetched = resolution.get("fetched_at")
    if not isinstance(fetched, str) or not fetched.endswith("Z"):
        raise AcquisitionError("Cached resolution fetched_at must be a UTC timestamp")
    utc(fetched)
    expected = _project_commit_response(response)
    if commit != expected:
        raise AcquisitionError("Cached commit projection differs from the retained API response")
    if not isinstance(commit["sha"], str) or not SHA_RE.fullmatch(commit["sha"]):
        raise AcquisitionError("Cached commit requires an immutable full SHA")
    if utc(commit["committed_at"]) >= utc(boundary):
        raise AcquisitionError("Cached commit is not strictly before the boundary")
    if commit["html_url"] != "https://github.com/github/advisory-database/commit/" + commit["sha"]:
        raise AcquisitionError("Cached commit URL identifies a different repository or revision")
    return entry


def snapshot(client, boundary, packages, root, previous=None):
    instant = utc(boundary)
    url = resolution_url(boundary)
    cached = cached_resolution(root, boundary) if previous is None else None
    if previous:
        commit, resolution = previous["commit"], previous["resolution"]
    elif cached is not None:
        commit, resolution = cached["commit"], cached["resolution"]
    else:
        payload, resolution = client.json(url)
        commit = _project_commit_response(payload)
    if utc(commit["committed_at"]) >= instant:
        raise AcquisitionError("Resolved commit is not strictly before the boundary")
    archive_url = "https://codeload.github.com/github/advisory-database/tar.gz/" + commit["sha"]
    cache = root / "data/cache/release-downloads"
    cache.mkdir(parents=True, exist_ok=True)
    # TemporaryDirectory removes only this call's cache files.
    with tempfile.TemporaryDirectory(prefix="snapshot-", dir=cache) as directory:
        archive = Path(directory) / "source.tar.gz"
        print(f"Downloading and scanning {boundary} ({commit['sha']})", flush=True)
        _, download = client.get(archive_url, destination=archive)
        scanned = load_snapshot_archive(archive, packages, boundary, commit["sha"], commit["committed_at"])
        archive_hash = sha256(archive)
        key = hashlib.sha256(boundary.encode()).hexdigest()[:24]
        path = root / "data/raw/release-advisories" / (key + ".json.gz")
        save_json(path, {"provenance": scanned.provenance(), "records": scanned.raw_records()})
    return {"boundary": boundary, "commit": commit, "resolution": resolution,
            "download": download, "archive_sha256": archive_hash,
            "bundle_path": path.relative_to(root).as_posix(), "bundle_sha256": sha256(path)}


def _fetch_snapshot(root, boundary, packages):
    """Picklable worker; only its unique capture files and HTTP state are local."""
    client = PublicClient(attempts=3, timeout=60)
    try:
        info = snapshot(client, boundary, packages, root)
        return info, None, client.events
    except (AcquisitionError, HistoricalEvidenceError, OSError, ValueError, KeyError, TypeError) as exc:
        return None, {"boundary": boundary, "at": now(), "error": str(exc),
                      "error_type": type(exc).__name__}, client.events


def acquire(root, scopes, packages_filter=None, limit=None, workers=1):
    from pcom01.release import plan
    if type(workers) is not int or not 1 <= workers <= 4:
        raise ValueError("workers must be an integer between 1 and 4")
    if limit is not None and (type(limit) is not int or limit < 1):
        raise ValueError("limit must be a positive integer")
    planned = plan(root)
    packages = selected_packages(root)
    if packages_filter and set(packages_filter) - set(packages):
        raise ValueError("Package filter contains an unselected package")
    boundaries = set()
    for scope in scopes:
        for package, decision in planned["scopes"][scope]["packages"].items():
            if packages_filter and package not in packages_filter:
                continue
            if decision.get("origin") and decision.get("supplied_record_count", 0):
                boundaries.update((decision["origin"], decision["outcome_end"]))
    manifest_path = root / "data/provenance/release-acquisition.json"
    manifest = read_json(manifest_path) if manifest_path.exists() else {
        "started_at": now(), "selection_sha256": planned["selection_sha256"],
        "original_acquisition_sha256": planned["original_acquisition_sha256"],
        "snapshots": {}, "failures": [],
        "claim": "Historical Git mirror evidence, not an exact historical GitHub service export."}
    for key in ("selection_sha256", "original_acquisition_sha256"):
        if manifest[key] != planned[key]:
            raise ValueError(f"Release acquisition no longer matches {key}")
    manifest["requested_scopes"] = sorted(set(manifest.get("requested_scopes", [])) | set(scopes))
    manifest["requested_boundaries"] = sorted(set(manifest.get("requested_boundaries", [])) | boundaries)
    acquired = 0
    events = []
    invalid_boundaries = []
    stopped = False
    stop_path = root / "data/cache/release-downloads/STOP-ADMISSION"
    manifest["admission_stop_requested"] = False
    manifest["workers"] = workers
    manifest["worker_mode"] = "processes" if workers > 1 else "single_thread"
    try:
        # Revalidate retained captures, including scopes outside this invocation.
        for boundary in sorted(manifest["requested_boundaries"]):
            old = manifest["snapshots"].get(boundary)
            if old:
                try:
                    stored = root / old["bundle_path"]
                    if not stored.is_file() or sha256(stored) != old["bundle_sha256"]:
                        raise ValueError("Recorded release source is absent or altered; refusing overwrite")
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    invalid_boundaries.append(boundary)
                    manifest["failures"].append({"boundary": boundary, "at": now(),
                                                 "error": str(exc), "error_type": type(exc).__name__})
                    stopped = True
        missing = sorted(boundaries - set(manifest["snapshots"]))
        # Record broader requests before workers can leave a partial run.
        manifest["invalid_recorded_boundaries"] = sorted(invalid_boundaries)
        manifest["missing_requested_boundaries"] = sorted(
            (set(manifest["requested_boundaries"]) - set(manifest["snapshots"])) | set(invalid_boundaries))
        manifest["requested_sources_complete"] = not manifest["missing_requested_boundaries"]
        save_json(manifest_path, manifest)
        remaining = iter(missing if limit is None else missing[:limit])
        executor = ProcessPoolExecutor if workers > 1 else ThreadPoolExecutor
        with executor(max_workers=workers) as pool:
            pending = {}

            def admit():
                nonlocal stopped
                if stop_path.exists():
                    stopped = True
                    manifest["admission_stop_requested"] = True
                while not stopped and len(pending) < workers:
                    boundary = next(remaining, None)
                    if boundary is None:
                        break
                    pending[pool.submit(_fetch_snapshot, root, boundary, packages)] = boundary

            admit()
            while pending:
                done, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in sorted(done, key=lambda item: pending[item]):
                    boundary = pending.pop(future)
                    try:
                        info, failure, worker_events = future.result()
                    except Exception as exc:
                        # Retain successful captures when another worker fails.
                        info, worker_events = None, []
                        failure = {"boundary": boundary, "at": now(), "error": str(exc),
                                   "error_type": type(exc).__name__}
                    events.extend(worker_events)
                    if failure is not None:
                        manifest["failures"].append(failure)
                        stopped = True
                        print(f"SOURCE ACQUISITION STOPPED: {failure['error']}", flush=True)
                    else:
                        manifest["snapshots"][boundary] = info
                        acquired += 1
                    save_json(manifest_path, manifest)
                # Stop new requests on failure; drain and retain in-flight results.
                admit()
    finally:
        manifest["last_attempt_at"] = now()
        manifest["invalid_recorded_boundaries"] = sorted(invalid_boundaries)
        manifest["missing_requested_boundaries"] = sorted(
            (set(manifest["requested_boundaries"]) - set(manifest["snapshots"])) | set(invalid_boundaries))
        manifest["requested_sources_complete"] = not manifest["missing_requested_boundaries"]
        save_json(manifest_path, manifest)
        events_path = root / "data/provenance/release-http-events.json"
        save_json(events_path, (read_json(events_path) if events_path.exists() else []) + events)
    print(json.dumps({"acquired_this_run": acquired, "snapshots_retained": len(manifest["snapshots"]),
                      "missing_requested_boundaries": len(manifest["missing_requested_boundaries"]),
                      "requested_sources_complete": manifest["requested_sources_complete"]}, indent=2))
    return 0 if manifest["requested_sources_complete"] else 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", action="append", required=True, choices=("supplied", "all-precutoff"))
    parser.add_argument("--package", action="append", help="Optional explicit diagnostic subset; never claims full coverage")
    parser.add_argument("--limit", type=int, help="Cap newly downloaded snapshots for this invocation")
    parser.add_argument("--workers", type=int, choices=range(1, 5), default=1,
                        help="Bounded concurrent snapshot downloads (1-4); stop admitting work on any source failure")
    args = parser.parse_args()
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    raise SystemExit(acquire(ROOT, args.scope, args.package, args.limit, args.workers))
