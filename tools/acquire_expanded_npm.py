"""Acquire a fixed, outcome-blind npm candidate pool and retain eligible sources."""
from __future__ import annotations

import argparse
import copy
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import shutil
import sys
import time
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcom01.io import AcquisitionError, PublicClient, now, read_json, save_json, sha256
from pcom01.npm import parse_timestamp, transform
from pcom01.release import select_anchor
from pcom01.downloads import monthly_downloads

SEARCH_TERMS = (
    "framework", "http", "cli", "build", "testing", "validation",
    "parser", "database", "stream", "logging", "template", "filesystem",
    "cryptography", "utilities", "authentication", "serialization",
    "network", "markdown", "image", "compression",
)
SEARCH_SIZE = 60


def verify_candidates(root, candidates, repository=None):
    repository = Path(repository) if repository is not None else ROOT
    original_path = repository / "config/packages.json"
    original = read_json(original_path)
    original_acquisition = read_json(repository / "data/provenance/acquisition.json")
    if sha256(original_path) != original_acquisition["selection_sha256"]:
        raise ValueError("Original candidate selection changed")
    expected = {x["name"]: {"name": x["name"], "roles": [x["role"]], "original": True}
                for x in original["packages"]}
    if candidates.get("search_terms") != list(SEARCH_TERMS) or candidates.get("results_per_term") != SEARCH_SIZE:
        raise ValueError("Candidate search specification changed")
    requests = candidates.get("requests", [])
    if [item.get("term") for item in requests] != list(SEARCH_TERMS):
        raise ValueError("Candidate search inventory is incomplete")
    for request in requests:
        term = request["term"]
        relative = "data/raw/search/" + term + ".json.gz"
        url = "https://registry.npmjs.org/-/v1/search?text=" + quote(term, safe="") + f"&size={SEARCH_SIZE}&from=0"
        if (request.get("path") != relative or request.get("url") != url
                or request.get("http", {}).get("url") != url
                or request.get("http", {}).get("status") != 200
                or sha256(root / relative) != request.get("stored_sha256")):
            raise ValueError("Candidate search source binding mismatch")
        payload = read_json(root / relative)
        if not isinstance(payload.get("objects"), list) or len(payload["objects"]) > SEARCH_SIZE:
            raise ValueError("Candidate search response has invalid result count")
        for result in payload["objects"]:
            name = result["package"]["name"]
            if not isinstance(name, str) or not name:
                raise ValueError("Candidate search response has no package name")
            entry = expected.setdefault(name, {"name": name, "roles": [], "original": False})
            if term not in entry["roles"]:
                entry["roles"].append(term)
    if candidates.get("packages") != [expected[name] for name in sorted(expected)]:
        raise ValueError("Frozen candidate pool differs from retained source results")
    return candidates


def capture(root, client, kind, package, url):
    path = root / "data/raw" / kind / (quote(package, safe="") + ".json.gz")
    payload, evidence = client.json(url)
    save_json(path, payload)
    return payload, {"path": path.relative_to(root).as_posix(),
                     "stored_sha256": sha256(path), "http": evidence}


def freeze_candidates(root):
    destination = root / "config/candidates.json"
    if destination.exists():
        return verify_candidates(root, read_json(destination))
    original = read_json(ROOT / "config/packages.json")
    candidates = {x["name"]: {"name": x["name"], "roles": [x["role"]], "original": True}
                  for x in original["packages"]}
    requests = []
    client = PublicClient(attempts=3, timeout=60)
    for term in SEARCH_TERMS:
        url = "https://registry.npmjs.org/-/v1/search?text=" + quote(term, safe="") + f"&size={SEARCH_SIZE}&from=0"
        payload, evidence = client.json(url)
        if not isinstance(payload.get("objects"), list):
            raise ValueError("Invalid npm search response")
        path = root / "data/raw/search" / (term + ".json.gz")
        save_json(path, payload)
        requests.append({"term": term, "url": url, "path": path.relative_to(root).as_posix(),
                         "stored_sha256": sha256(path), "http": evidence})
        for item in payload["objects"]:
            name = item["package"]["name"]
            if not isinstance(name, str) or not name:
                raise ValueError("Search result has no package name")
            candidate = candidates.setdefault(name, {"name": name, "roles": [], "original": False})
            if term not in candidate["roles"]:
                candidate["roles"].append(term)
        print(f"SEARCH {term}: {len(candidates)} distinct candidates", flush=True)
    result = {"frozen_at": now(), "search_terms": list(SEARCH_TERMS), "results_per_term": SEARCH_SIZE,
              "selection_method": "Original package sample plus the first 60 public npm search results for each fixed software-role term. Candidate names are frozen before historical advisory acquisition; admission depends on source and release-window completeness, never target values. This is a retrospective purposive cohort, not a random or release-time popularity sample.",
              "requests": requests, "packages": [candidates[name] for name in sorted(candidates)]}
    save_json(destination, result)
    return verify_candidates(root, result)


def seed_original(root):
    original = read_json(ROOT / "data/provenance/acquisition.json")
    original_supplements = read_json(ROOT / "data/provenance/release-manifests.json")
    entries = copy.deepcopy(original["packages"])
    for info in entries.values():
        for kind in ("registry", "downloads"):
            if "path" in info.get(kind, {}):
                source = ROOT / info[kind]["path"]
                target = root / info[kind]["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                if not target.exists():
                    shutil.copyfile(source, target)
                if sha256(target) != info[kind]["stored_sha256"]:
                    raise ValueError("Copied original source digest mismatch")
    for package, versions in original_supplements["manifests"].items():
        for item in versions.values():
            source, target = ROOT / item["path"], root / item["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                shutil.copyfile(source, target)
            if sha256(target) != item["stored_sha256"]:
                raise ValueError("Copied supplemental source digest mismatch")
    return entries, original_supplements


def registry_candidate(root, item, previous, supplements):
    package = item["name"]
    client = PublicClient(attempts=3, timeout=60)
    entry = copy.deepcopy(previous or {})
    try:
        if "path" in entry.get("registry", {}):
            if sha256(root / entry["registry"]["path"]) != entry["registry"]["stored_sha256"]:
                raise ValueError("Retained registry hash mismatch")
            registry = read_json(root / entry["registry"]["path"])
        else:
            registry, entry["registry"] = capture(root, client, "registry", package,
                                                 "https://registry.npmjs.org/" + quote(package, safe=""))
        merged = copy.deepcopy(registry)
        for version, info in supplements.get(package, {}).items():
            merged["versions"][version] = read_json(root / info["path"])
        facts = transform(merged, package)
        decision = select_anchor(merged, package, "supplied")
        missing = [x["version"] for x in facts["excluded"]
                   if x["reason"] == "timestamp_without_version_manifest"
                   and parse_timestamp("2025-07-01T00:00:00Z") <= parse_timestamp(merged["time"][x["version"]])
                   < parse_timestamp("2026-07-01T00:00:00Z")]
        if missing:
            return package, entry, {"accepted": False, "reason": "missing_version_manifests", "versions": missing}, client.events
        if len(facts["records"]) != facts["statistics"]["stable_versions_in_history"]:
            return package, entry, {"accepted": False, "reason": "incomplete_version_inventory",
                                    "stable_versions": facts["statistics"]["stable_versions_in_history"],
                                    "usable_records": len(facts["records"])}, client.events
        if not decision["origin"] or decision["blockers"] or not decision["supplied_record_count"]:
            return package, entry, {"accepted": False, "reason": "ineligible_release_inventory", "decision": decision}, client.events
        return package, entry, {"accepted": True, "decision": decision}, client.events
    except (AcquisitionError, ValueError, OSError, KeyError, TypeError) as exc:
        return package, entry, {"accepted": False, "reason": "source_or_metadata_error", "error_type": type(exc).__name__, "detail": str(exc)}, client.events


def acquire(root, workers=4, recheck=False):
    root = Path(root).resolve()
    intended = ROOT.resolve() / "datasets/training"
    if root != intended or ROOT.resolve() not in root.parents:
        raise ValueError("Acquisition must use the isolated datasets/training directory")
    root.mkdir(parents=True, exist_ok=True)
    candidates = freeze_candidates(root)
    original, supplements = seed_original(root)
    state_path = root / "data/provenance/npm-screening.json"
    state = read_json(state_path) if state_path.exists() else {
        "started_at": now(), "candidate_sha256": sha256(root / "config/candidates.json"),
        "packages": {}, "screening": {}, "events": []}
    if state["candidate_sha256"] != sha256(root / "config/candidates.json"):
        raise ValueError("Candidate pool changed")
    events_path = root / "data/provenance/http-events.json"
    if events_path.exists():
        seen = {json.dumps(item, sort_keys=True) for item in state["events"]}
        for event in read_json(events_path):
            key = json.dumps(event, sort_keys=True)
            if key not in seen:
                state["events"].append(event)
                seen.add(key)
    todo = [x for x in candidates["packages"] if recheck or x["name"] not in state["screening"]]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(registry_candidate, root, item, state["packages"].get(item["name"], original.get(item["name"])), supplements["manifests"]) for item in todo]
        for future in as_completed(futures):
            package, entry, result, events = future.result()
            state["packages"][package] = entry
            state["screening"][package] = result
            state["events"].extend(events)
            save_json(state_path, state)
            n = len(state["screening"])
            accepted = sum(x["accepted"] for x in state["screening"].values())
            if n % 10 == 0 or not result["accepted"]:
                print(f"REGISTRY {n}/{len(candidates['packages'])}: {accepted} eligible; {package}: {result.get('reason', 'accepted')}", flush=True)
    accepted_names = sorted(name for name, result in state["screening"].items() if result["accepted"])
    if len(accepted_names) < 300:
        raise ValueError(f"Only {len(accepted_names)} source-valid packages; expand the declared candidate pool before finalizing")
    by_name = {x["name"]: x for x in candidates["packages"]}
    selection = {"selection_version": 1, "selection_method": candidates["selection_method"],
                 "candidate_sha256": state["candidate_sha256"],
                 "packages": [{"name": name, "role": ", ".join(by_name[name]["roles"])} for name in accepted_names]}
    save_json(root / "config/packages.json", selection)
    manifest_path = root / "data/provenance/acquisition.json"
    manifest = {"started_at": state["started_at"], "input_cutoff_exclusive": "2026-07-01T00:00:00.000Z",
                "outcome_end_exclusive": "2026-09-29T00:00:00.000Z",
                "selection_sha256": sha256(root / "config/packages.json"), "packages": {name:state["packages"][name] for name in accepted_names},
                "snapshots": {}, "failures": [], "candidate_inventory_sha256": state["candidate_sha256"],
                "original_capture_manifest_sha256": sha256(ROOT / "data/provenance/acquisition.json")}
    client = PublicClient(attempts=4, timeout=60)
    event_offset = 0
    for index, name in enumerate(accepted_names, 1):
        entry = manifest["packages"][name]
        if "path" in entry.get("downloads", {}):
            if sha256(root / entry["downloads"]["path"]) != entry["downloads"]["stored_sha256"]:
                raise ValueError("Retained download hash mismatch")
            monthly_downloads(read_json(root / entry["downloads"]["path"]), name)
            continue
        time.sleep(2.1)
        try:
            payload, entry["downloads"] = capture(root, client, "downloads", name,
                "https://api.npmjs.org/downloads/range/2025-07-01:2026-06-30/" + quote(name, safe=""))
            monthly_downloads(payload, name)
        except (AcquisitionError, ValueError, OSError) as exc:
            entry["downloads"] = {"failure": {"package": name, "source": "downloads", "at": now(), "error_type": type(exc).__name__, "detail": str(exc)}}
            manifest["failures"].append(entry["downloads"]["failure"])
        state["packages"][name] = entry
        state["events"].extend(client.events[event_offset:])
        event_offset = len(client.events)
        save_json(state_path, state)
        save_json(events_path, state["events"])
        save_json(manifest_path, manifest)
        print(f"DOWNLOADS {index}/{len(accepted_names)}: {name}", flush=True)
    manifest["completed_at"] = now()
    save_json(manifest_path, manifest)
    save_json(state_path, state)
    save_json(events_path, state["events"])
    supplements["selection_sha256"] = manifest["selection_sha256"]
    supplements["original_acquisition_sha256"] = sha256(manifest_path)
    supplements["copied_from_inventory_sha256"] = sha256(ROOT / "data/provenance/release-manifests.json")
    save_json(root / "data/provenance/release-manifests.json", supplements)
    (root / "schema").mkdir(exist_ok=True)
    shutil.copyfile(ROOT / "schema/record_schema.json", root / "schema/record_schema.json")
    print(json.dumps({"candidates":len(candidates["packages"]),"eligible_packages":len(accepted_names),"download_failures":len(manifest["failures"])}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT / "datasets/training")
    parser.add_argument("--workers", type=int, default=4, choices=range(1,5))
    parser.add_argument("--recheck", action="store_true", help="Revalidate retained registry captures before sealing the cohort")
    args = parser.parse_args()
    acquire(args.root.resolve(), args.workers, args.recheck)
