"""Acquire pinned sources, deterministically rebuild, and validate course data."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys
from urllib.parse import quote

from pcom01.io import AcquisitionError, PublicClient, json_bytes, now, read_json, save_json, sha256

ROOT = Path(__file__).resolve().parents[2]
CUTOFF = "2026-07-01T00:00:00.000Z"
OUTCOME_END = "2026-09-29T00:00:00.000Z"


def package_filename(name):
    return quote(name, safe="") + ".json.gz"


def selected_packages(root=ROOT):
    selection = read_json(root / "config/packages.json")
    names = [item["name"] for item in selection["packages"]]
    if len(names) != len(set(names)) or not names:
        raise ValueError("selection must contain unique explicit packages")
    return names


def snapshot_source(client, name, boundary, packages, root, previous=None):
    from pcom01.advisories import load_snapshot_archive
    until = (datetime.fromisoformat(boundary.replace("Z", "+00:00")) - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
    url = "https://api.github.com/repos/github/advisory-database/commits?until=" + until + "&per_page=1"
    if previous:
        commit = previous["commit"]
        resolution = previous["resolution"]
    else:
        commits, resolution = client.json(url)
        if not isinstance(commits, list) or len(commits) != 1:
            raise AcquisitionError("Cannot resolve exactly one latest pre-boundary commit")
        commit = {"sha": commits[0]["sha"], "committed_at": commits[0]["commit"]["committer"]["date"],
                  "html_url": commits[0]["html_url"]}
    archive_url = "https://codeload.github.com/github/advisory-database/tar.gz/" + commit["sha"]
    archive = root / "data/cache" / (commit["sha"] + ".tar.gz")
    if archive.exists() and previous and sha256(archive) == previous.get("archive_sha256"):
        download = previous["download"]
    else:
        print(f"Downloading {name} advisory snapshot {commit['sha']}", flush=True)
        _, download = client.get(archive_url, destination=archive)
    print(f"Scanning complete {name} reviewed advisory tree", flush=True)
    snapshot = load_snapshot_archive(archive, packages, observed_before=boundary,
                                     commit_sha=commit["sha"], committed_at=commit["committed_at"])
    path = root / "data/raw" / f"advisories-{name}.json.gz"
    save_json(path, {"provenance": snapshot.provenance(), "records": snapshot.raw_records()})
    return {"commit": commit, "resolution": resolution, "download": download,
            "archive_sha256": sha256(archive), "bundle_path": path.relative_to(root).as_posix(),
            "bundle_sha256": sha256(path), "boundary": boundary}


def acquire(root=ROOT, *, refresh=False):
    packages = selected_packages(root)
    manifest_path = root / "data/provenance/acquisition.json"
    manifest = read_json(manifest_path) if manifest_path.exists() and not refresh else {
        "started_at": now(), "python": platform.python_version(),
        "input_cutoff_exclusive": CUTOFF, "outcome_end_exclusive": OUTCOME_END,
        "selection_sha256": sha256(root / "config/packages.json"),
        "packages": {}, "snapshots": {}, "failures": []}
    if manifest["selection_sha256"] != sha256(root / "config/packages.json"):
        raise ValueError("Selection changed; use a separate checkout or --refresh")
    client = PublicClient()
    try:
        for label, boundary in (("history", CUTOFF), ("outcome", OUTCOME_END)):
            previous = manifest["snapshots"].get(label)
            if previous and (root / previous["bundle_path"]).exists() and sha256(root / previous["bundle_path"]) == previous["bundle_sha256"]:
                print(f"Using recorded {label} snapshot bundle", flush=True)
                continue
            manifest["snapshots"][label] = snapshot_source(client, label, boundary, packages, root, previous)
            save_json(manifest_path, manifest)
        for index, package in enumerate(packages, 1):
            entry = manifest["packages"].setdefault(package, {})
            for kind, base in (("registry", "https://registry.npmjs.org/"),
                               ("downloads", "https://api.npmjs.org/downloads/range/2025-07-01:2026-06-30/")):
                old = entry.get(kind)
                if old and "path" in old and (root / old["path"]).exists() and sha256(root / old["path"]) == old["stored_sha256"]:
                    continue
                url = base + quote(package, safe="")
                print(f"[{index}/{len(packages)}] {kind}: {package}", flush=True)
                try:
                    if kind == "downloads":
                        client.sleep(2.1)
                    payload, evidence = client.json(url)
                    path = root / "data/raw" / kind / package_filename(package)
                    save_json(path, payload)
                    entry[kind] = {"path": path.relative_to(root).as_posix(), "stored_sha256": sha256(path),
                                   "http": evidence}
                except AcquisitionError as exc:
                    failure = {"package": package, "source": kind, "error": str(exc), "at": now()}
                    entry[kind] = {"failure": failure}
                    manifest["failures"].append(failure)
                    print(f"SOURCE FAILURE: {package} {kind}: {exc}", flush=True)
                save_json(manifest_path, manifest)
        manifest["completed_at"] = now()
    finally:
        save_json(manifest_path, manifest)
        events_path = root / "data/provenance/http-events.json"
        old_events = read_json(events_path) if events_path.exists() and not refresh else []
        save_json(events_path, old_events + client.events)
    print(json.dumps({"packages_considered": len(packages), "source_failures_logged": len(manifest["failures"]),
                      "manifest": str(manifest_path)}, indent=2), flush=True)
    return manifest


def checked_json(root, info, path_key="path", hash_key="stored_sha256"):
    path = root / info[path_key]
    if sha256(path) != info[hash_key]:
        raise ValueError(f"Source digest mismatch: {path}")
    return read_json(path)


def build(root=ROOT, *, output=None):
    from pcom01.advisories import derive_features, package_evidence, restore_snapshot, HistoricalEvidenceError
    from pcom01.downloads import monthly_downloads
    from pcom01.npm import transform, MetadataError
    from pcom01.schema import COLUMNS, blank_record
    from pcom01.validation import validate_record, validate_dataset
    output = Path(output) if output else root / "data/processed"
    output.mkdir(parents=True, exist_ok=True)
    save_json(output / "build-status.json", {"complete": False, "reason": "build started; old training artifacts are invalid until success"})
    manifest = read_json(root / "data/provenance/acquisition.json")
    if manifest["selection_sha256"] != sha256(root / "config/packages.json"):
        raise ValueError("Selection does not match acquired sources")
    if manifest["input_cutoff_exclusive"] != CUTOFF or manifest["outcome_end_exclusive"] != OUTCOME_END:
        raise ValueError("Recorded cutoff differs from this fixed course experiment")
    snapshots = {}
    for name in ("history", "outcome"):
        bundle = checked_json(root, manifest["snapshots"][name], "bundle_path", "bundle_sha256")
        snapshots[name] = restore_snapshot(bundle["records"], bundle["provenance"])
    rows, exclusions, package_reports, provenance, exploratory = [], [], {}, {}, []
    for package in selected_packages(root):
        info = manifest["packages"].get(package, {})
        if "path" not in info.get("registry", {}):
            exclusions.append({"package": package, "reason": "registry_acquisition_failed"})
            continue
        try:
            registry = checked_json(root, info["registry"])
            npm = transform(registry, package, cutoff=CUTOFF)
        except (MetadataError, ValueError) as exc:
            exclusions.append({"package": package, "reason": "invalid_registry_evidence", "detail": str(exc)})
            continue
        package_reports[package] = {key: value for key, value in npm.items() if key != "records"}
        exclusions.extend({"package": package, **item} for item in npm["excluded"])
        if not npm["records"]:
            exclusions.append({"package": package, "reason": "no_stable_version_in_history", "records": 0})
        downloads = {}
        if "path" in info.get("downloads", {}):
            try:
                downloads = monthly_downloads(checked_json(root, info["downloads"]), package)
            except ValueError as exc:
                package_reports[package]["warnings"].append({"reason": "invalid_download_evidence", "detail": str(exc)})
        else:
            package_reports[package]["warnings"].append({"reason": "downloads_unavailable"})
        try:
            ghsa = derive_features(package, snapshots["history"], snapshots["outcome"], cutoff=CUTOFF)
            provenance[package] = package_evidence(package, snapshots["history"], snapshots["outcome"], cutoff=CUTOFF)
        except HistoricalEvidenceError as exc:
            reason = {"package": package, "reason": "unverified_historical_ghsa", "detail": str(exc), "records": len(npm["records"])}
            exclusions.append(reason)
            exploratory.extend({"package": package, "status": reason["reason"], "record": record} for record in npm["records"])
            continue
        for partial in npm["records"]:
            record = blank_record()
            for values in (partial, downloads, ghsa):
                unknown = set(values) - set(COLUMNS)
                if unknown:
                    raise ValueError(f"Transformer emitted non-schema columns: {sorted(unknown)}")
                record.update(values)
            errors = validate_record(record, prediction_at=CUTOFF)
            if errors:
                raise ValueError(f"Constructed record fails schema validation: {record['purl']}: {errors}")
            rows.append(record)
    rows.sort(key=lambda row: row["purl"])
    validation = validate_dataset(rows, prediction_at=CUTOFF)
    # Preserve diagnostics even when all records must be quarantined.
    save_json(output / "package-reports.json", package_reports)
    save_json(output / "exclusions.json", exclusions)
    save_json(output / "advisory-evidence.json", provenance)
    save_json(output / "exploratory.json", exploratory)
    save_json(output / "build-validation.json", validation)
    if not validation["valid"] or not rows:
        raise ValueError(f"No valid nonempty final dataset: {validation}")
    data = b"".join(json.dumps(row, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n" for row in rows)
    (output / "training.jsonl").write_bytes(data)
    import csv
    with (output / "training.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows({key: "" if value is None else value for key, value in row.items()} for row in rows)
    targets = [column for column in COLUMNS if column.startswith("target_")]
    # A package's versions share package-wide outcome counts. Report both units.
    represented = sorted({row["purl"].split("@")[0].removeprefix("pkg:npm/") for row in rows})
    from urllib.parse import unquote
    represented = [unquote(name) for name in represented]
    package_labels = {package: {key: derive_features(package, snapshots["history"], snapshots["outcome"], cutoff=CUTOFF)[key] for key in targets}
                      for package in represented}
    report = {
        "packages_considered": len(selected_packages(root)), "packages_registry_processed": len(package_reports),
        "packages_with_final_records": len(represented), "valid_records": len(rows),
        "schema_columns": len(COLUMNS), "input_cutoff_exclusive": CUTOFF, "outcome_end_exclusive": OUTCOME_END,
        "registry_versions_considered": sum(value["statistics"]["versions_in_registry"] for value in package_reports.values()),
        "exclusion_counts": dict(sorted(Counter(value["reason"] for value in exclusions).items())),
        "source_failures": manifest["failures"],
        "unresolved_source_failures": [entry[kind]["failure"] for entry in manifest["packages"].values()
                                       for kind in ("registry", "downloads") if "failure" in entry.get(kind, {})],
        "exploratory_record_count": len(exploratory),
        "row_target_totals": {key: sum(row[key] for row in rows) for key in targets},
        "package_target_totals": {key: sum(row[key] for row in package_labels.values()) for key in targets},
        "distinct_target_ghsa_ids": len({ghsa_id for package in represented for ids in provenance[package]["targets"].values() for ghsa_id in ids}),
        "package_label_distribution": dict(sorted(Counter(str(sum(value.values())) for value in package_labels.values()).items())),
        "package_labels": package_labels,
        "dataset_sha256": hashlib.sha256(data).hexdigest(),
        "historical_evidence_status": "verified_against_commit_pinned_public_git_mirror; interpretation and retrospective registry limitations apply",
        "validation": validation,
    }
    save_json(output / "statistics.json", report)
    save_json(output / "build-status.json", {"complete": True, "dataset_sha256": report["dataset_sha256"],
                                            "acquisition_sha256": sha256(root / "data/provenance/acquisition.json")})
    print(json.dumps({key: report[key] for key in ("packages_considered", "packages_with_final_records", "valid_records", "schema_columns", "dataset_sha256", "exploratory_record_count")}, indent=2), flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("acquire", "build", "validate", "reproduce", "test"))
    parser.add_argument("--refresh", action="store_true", help="Explicitly start a new acquisition; keep existing project as archival release")
    args = parser.parse_args()
    if args.command == "test":
        import io
        import unittest
        from contextlib import redirect_stdout
        started = now()
        stream = io.StringIO()
        suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
        with redirect_stdout(stream):
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        transcript = stream.getvalue()
        (ROOT / "reports").mkdir(exist_ok=True)
        (ROOT / "reports/tests.txt").write_text(transcript, encoding="utf-8", newline="\n")
        report = {"started_at": started, "completed_at": now(),
                  "python": platform.python_version(), "tests_run": result.testsRun,
                  "successful": result.wasSuccessful(), "failures": len(result.failures),
                  "errors": len(result.errors), "skipped": len(result.skipped)}
        save_json(ROOT / "reports/tests.json", report)
        print(json.dumps(report, indent=2))
        return 0 if result.wasSuccessful() else 1
    elif args.command == "acquire":
        acquire(refresh=args.refresh)
    elif args.command == "build":
        build()
    elif args.command == "validate":
        from pcom01.validation import validate_dataset
        state = read_json(ROOT / "data/processed/build-status.json")
        if not state.get("complete") or state.get("acquisition_sha256") != sha256(ROOT / "data/provenance/acquisition.json") or state.get("dataset_sha256") != sha256(ROOT / "data/processed/training.jsonl"):
            raise ValueError("Dataset is stale, altered, or from an incomplete build; rebuild successfully before validation")
        with (ROOT / "data/processed/training.jsonl").open(encoding="utf-8") as stream:
            records = [json.loads(line) for line in stream if line.strip()]
        report = validate_dataset(records, prediction_at=CUTOFF)
        save_json(ROOT / "reports/validation.json", report)
        print(json.dumps({"valid": report["valid"], "records": report["row_count"], "error_count": len(report["errors"])}, indent=2))
        return 0 if report["valid"] and records else 1
    else:
        output = ROOT / "reports/replay"
        build(output=output)
        compared = {}
        for original in sorted((ROOT / "data/processed").glob("*")):
            if original.is_file():
                regenerated = output / original.name
                compared[original.name] = {"original_sha256": sha256(original), "replayed_sha256": sha256(regenerated),
                                           "identical": original.read_bytes() == regenerated.read_bytes()}
        report = {"executed_at": now(), "all_identical": all(item["identical"] for item in compared.values()), "files": compared}
        save_json(ROOT / "reports/reproducibility.json", report)
        print(json.dumps(report, indent=2))
        return 0 if report["all_identical"] else 1
    return 0
