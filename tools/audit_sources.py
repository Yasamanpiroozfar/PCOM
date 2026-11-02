"""Independent row-by-row audit against captured raw sources, not the builders.

This auditor deliberately does not call npm.transform or advisory.derive_features.
It checks the produced records against source identities and independently counts
GHSA membership. It cannot prove that a mutable public source was historically
immutable; that limitation remains in the report.
"""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys
import tarfile
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcom01.io import read_json, save_json, sha256, now


def stamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archives", action="store_true", help="Also independently verify projected records against the recorded full Git archives")
    args = parser.parse_args()
    manifest = read_json(ROOT / "data/provenance/acquisition.json")
    rows = [json.loads(line) for line in (ROOT / "data/processed/training.jsonl").read_text(encoding="utf-8").splitlines()]
    cutoff = stamp(manifest["input_cutoff_exclusive"])
    end = stamp(manifest["outcome_end_exclusive"])
    assert end - cutoff == timedelta(days=90)
    errors, comparisons, source_documents_verified = [], 0, 0
    captured = {}
    for package, entry in manifest["packages"].items():
        captured[package] = {}
        for kind in ("registry", "downloads"):
            info = entry.get(kind, {})
            if "path" not in info:
                continue
            path = ROOT / info["path"]
            if sha256(path) != info["stored_sha256"]:
                errors.append(f"Source digest mismatch: {info['path']}")
            captured[package][kind] = read_json(path)
    snapshots = {}
    for name, info in manifest["snapshots"].items():
        path = ROOT / info["bundle_path"]
        if sha256(path) != info["bundle_sha256"]:
            errors.append(f"Snapshot digest mismatch: {name}")
        bundle = read_json(path)
        snapshots[name] = bundle
        boundary = cutoff if name == "history" else end
        if stamp(bundle["provenance"]["committed_at"]) >= boundary:
            errors.append(f"Future snapshot: {name}")
        if bundle["provenance"]["commit_sha"] != info["commit"]["sha"]:
            errors.append(f"Manifest/bundle commit mismatch: {name}")
        if args.archives:
            archive_path = ROOT / "data/cache" / (info["commit"]["sha"] + ".tar.gz")
            if sha256(archive_path) != info["archive_sha256"]:
                errors.append(f"Original archive digest mismatch: {name}")
            wanted = {record["source_path"]: record for record in bundle["records"]}
            seen, scanned = set(), 0
            original_ids, independently_selected = set(), set()
            selected_names = set(bundle["provenance"]["selected_packages"])
            with tarfile.open(archive_path, "r|gz") as archive:
                for member in archive:
                    if "/advisories/github-reviewed/" not in member.name or not member.name.endswith(".json"):
                        continue
                    scanned += 1
                    original = json.load(archive.extractfile(member))
                    original_ids.add(original["id"])
                    npm_names = {affected["package"]["name"] for affected in original.get("affected", [])
                                 if affected.get("package", {}).get("ecosystem") == "npm"}
                    if npm_names & selected_names or "*" in npm_names:
                        independently_selected.add(member.name)
                    if member.name not in wanted:
                        continue
                    retained = wanted[member.name]
                    digest = hashlib.sha256(json.dumps(original, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                    if digest != retained["source_document_sha256"] or any(original.get(key) != value for key, value in retained["document"].items()):
                        errors.append(f"Projected measurement differs from original Git document: {member.name}")
                    else:
                        source_documents_verified += 1
                    seen.add(member.name)
            if seen != set(wanted) or scanned != bundle["provenance"]["reviewed_files_scanned"]:
                errors.append(f"Original archive coverage mismatch: {name}")
            if independently_selected != set(wanted):
                errors.append(f"Selected-package advisory coverage mismatch: {name}")
            if original_ids != set(bundle["provenance"]["all_ghsa_ids"]):
                errors.append(f"Complete reviewed GHSA inventory mismatch: {name}")
    severities = ("low", "moderate", "high", "critical", "unknown")
    buckets = {name: defaultdict(set) for name in ("history", "outcome")}
    known_ids = set(snapshots["history"]["provenance"]["all_ghsa_ids"])
    for label, bundle in snapshots.items():
        boundary = cutoff if label == "history" else end
        for source in bundle["records"]:
            item = source["document"]
            specific = item["database_specific"]
            if specific.get("github_reviewed") is not True:
                errors.append(f"Unreviewed included record: {item['id']}")
            for key, value in (("published", item["published"]), ("modified", item["modified"]),
                               ("reviewed", specific.get("github_reviewed_at"))):
                if value and stamp(value) >= boundary:
                    errors.append(f"Future {key}: {item['id']}")
            published = stamp(item["published"])
            if item.get("withdrawn") and stamp(item["withdrawn"]) < boundary:
                continue
            if label == "outcome" and (not cutoff <= published < end or item["id"] in known_ids):
                continue
            severity = specific.get("severity")
            severity = severity.strip().lower() if isinstance(severity, str) else "unknown"
            if severity not in severities:
                severity = "unknown"
            names = {affected["package"]["name"] for affected in item["affected"]
                     if affected.get("package", {}).get("ecosystem") == "npm"}
            for package in names:
                buckets[label][package, severity, "all"].add(item["id"])
                if label == "history":
                    index = (2026 - published.year) * 12 + 6 - published.month
                    if 0 <= index < 12:
                        buckets[label][package, severity, index].add(item["id"])
    core = {"dependencies": "dependency_count", "optionalDependencies": "optional_dependency_count",
            "peerDependencies": "peer_dependency_count", "devDependencies": "dev_dependency_count"}
    for row in rows:
        identity, version = row["purl"].removeprefix("pkg:npm/").rsplit("@", 1)
        package, version = unquote(identity), unquote(version)
        registry = captured[package]["registry"]
        source = registry["versions"].get(version)
        if not source or source.get("name") != package or source.get("version") != version:
            errors.append(f"No matching real version: {row['purl']}")
            continue
        expected = {field: len(source.get(key, {})) for key, field in core.items()}
        bundle = source.get("bundleDependencies", source.get("bundledDependencies", []))
        expected["bundled_dependency_count"] = len(set(source.get("dependencies", {})) | set(source.get("optionalDependencies", {}))) if bundle is True else len(set(bundle or []))
        for key, raw in (("published_at", registry["time"][version]), ("package_created_at", registry["time"]["created"])):
            expected[key] = stamp(raw).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        for severity in severities:
            expected[f"ghsa_{severity}_count"] = len(buckets["history"][package, severity, "all"])
            expected[f"target_ghsa_{severity}_count_90d"] = len(buckets["outcome"][package, severity, "all"])
            for index in range(12):
                expected[f"ghsa_{severity}_count_M{index}"] = len(buckets["history"][package, severity, index])
        if "downloads" in captured[package]:
            days = captured[package]["downloads"]["downloads"]
            for index in range(12):
                absolute = 2026 * 12 + 5 - index
                year, month = divmod(absolute, 12)
                selected = [day for day in days if day["day"].startswith(f"{year:04}-{month+1:02}-")]
                expected[f"package_download_days_observed_M{index}"] = len(selected)
                expected[f"package_downloads_M{index}"] = sum(day["downloads"] for day in selected) if selected else None
        for key, value in expected.items():
            comparisons += 1
            if row[key] != value:
                errors.append(f"Source disagreement: {row['purl']} {key}: stored={row[key]!r} expected={value!r}")
    report = {"executed_at": now(), "valid": not errors and bool(rows), "rows_audited": len(rows),
              "source_value_comparisons": comparisons, "errors": errors,
              "archive_audit_executed": args.archives, "original_advisory_documents_verified": source_documents_verified,
              "scope": "Independent real-version identity, timestamps, dependency counts, observed downloads and 70 GHSA fields per row; captured source hashes and snapshot boundaries. With --archives, independently compare complete GHSA inventories and selected-package coverage against original trees.",
              "limitations": "Verifies captured public source evidence, not historical immutability of npm or exact historical GitHub service state."}
    save_json(ROOT / "reports/source-audit.json", report)
    print(json.dumps(report, indent=2))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
