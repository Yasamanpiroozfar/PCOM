"""Independently audit primary and sensitivity records against retained sources.

Does not reuse the builder's npm or GHSA derivation functions. Only complete,
nonempty supplied-version records qualify as the primary dataset.
"""
from __future__ import annotations

from collections import Counter
import csv
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import quote, unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcom01.io import read_json, save_json, sha256
from pcom01.schema import CONTRACT, COLUMNS, FIELDS, MONTHS, REQUIRED_COLUMNS, SEVERITIES
from pcom01.git_evidence import verification_session

STABLE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z")
HISTORY_START = datetime(2025, 7, 1, tzinfo=timezone.utc)
HISTORY_END = datetime(2026, 7, 1, tzinfo=timezone.utc)


def stamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("Source timestamp lacks timezone")
    return result.astimezone(timezone.utc)


def formatted(value):
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def precedence(version):
    match = STABLE.fullmatch(version) if isinstance(version, str) else None
    return tuple(int(match.group(i)) for i in (1, 2, 3)) if match else None


def purl(package, version):
    return "pkg:npm/" + quote(package, safe="/") + "@" + quote(version, safe="._-~")


def month_bounds(value):
    year, month = map(int, value.split("-"))
    return (datetime(year, month, 1, tzinfo=timezone.utc),
            datetime(year + (month == 12), 1 if month == 12 else month + 1, 1, tzinfo=timezone.utc))


WINDOWS = {name: month_bounds(value) for name, value in MONTHS.items()}


def dependencies(manifest):
    mapping = {"dependencies": "dependency_count", "optionalDependencies": "optional_dependency_count",
               "peerDependencies": "peer_dependency_count", "devDependencies": "dev_dependency_count"}
    counts, names = {}, {}
    for source, destination in mapping.items():
        value = manifest.get(source, {})
        if not isinstance(value, dict) or any(not isinstance(key, str) or not key for key in value):
            raise ValueError("Invalid dependency map")
        counts[destination], names[source] = len(value), set(value)
    bundles = []
    for alias in ("bundleDependencies", "bundledDependencies"):
        if alias not in manifest:
            continue
        value = manifest[alias]
        if value is True:
            bundles.append(names["dependencies"] | names["optionalDependencies"])
        elif value is False:
            bundles.append(set())
        elif isinstance(value, list) and all(isinstance(item, str) and item for item in value):
            bundles.append(set(value))
        else:
            raise ValueError("Invalid bundle declaration")
    if len(bundles) == 2 and bundles[0] != bundles[1]:
        raise ValueError("Conflicting bundle declarations")
    counts["bundled_dependency_count"] = len(bundles[0]) if bundles else 0
    return counts


def registry_facts(registry, package):
    if registry.get("name") != package:
        raise ValueError("Registry package identity mismatch")
    versions, times = registry["versions"], registry["time"]
    created = stamp(times["created"])
    dates, eligible, complete = {}, {}, True
    for version in sorted(set(versions) | set(times)):
        if precedence(version) is None:
            continue
        try:
            date = stamp(times[version])
            if date < created:
                raise ValueError("Version precedes creation")
        except (KeyError, ValueError, AttributeError, TypeError):
            complete = False
            continue
        dates[version] = date
        manifest = versions.get(version)
        if not HISTORY_START <= date < HISTORY_END or not isinstance(manifest, dict):
            continue
        if manifest.get("name") != package or manifest.get("version") != version:
            continue
        try:
            counts = dependencies(manifest)
        except ValueError:
            continue
        dist = manifest.get("dist", {})
        dist = dist if isinstance(dist, dict) else {}
        row = {"purl": purl(package, version), "package_created_at": formatted(created),
               "published_at": formatted(date), **counts}
        for raw, column in (("unpackedSize", "unpacked_size"), ("fileCount", "file_count")):
            value = dist.get(raw)
            row[column] = value if type(value) is int and 0 <= value < 2**63 else None
        eligible[version] = row
    return dates, eligible, complete


def read_bound(root, info, path_key="path", hash_key="stored_sha256"):
    path = root / info[path_key]
    if sha256(path) != info[hash_key]:
        raise ValueError("Hash mismatch: " + str(path))
    return read_json(path)


def supplementary_facts(root, original, packages):
    """Independently validate retained manifests before any in-memory merge."""
    path = root / "data/provenance/release-manifests.json"
    if not path.exists():
        return {}, {}, None
    source = read_json(path)
    if source.get("schema_version") != 1 or source.get("complete") is not True or source.get("missing") != []:
        raise ValueError("Supplemental manifest acquisition is incomplete")
    if (source.get("selection_sha256") != original["selection_sha256"]
            or source.get("original_acquisition_sha256") != sha256(root / "data/provenance/acquisition.json")):
        raise ValueError("Supplemental manifest source binding mismatch")
    captured = source.get("manifests")
    if not isinstance(captured, dict) or any(package not in packages for package in captured):
        raise ValueError("Supplemental manifests contain a foreign package or invalid mapping")
    documents = {}
    for package, additions in captured.items():
        if not isinstance(additions, dict):
            raise ValueError("Supplemental versions must be an object")
        registry = read_bound(root, original["packages"][package]["registry"])
        for version, entry in additions.items():
            if precedence(version) is None:
                raise ValueError("Supplemental version is not stable SemVer")
            if version in registry["versions"]:
                raise ValueError("Supplemental source attempts to overwrite an original manifest")
            if version not in registry["time"]:
                raise ValueError("Supplemental source attempts to invent a publication timestamp")
            original_time = registry["time"][version]
            if not HISTORY_START <= stamp(original_time) < HISTORY_END:
                raise ValueError("Supplemental publication is outside the required history")
            if (not isinstance(entry, dict) or entry.get("package") != package or entry.get("version") != version
                    or entry.get("published_at") != original_time or entry.get("http_status") != 200):
                raise ValueError("Supplemental source identity, timestamp or status mismatch")
            parsed = [urlsplit(entry[key]) for key in ("url", "final_url")]
            for address in parsed:
                if (address.scheme != "https" or address.netloc not in ("registry.npmjs.org", "registry.npmmirror.com")
                        or address.query or address.fragment or unquote(address.path) != "/" + package + "/" + version):
                    raise ValueError("Supplemental URL does not identify an allowed registry manifest")
            kind = {"registry.npmjs.org": "npm_version_metadata", "registry.npmmirror.com": "retained_npm_mirror_version_metadata"}[parsed[1].netloc]
            if parsed[0].netloc != parsed[1].netloc or entry.get("source_kind") != kind:
                raise ValueError("Supplemental source attribution disagrees with its URL")
            if stamp(entry["fetched_at"]) < stamp(original_time):
                raise ValueError("Supplemental capture predates its version publication")
            expected_path = "data/raw/release-manifests/" + quote(package, safe="") + "@" + quote(version, safe="") + ".json.gz"
            if entry.get("path") != expected_path:
                raise ValueError("Supplemental filename does not match package/version identity")
            payload_path = root / expected_path
            if sha256(payload_path) != entry.get("stored_sha256"):
                raise ValueError("Supplemental compressed hash mismatch")
            raw = gzip.decompress(payload_path.read_bytes())
            if (len(raw) > 2 * 1024 * 1024 or len(raw) != entry.get("response_bytes")
                    or hashlib.sha256(raw).hexdigest() != entry.get("response_sha256")):
                raise ValueError("Supplemental response bytes/hash mismatch")
            manifest = read_json(payload_path)
            if not isinstance(manifest, dict) or manifest.get("name") != package or manifest.get("version") != version:
                raise ValueError("Supplemental JSON manifest identity mismatch")
            dependencies(manifest)  # Independent required-field validation.
            documents.setdefault(package, {})[version] = manifest
    return documents, captured, sha256(path)


def load_snapshot(root, acquisition, boundary, package):
    """Read direct retained JSON; no builder or snapshot restoration functions."""
    info = acquisition.get("snapshots", {}).get(boundary)
    if info is None:
        return None
    bundle = read_bound(root, info, "bundle_path", "bundle_sha256")
    proof = bundle["provenance"]
    kinds = {acquisition.get("source_kind"), info.get("source_kind"), proof.get("source_kind")}
    if "git_reviewed_tree" in kinds:
        if kinds != {"git_reviewed_tree"}:
            raise ValueError("Inconsistent historical Git source transport")
        if acquisition.get("final_source_binding_sealed") is not True:
            return None
        from pcom01.git_evidence import verify_git_source
        verify_git_source(root, info, bundle)
    elif kinds != {None} or not info.get("archive_sha256"):
        raise ValueError("Unknown or archive-less historical source transport")
    edge = stamp(boundary)
    if not (stamp(info["boundary"]) == stamp(proof["observed_before"]) == edge
            and proof["commit_sha"] == info["commit"]["sha"]
            and stamp(proof["committed_at"]) == stamp(info["commit"]["committed_at"]) < edge
            and proof["archive_sha256"] == info["archive_sha256"]):
        raise ValueError("Snapshot provenance disagreement at " + boundary)
    if (proof["reviewed_files_scanned"] < 1 or not proof["all_ghsa_ids"]
            or len(set(proof["all_ghsa_ids"])) > proof["reviewed_files_scanned"]
            or len(set(proof["all_ghsa_ids"])) != len(proof["all_ghsa_ids"])):
        raise ValueError("Missing complete reviewed corpus inventory")
    if package not in proof["selected_packages"] or proof.get("issues", {}).get(package):
        return None
    known = set(proof["all_ghsa_ids"])
    records = []
    for retained in bundle["records"]:
        item = retained["document"]
        if item["id"] not in known:
            raise ValueError("Retained advisory absent from corpus inventory")
        if (retained.get("source_document_sha256") != proof["source_document_hashes"].get(item["id"])
                or Path(retained["source_path"]).stem != item["id"]
                or "/advisories/github-reviewed/" not in "/" + retained["source_path"]):
            raise ValueError("Retained advisory identity/hash provenance disagreement")
        names = {affected["package"]["name"] for affected in item.get("affected", [])
                 if affected.get("package", {}).get("ecosystem") == "npm"}
        if package not in names:
            continue
        specific = item.get("database_specific", {})
        if specific.get("github_reviewed") is not True:
            return None
        for value in (item.get("published"), item.get("modified")):
            if not value or stamp(value) >= edge:
                return None
        for value in (specific.get("github_reviewed_at"), item.get("withdrawn")):
            if value and stamp(value) >= edge:
                return None
        if item.get("withdrawn") and stamp(item["withdrawn"]) < edge:
            continue
        category = specific.get("severity")
        category = category.strip().lower() if isinstance(category, str) else "unknown"
        if category not in SEVERITIES:
            category = "unknown"
        records.append((item["id"], stamp(item["published"]), category))
    return {"records": records, "known": known, "commit": proof["commit_sha"]}


def ghsa_facts(root, acquisition, package, origin):
    start, end = stamp(origin), stamp(origin) + timedelta(days=90)
    history = load_snapshot(root, acquisition, origin, package)
    if history is None:
        return {}, None
    monthly, result = {}, {}
    lifetime = {level: sorted({identity for identity, published, severity in history["records"]
                              if severity == level and published < start}) for level in SEVERITIES}
    for name, (lower, upper) in WINDOWS.items():
        monthly[name] = {level: sorted({identity for identity, published, severity in history["records"]
                                       if severity == level and lower <= published < upper and published < start})
                         for level in SEVERITIES}
    outcome = load_snapshot(root, acquisition, formatted(end), package)
    targets = ({level: sorted({identity for identity, published, severity in outcome["records"]
                              if severity == level and start <= published < end and identity not in history["known"]})
                for level in SEVERITIES} if outcome is not None else None)
    for level in SEVERITIES:
        result[f"ghsa_{level}_count"] = len(lifetime[level])
        result[f"target_ghsa_{level}_count_90d"] = len(targets[level]) if targets is not None else None
        for month in MONTHS:
            result[f"ghsa_{level}_count_{month}"] = len(monthly[month][level])
    evidence = {"package": package, "origin": origin, "outcome_end": formatted(end),
                "history_commit": history["commit"], "outcome_commit": outcome["commit"] if outcome else None,
                "history": lifetime, "monthly": monthly, "targets": targets}
    return result, evidence


def structurally_valid(row):
    """Independent field constraints for rows already derived from source facts."""
    if tuple(row) != COLUMNS:
        return False
    for field in FIELDS:
        value = row[field["name"]]
        if value is None:
            if field["required"]:
                return False
        elif field["type"] == "integer":
            if type(value) is not int or not field["minimum"] <= value <= field["maximum"]:
                return False
    return True


@verification_session
def audit(root=ROOT, scopes=("supplied", "all-precutoff")):
    root = Path(root)
    original_path = root / "data/provenance/acquisition.json"
    original = read_json(original_path)
    selection_path = root / "config/packages.json"
    if original["selection_sha256"] != sha256(selection_path):
        raise ValueError("Original acquisition selection binding failed")
    acquisition_path = root / "data/provenance/release-acquisition.json"
    acquisition = read_json(acquisition_path) if acquisition_path.exists() else {}
    if acquisition and (acquisition.get("selection_sha256") != original["selection_sha256"]
                        or acquisition.get("original_acquisition_sha256") != sha256(original_path)):
        raise ValueError("Release acquisition original-source binding failed")
    packages = [item["name"] for item in read_json(selection_path)["packages"]]
    if not packages or len(packages) != len(set(packages)):
        raise ValueError("Package selection must be nonempty and unique")
    supplementary, supplementary_entries, supplemental_hash = supplementary_facts(root, original, packages)
    schema_path = root / "schema/record_schema.json"
    try:
        schema_valid = read_json(schema_path) == CONTRACT
    except (OSError, ValueError):
        schema_valid = False
    results = {}
    for scope in scopes:
        if scope not in ("supplied", "all-precutoff"):
            raise ValueError("Unknown explicit anchor scope")
        role = "primary_corrected" if scope == "supplied" else "sensitivity"
        folder = root / "data/corrections" / scope
        rows = [json.loads(line) for line in (folder / "candidate-records.jsonl").read_text(encoding="utf-8").splitlines()]
        decisions = read_json(folder / "package-decisions.json")
        metadata_rows = read_json(folder / "row-metadata.json")
        metadata = {item["purl"]: item for item in metadata_rows}
        recorded_evidence = read_json(folder / "advisory-evidence.json")
        report = read_json(folder / "report.json")
        state = read_json(folder / "build-status.json")
        validation = read_json(folder / "validation.json")
        errors, expected, expected_evidence, compared = [], {}, {}, 0
        expected_eligibility = {}
        all_required_sources_complete = True
        def check(condition, message):
            if not condition:
                errors.append(message)
        check(len(metadata) == len(metadata_rows) == len(rows), "Duplicate or missing per-row metadata")
        for package in packages:
            info = original["packages"].get(package, {})
            if "path" not in info.get("registry", {}):
                all_required_sources_complete = False
                continue
            registry = read_bound(root, info["registry"])
            registry = {**registry, "versions": {**registry["versions"], **supplementary.get(package, {})}}
            dates, supplied, complete = registry_facts(registry, package)
            universe = list(supplied) if scope == "supplied" else [v for v, date in dates.items() if date < HISTORY_END]
            highest = max((precedence(v) for v in universe), default=None)
            candidates = sorted(v for v in universe if precedence(v) == highest)
            anchor = candidates[0] if len(candidates) == 1 and complete and dates[candidates[0]].microsecond % 1000 == 0 else None
            decision = decisions[package]
            check(decision["anchor_version"] == anchor, package + ": highest SemVer anchor mismatch")
            check(decision.get("anchor_candidates", []) == candidates, package + ": anchor candidate set mismatch")
            if not anchor:
                history_dates = [date for date in dates.values() if HISTORY_START <= date < HISTORY_END]
                if not complete or history_dates or supplied:
                    all_required_sources_complete = False
                continue
            if not supplied:
                if any(HISTORY_START <= date < HISTORY_END for date in dates.values()):
                    all_required_sources_complete = False
                continue
            origin = dates[anchor]
            check(decision["origin"] == formatted(origin), package + ": origin does not equal raw release time")
            check(decision["outcome_end"] == formatted(origin + timedelta(days=90)), package + ": horizon is not 90 days")
            usable = [name for name, (_, upper) in WINDOWS.items() if upper <= origin]
            check(decision["available_full_months"] == usable, package + ": available month identities mismatch")
            late = sorted(purl(package, v) for v in supplied if dates[v] > origin)
            check(decision["records_after_origin"] == late, package + ": future version exclusions mismatch")
            downloads = None
            if "path" in info.get("downloads", {}):
                downloads = read_bound(root, info["downloads"])
                check(downloads.get("package") == package, package + ": downloads identity mismatch")
                days = downloads["downloads"]
                check(len({item["day"] for item in days}) == len(days), package + ": duplicate download days")
                check(all("2025-07-01" <= item["day"] < "2026-07-01" and type(item["downloads"]) is int
                          and 0 <= item["downloads"] < 2**63 for item in days), package + ": invalid download observations")
            values, membership = ghsa_facts(root, acquisition, package, formatted(origin)) if supplied else ({}, None)
            if membership is not None:
                expected_evidence[package] = membership
            version_evidence_complete = len(supplied) == sum(HISTORY_START <= date < HISTORY_END for date in dates.values())
            package_sources_complete = (complete and version_evidence_complete and downloads is not None
                                        and membership is not None and membership["targets"] is not None)
            if not package_sources_complete:
                all_required_sources_complete = False
            for version, partial in supplied.items():
                if dates[version] > origin:
                    continue
                row = dict.fromkeys(COLUMNS)
                row.update(partial)
                row.update(values)
                for name, (lower, upper) in WINDOWS.items():
                    row[f"package_stable_release_count_{name}"] = sum(lower <= date < upper and date <= origin for date in dates.values()) if complete else None
                    if downloads is not None:
                        observations = [item["downloads"] for item in downloads["downloads"]
                                        if item["day"].startswith(MONTHS[name])
                                        and stamp(item["day"] + "T00:00:00Z") + timedelta(days=1) <= origin]
                        row[f"package_download_days_observed_{name}"] = len(observations)
                        row[f"package_downloads_{name}"] = sum(observations) if observations else None
                expected[row["purl"]] = row
                sidecar = metadata.get(row["purl"], {})
                check(sidecar.get("origin") == formatted(origin) and sidecar.get("outcome_end") == formatted(origin + timedelta(days=90)), row["purl"] + ": sidecar origin/horizon mismatch")
                check(sidecar.get("source_published_at") == registry["time"][version], row["purl"] + ": original publication timestamp not retained")
                extra = supplementary_entries.get(package, {}).get(version)
                manifest_source = ({name: extra[name] for name in
                                    ("source_kind", "path", "stored_sha256", "response_sha256", "url", "fetched_at")}
                                   if extra else {"source_kind": "original_npm_registry_metadata",
                                                 "path": info["registry"]["path"], "stored_sha256": info["registry"]["stored_sha256"]})
                check(sidecar.get("version_manifest_source") == manifest_source, row["purl"] + ": version manifest provenance mismatch")
                check(sidecar.get("anchor_version") == anchor and sidecar.get("scope") == scope, row["purl"] + ": sidecar anchor/scope mismatch")
                missing = [name for name in REQUIRED_COLUMNS if row[name] is None]
                row_valid = structurally_valid(row)
                eligible = schema_valid and package_sources_complete and row_valid
                expected_eligibility[row["purl"]] = eligible
                check(sidecar.get("schema_structurally_valid") == row_valid, row["purl"] + ": structural status mismatch")
                check(sidecar.get("source_eligible") == eligible, row["purl"] + ": source eligibility mismatch")
                check(sidecar.get("role") == role and sidecar.get("quarantined") == (not eligible or scope != "supplied"), row["purl"] + ": role/quarantine mismatch")
                check(sidecar.get("missing_required_columns") == missing, row["purl"] + ": missing-required explanation mismatch")
                check(dates[version] <= origin, row["purl"] + ": raw publication leaks past origin")
                check("full_calendar_history_overlaps_origin" in sidecar.get("warnings", []), row["purl"] + ": calendar overlap fact not disclosed")
                check(sidecar.get("measurement_policy") == "origin-known-fixed-calendar", row["purl"] + ": origin-known policy not explicit")
                statuses = {name: "completed" if upper <= origin else "future" if lower >= origin else "partial"
                            for name, (lower, upper) in WINDOWS.items()}
                check(sidecar.get("month_observation_status") == statuses, row["purl"] + ": temporal coverage status mismatch")
                check(not any("instructor_" in blocker and "unconfirmed" in blocker for blocker in sidecar.get("blockers", [])), row["purl"] + ": invented instructor-approval blocker")
                check(bool(sidecar.get("blockers")) == (not eligible), row["purl"] + ": genuine source/schema blockers inconsistent with eligibility")
        actual = {row.get("purl"): row for row in rows}
        check(len(actual) == len(rows), "Duplicate candidate PURL")
        check(set(actual) == set(expected), "Candidate membership differs from independent release-time eligibility")
        for identity, row in actual.items():
            check(tuple(row) == COLUMNS, str(identity) + ": not the official ordered 224 fields")
            if identity not in expected:
                continue
            for key in COLUMNS:
                compared += 1
                check(row.get(key) == expected[identity][key] and type(row.get(key)) is type(expected[identity][key]), identity + " " + key + ": direct source disagreement")
        check(recorded_evidence == expected_evidence, "Exact GHSA memberships differ from independent source counts")
        with (folder / "candidate-records.csv").open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            csv_rows = list(reader)
            check(tuple(reader.fieldnames) == COLUMNS, "CSV schema/order mismatch")
            check(csv_rows == [{key: "" if value is None else str(value) for key, value in row.items()} for row in rows], "CSV/JSONL parity failed")
        check(report.get("scope") == scope and report.get("candidate_records") == len(rows), "Report scope or row count mismatch")
        structural_count = sum(structurally_valid(row) for row in expected.values())
        eligible_count = sum(expected_eligibility.values())
        ready_expected = (scope == "supplied" and bool(expected) and eligible_count == len(expected)
                          and schema_valid and all_required_sources_complete)
        check(report.get("structurally_valid_candidates") == structural_count, "Report structural validity count mismatch")
        check(validation.get("schema_structurally_valid") == (bool(rows) and structural_count == len(rows))
              and validation.get("ready_for_submission") == ready_expected, "Structural validation/readiness gate disagreement")
        check(report.get("measurement_policy") == "origin-known-fixed-calendar", "Report measurement interpretation omitted")
        represented = {item["package"] for item in metadata_rows}
        check(report.get("source_verified_ghsa_packages") == sum(item["targets"] is not None for item in expected_evidence.values()), "Source-inspected complete GHSA count mismatch")
        check(report.get("source_verified_history_ghsa_packages") == len(expected_evidence), "Source-inspected historical GHSA count mismatch")
        check(report.get("represented_source_verified_ghsa_packages") == sum(package in represented and item["targets"] is not None for package, item in expected_evidence.items()), "Represented complete GHSA count mismatch")
        check(report.get("candidate_sha256") == sha256(folder / "candidate-records.jsonl"), "Report candidate hash mismatch")
        check(report.get("original_acquisition_sha256") == sha256(original_path), "Report original-source hash mismatch")
        check(report.get("supplemental_source_sha256") == supplemental_hash, "Report supplemental source binding mismatch")
        check(report.get("supplemental_manifest_versions") == sorted(purl(package, version)
                                                                     for package, versions in supplementary.items() for version in versions),
              "Report supplemental manifest inventory mismatch")
        check(report.get("release_acquisition_sha256") == (sha256(acquisition_path) if acquisition_path.exists() else None), "Report release-source hash mismatch")
        check(report.get("schema_contract_sha256") == (sha256(schema_path) if schema_path.exists() else None), "Report schema binding mismatch")
        check(report.get("ready_for_submission") == ready_expected and report.get("publication_permitted") is False
              and report.get("all_candidates_quarantined") == all(not value or scope != "supplied" for value in expected_eligibility.values())
              and report.get("official_training_records") == 0, "Report readiness/publication/quarantine gates disagree with independent sources")
        check(report.get("eligible_records") == eligible_count
              and report.get("corrected_training_records") == (eligible_count if scope == "supplied" else 0)
              and report.get("role") == role, "Report primary/sensitivity role or eligible record counts disagree")
        check(state.get("complete") is True and state.get("scope") == scope and state.get("ready_for_submission") == ready_expected
              and state.get("role") == role,
              "Candidate build is incomplete or reports invalid readiness")
        for key in ("candidate_sha256", "original_acquisition_sha256", "supplemental_source_sha256", "release_acquisition_sha256", "schema_contract_sha256"):
            check(state.get(key) == report.get(key), "Build-state/report binding disagreement: " + key)
        artifacts = ("candidate-records.jsonl", "candidate-records.csv", "package-decisions.json", "exclusions.json",
                     "row-metadata.json", "advisory-evidence.json", "validation.json", "report.json")
        check(set(state.get("artifact_sha256", {})) == set(artifacts), "Build-state artifact inventory mismatch")
        for filename in artifacts:
            check(state.get("artifact_sha256", {}).get(filename) == sha256(folder / filename),
                  "Build-state artifact digest mismatch: " + filename)
        results[scope] = {"valid_candidate_derivation": not errors and bool(rows),
                          "role": role, "ready_for_submission": ready_expected and not errors,
                          "publication_permitted": False,
                          "eligible_records": eligible_count,
                          "corrected_training_records": eligible_count if scope == "supplied" else 0,
                          "schema_contract_verified": schema_valid,
                          "required_sources_complete": all_required_sources_complete,
                          "candidate_records_audited": len(rows),
                          "source_value_comparisons": compared, "errors": errors,
                          "candidate_sha256": sha256(folder / "candidate-records.jsonl"),
                          "structurally_valid_candidates": structural_count,
                          "complete_ghsa_evidence_packages": sum(item["targets"] is not None for item in expected_evidence.values()),
                          "history_ghsa_evidence_packages": len(expected_evidence),
                          "evidence_count_scope": "All source-inspected packages; includes diagnostics for packages with zero surviving rows.",
                          "represented_complete_ghsa_evidence_packages": sum(package in represented and item["targets"] is not None for package, item in expected_evidence.items())}
    result = {"valid_candidate_derivation": all(item["valid_candidate_derivation"] for item in results.values()),
              "ready_for_submission": results.get("supplied", {}).get("ready_for_submission", False)
                                      and all(item["valid_candidate_derivation"] for item in results.values()),
              "publication_permitted": False, "scopes": results,
              "original_acquisition_sha256": sha256(original_path),
              "supplemental_source_sha256": supplemental_hash,
              "release_acquisition_sha256": sha256(acquisition_path) if acquisition_path.exists() else None,
              "scope": "Independent raw-source recount of every candidate field, anchor selection, exact publication timing, GHSA ID membership, CSV parity, source bindings and quarantine status; no calls to build/transform/derive.",
              "limitations": "Authenticity is bounded by recorded hashes and historical Git mirror provenance; this does not certify exact historical GitHub service state or immutable npm metadata. Known-ID exclusion covers the earlier reviewed corpus, not all review statuses or independent first-publication history. Readiness refers to the documented supplied-version interpretation, not instructor endorsement or permission to publish."}
    save_json(root / "reports/correction-source-audit.json", result)
    return result


if __name__ == "__main__":
    result = audit()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["valid_candidate_derivation"] else 1)
