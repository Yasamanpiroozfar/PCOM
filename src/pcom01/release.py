"""Build supplied-version release-origin data and all-precutoff sensitivity data.

M0..M11 retain their June 2026..July 2025 identities. Counts reflect knowledge at
the release origin; download observations retain explicit day coverage.
"""
from __future__ import annotations

from collections import Counter
import csv
from datetime import timedelta
from functools import lru_cache
import gzip
import hashlib
import json
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

from .advisories import HistoricalEvidenceError, restore_snapshot, utc
from .downloads import monthly_downloads
from .io import read_json, save_json, sha256
from .npm import MetadataError, exact_purl, format_timestamp, parse_timestamp, stable_semver_key, transform
from .schema import CONTRACT, COLUMNS, MONTHS, MONTH_WINDOWS, REQUIRED_COLUMNS, SEVERITIES, blank_record
from .validation import parse_npm_purl, validate_record
from .git_evidence import verification_session

SCOPES = ("supplied", "all-precutoff")
SELECTION_CUTOFF = "2026-07-01T00:00:00.000Z"
ROOT = Path(__file__).resolve().parents[2]


def _scope(scope):
    if scope not in SCOPES:
        raise ValueError("An explicit version scope is required: supplied or all-precutoff")


def available_months(origin):
    """Return full official months completed by the release instant."""
    boundary = utc(origin)
    return [name for name in MONTHS if MONTH_WINDOWS[name][1] <= boundary]


def month_observation_status(origin):
    boundary = utc(origin)
    return {name: "completed" if upper <= boundary else "future" if lower >= boundary else "partial"
            for name, (lower, upper) in MONTH_WINDOWS.items()}


def release_downloads(payload, package, origin):
    """Retain observed daily totals only once their whole UTC day has ended."""
    monthly_downloads(payload, package)  # Validate every captured observation.
    boundary = utc(origin)
    observations = [item for item in payload["downloads"]
                    if utc(item["day"] + "T00:00:00Z") + timedelta(days=1) <= boundary]
    return monthly_downloads({"package": package, "downloads": observations}, package)


def release_counts(registry, origin):
    """Origin-known fixed-month stable releases; include the anchor instant."""
    boundary = utc(origin)
    dates, complete = [], True
    created = parse_timestamp(registry["time"]["created"])
    for version in set(registry["versions"]) | set(registry["time"]):
        try:
            stable_semver_key(version)
        except MetadataError:
            continue
        try:
            date = parse_timestamp(registry["time"].get(version))
            if date < created:
                raise MetadataError("Release precedes creation")
        except MetadataError:
            complete = False
            continue
        if date <= boundary:
            dates.append(date)
    return {f"package_stable_release_count_{name}":
            sum(lower <= date < upper for date in dates) if complete else None
            for name, (lower, upper) in MONTH_WINDOWS.items()}


def select_anchor(registry, package, scope):
    """Select the highest stable SemVer in the requested version universe.

    Supplied uses eligible fixed-window records before GHSA exclusions;
    all-precutoff includes earlier releases. Unknown timestamps and SemVer
    precedence ties block selection.
    """
    _scope(scope)
    npm = transform(registry, package)
    rows = npm["records"]
    times = registry["time"]
    cutoff = parse_timestamp(SELECTION_CUTOFF)
    blockers = []
    if not npm["latest_semver_verified_for_returned_metadata"]:
        blockers.append("unknown_stable_release_timestamp")
    if scope == "supplied":
        versions = [parse_npm_purl(row["purl"])[1] for row in rows]
    else:
        versions = []
        for version, raw_time in times.items():
            if version in {"created", "modified", "unpublished"}:
                continue
            try:
                stable_semver_key(version)
            except MetadataError:
                continue
            try:
                stamp = parse_timestamp(raw_time)
            except MetadataError:
                continue  # The completeness blocker above prevents selection.
            if stamp < cutoff and stamp >= parse_timestamp(times["created"]):
                versions.append(version)
    maximum = max((stable_semver_key(v) for v in versions), default=None)
    candidates = sorted(v for v in versions if stable_semver_key(v) == maximum)
    if not candidates:
        blockers.append("no_eligible_anchor_version")
    if len(candidates) > 1:
        blockers.append("highest_semver_precedence_tie")
    if len(candidates) == 1 and parse_timestamp(times[candidates[0]]).microsecond % 1000:
        blockers.append("anchor_timestamp_exceeds_schema_millisecond_precision")
    anchor = candidates[0] if len(candidates) == 1 and not blockers else None
    origin = format_timestamp(parse_timestamp(times[anchor])) if anchor else None
    end = format_timestamp(parse_timestamp(origin) + timedelta(days=90)) if origin else None
    later = [row["purl"] for row in rows
             if origin and parse_timestamp(times[parse_npm_purl(row["purl"])[1]]) > parse_timestamp(origin)]
    usable = available_months(origin) if origin else []
    return {
        "package": package, "scope": scope,
        "selection_cutoff_exclusive": SELECTION_CUTOFF,
        "anchor_version": anchor, "anchor_candidates": candidates,
        "origin": origin, "outcome_end": end,
        "anchor_in_supplied_records": bool(anchor and any(
            row["published_at"] == origin and row["purl"] == exact_purl(package, anchor)
            for row in rows)),
        "supplied_record_count": len(rows), "records_after_origin": sorted(later),
        "stable_versions_in_history": npm["statistics"]["stable_versions_in_history"],
        "available_full_months": usable,
        "unavailable_full_months": [name for name in MONTHS if name not in usable],
        "blockers": blockers,
        "selection_uses_outcomes": False,
        "source_limit": "Retrospective registry capture; not a historical registry transaction log.",
    }


def _sources(root):
    manifest_path = root / "data/provenance/acquisition.json"
    manifest = read_json(manifest_path)
    selection_path = root / "config/packages.json"
    if manifest["selection_sha256"] != sha256(selection_path):
        raise ValueError("Original selection hash differs from acquisition evidence")
    packages = [item["name"] for item in read_json(selection_path)["packages"]]
    if not packages or len(set(packages)) != len(packages):
        raise ValueError("Package selection must be nonempty and unique")
    return manifest, packages


def _checked(root, info, path_key="path", hash_key="stored_sha256"):
    path = root / info[path_key]
    if sha256(path) != info[hash_key]:
        raise ValueError("Source digest mismatch: " + str(path))
    return read_json(path)


def _supplemental_sources(root, original, packages):
    """Load verified missing-version manifests for an in-memory merge."""
    inventory_path = root / "data/provenance/release-manifests.json"
    if not inventory_path.exists():
        return {"documents": {}, "entries": {}, "sha256": None}
    inventory = read_json(inventory_path)
    if (inventory.get("schema_version") != 1 or inventory.get("complete") is not True
            or inventory.get("missing") != []
            or inventory.get("selection_sha256") != original["selection_sha256"]
            or inventory.get("original_acquisition_sha256") != sha256(root / "data/provenance/acquisition.json")):
        raise ValueError("Supplemental manifest inventory is incomplete or has invalid source bindings")
    entries = inventory.get("manifests")
    if not isinstance(entries, dict) or set(entries) - set(packages):
        raise ValueError("Supplemental manifest inventory contains foreign packages or malformed entries")
    documents = {}
    lower, upper = min(value[0] for value in MONTH_WINDOWS.values()), max(value[1] for value in MONTH_WINDOWS.values())
    for package, versions in entries.items():
        if not isinstance(versions, dict):
            raise ValueError("Supplemental version map must be an object")
        registry_info = original["packages"].get(package, {}).get("registry", {})
        if "path" not in registry_info:
            raise ValueError("Supplemental package has no original registry evidence")
        registry = _checked(root, registry_info)
        for version, entry in versions.items():
            stable_semver_key(version)
            if version in registry["versions"]:
                raise ValueError("Supplemental manifest cannot overwrite an original version")
            if version not in registry["time"]:
                raise ValueError("Supplemental version has no original publication timestamp")
            published = registry["time"][version]
            if not lower <= parse_timestamp(published) < upper:
                raise ValueError("Supplemental version is outside the fixed history window")
            if (not isinstance(entry, dict) or entry.get("package") != package
                    or entry.get("version") != version or entry.get("published_at") != published
                    or entry.get("http_status") != 200):
                raise ValueError("Supplemental manifest identity, timestamp or HTTP status mismatch")
            requested, final = urlsplit(entry["url"]), urlsplit(entry["final_url"])
            for address in (requested, final):
                if (address.scheme != "https" or address.netloc not in {"registry.npmjs.org", "registry.npmmirror.com"}
                        or address.query or address.fragment
                        or unquote(address.path) != "/" + package + "/" + version):
                    raise ValueError("Supplemental manifest source URL identity mismatch")
            expected_kind = "npm_version_metadata" if final.netloc == "registry.npmjs.org" else "retained_npm_mirror_version_metadata"
            if entry.get("source_kind") != expected_kind or requested.netloc != final.netloc:
                raise ValueError("Supplemental manifest source kind does not match its verified URL")
            if parse_timestamp(entry["fetched_at"]) < parse_timestamp(published):
                raise ValueError("Supplemental manifest acquisition precedes publication")
            relative = "data/raw/release-manifests/" + quote(package, safe="") + "@" + quote(version, safe="") + ".json.gz"
            if entry.get("path") != relative:
                raise ValueError("Supplemental manifest source path does not match identity")
            path = root / relative
            if sha256(path) != entry.get("stored_sha256"):
                raise ValueError("Supplemental manifest compressed source hash mismatch")
            raw = gzip.decompress(path.read_bytes())
            if (len(raw) != entry.get("response_bytes") or len(raw) > 2 * 1024 * 1024
                    or hashlib.sha256(raw).hexdigest() != entry.get("response_sha256")):
                raise ValueError("Supplemental manifest response hash or byte count mismatch")
            document = read_json(path)
            if not isinstance(document, dict) or document.get("name") != package or document.get("version") != version:
                raise ValueError("Supplemental manifest document identity mismatch")
            # Recovered manifests must satisfy the regular version schema.
            merged = {**registry, "versions": {**registry["versions"], version: document}}
            if not any(row["purl"] == exact_purl(package, version) for row in transform(merged, package)["records"]):
                raise ValueError("Supplemental manifest fails required version schema")
            documents.setdefault(package, {})[version] = document
    return {"documents": documents, "entries": entries, "sha256": sha256(inventory_path)}


def _merge_supplements(registry, package, supplements):
    additions = supplements["documents"].get(package, {})
    return {**registry, "versions": {**registry["versions"], **additions}} if additions else registry


def plan(root=ROOT):
    """Return anchors and required snapshot boundaries for both version scopes."""
    root = Path(root)
    original, packages = _sources(root)
    supplements = _supplemental_sources(root, original, packages)
    result = {"selection_sha256": original["selection_sha256"],
              "original_acquisition_sha256": sha256(root / "data/provenance/acquisition.json"),
              "supplemental_source_sha256": supplements["sha256"],
              "scopes": {}}
    for scope in SCOPES:
        decisions, boundaries = {}, set()
        for package in packages:
            info = original["packages"].get(package, {}).get("registry", {})
            if "path" not in info:
                decisions[package] = {"package": package, "scope": scope,
                                      "anchor_version": None, "origin": None, "outcome_end": None,
                                      "blockers": ["registry_unavailable"]}
                continue
            registry = _merge_supplements(_checked(root, info), package, supplements)
            try:
                decision = select_anchor(registry, package, scope)
            except MetadataError as exc:
                decision = {"package": package, "scope": scope,
                            "anchor_version": None, "origin": None, "outcome_end": None,
                            "blockers": ["invalid_registry: " + str(exc)]}
            decisions[package] = decision
            if decision["origin"] and decision.get("supplied_record_count", 0):
                boundaries.update((decision["origin"], decision["outcome_end"]))
        result["scopes"][scope] = {"packages": decisions,
                                   "snapshot_boundaries": sorted(boundaries)}
    return result


release_plan = plan


def _history_evidence(package, history, origin):
    start = utc(origin)
    if history.observed_before != start or history.committed_at >= start:
        raise HistoricalEvidenceError("History snapshot does not match exact release origin")
    history.require_package(package)
    historical = [item for item in history.advisories.values()
                  if package in item.packages and item.published < start and item.active_before(start)]
    monthly = {}
    for name, (lower, upper) in MONTH_WINDOWS.items():
        monthly[name] = {severity: sorted(item.ghsa_id for item in historical
                                         if item.severity == severity and lower <= item.published < upper)
                         for severity in SEVERITIES}
    return {"package": package, "origin": format_timestamp(start),
            "outcome_end": format_timestamp(start + timedelta(days=90)),
            "history_commit": history.commit_sha, "outcome_commit": None,
            "history": {severity: sorted(item.ghsa_id for item in historical if item.severity == severity)
                        for severity in SEVERITIES},
            "monthly": monthly, "targets": None}


def release_advisory_evidence(package, history, outcome, origin):
    """GHSA state at arbitrary release instants and exact 90-day boundaries."""
    evidence = _history_evidence(package, history, origin)
    start, end = utc(origin), utc(origin) + timedelta(days=90)
    if outcome.observed_before != end or outcome.committed_at >= end:
        raise HistoricalEvidenceError("Outcome snapshot does not match exact 90-day end")
    outcome.require_package(package)
    targets = [item for item in outcome.advisories.values()
               if package in item.packages and start <= item.published < end
               and item.active_before(end) and item.ghsa_id not in history.all_ghsa_ids]
    evidence["outcome_commit"] = outcome.commit_sha
    evidence["targets"] = {severity: sorted(item.ghsa_id for item in targets if item.severity == severity)
                           for severity in SEVERITIES}
    return evidence


def release_advisory_features(package, history, outcome, origin):
    evidence = release_advisory_evidence(package, history, outcome, origin)
    return _advisory_values(evidence)


def _advisory_values(evidence):
    result = {}
    for severity in SEVERITIES:
        result[f"ghsa_{severity}_count"] = len(evidence["history"][severity])
        result[f"target_ghsa_{severity}_count_90d"] = (len(evidence["targets"][severity])
                                                       if evidence["targets"] is not None else None)
        for month in MONTHS:
            bucket = evidence["monthly"][month]
            result[f"ghsa_{severity}_count_{month}"] = len(bucket[severity]) if bucket is not None else None
    return result


def _snapshot(root, manifest, boundary):
    info = manifest.get("snapshots", {}).get(boundary)
    if not info:
        raise HistoricalEvidenceError("missing_release_snapshot: " + boundary)
    if utc(info.get("boundary")) != utc(boundary):
        raise HistoricalEvidenceError("Snapshot manifest boundary mismatch")
    bundle = _checked(root, info, "bundle_path", "bundle_sha256")
    provenance = bundle["provenance"]
    if (provenance["commit_sha"] != info["commit"]["sha"]
            or utc(provenance["committed_at"]) != utc(info["commit"]["committed_at"])
            or provenance.get("archive_sha256") != info.get("archive_sha256")
            or utc(provenance["observed_before"]) != utc(boundary)):
        raise HistoricalEvidenceError("Snapshot manifest and recorded provenance disagree")
    kinds = {manifest.get("source_kind"), info.get("source_kind"), provenance.get("source_kind")}
    if "git_reviewed_tree" in kinds:
        if kinds != {"git_reviewed_tree"}:
            raise HistoricalEvidenceError("Inconsistent historical Git source transport")
        if manifest.get("final_source_binding_sealed") is not True:
            raise HistoricalEvidenceError("Expanded Git source acquisition is not finally sealed")
        from .git_evidence import verify_git_source
        verify_git_source(root, info, bundle)
    elif kinds != {None} or not info.get("archive_sha256"):
        raise HistoricalEvidenceError("Unknown or archive-less historical source transport")
    return restore_snapshot(bundle["records"], provenance)


@verification_session
def build_release(root=ROOT, scope=None, output=None):
    """Build source-bound records for the primary or sensitivity scope.

    Primary readiness requires nonempty records, complete source evidence and
    valid schema fields.
    """
    _scope(scope)
    role = "primary_corrected" if scope == "supplied" else "sensitivity"
    root = Path(root)
    output = Path(output) if output is not None else root / "data/corrections" / scope
    resolved = output.resolve()
    legacy = (root / "data/processed").resolve()
    if resolved == legacy or legacy in resolved.parents:
        raise ValueError("Release correction cannot overwrite original processed artifacts")
    output.mkdir(parents=True, exist_ok=True)
    save_json(output / "build-status.json", {
        "complete": False, "scope": scope, "role": role, "ready_for_submission": False,
        "reason": "Build started; previous candidate artifacts are stale until successful completion.",
    })
    original, packages = _sources(root)
    inventory = plan(root)
    supplements = _supplemental_sources(root, original, packages)
    decisions = inventory["scopes"][scope]["packages"]
    release_path = root / "data/provenance/release-acquisition.json"
    acquired = read_json(release_path) if release_path.exists() else {}
    if acquired and any(acquired.get(key) != inventory[key]
                        for key in ("selection_sha256", "original_acquisition_sha256")):
        raise ValueError("Release acquisition does not match original recorded sources")
    rows, metadata, exclusions, evidence, validation_errors = [], [], [], {}, []
    counts, warning_counts = Counter(), Counter()
    readiness_blockers = []
    schema_path = root / "schema/record_schema.json"
    try:
        schema_valid = read_json(schema_path) == CONTRACT
    except (OSError, ValueError):
        schema_valid = False
    if not schema_valid:
        raise ValueError("Schema contract is missing or differs from the loaded official field contract")
    @lru_cache(maxsize=4)
    def snapshot(boundary):
        return _snapshot(root, acquired, boundary)

    for package in packages:
        decision = decisions[package]
        blockers = list(decision["blockers"])
        origin = decision["origin"]
        if not origin:
            benign_empty = (blockers == ["no_eligible_anchor_version"]
                            and decision.get("stable_versions_in_history") == 0)
            exclusions.append({"package": package, "reason": "no_supplied_stable_records" if benign_empty else "unresolved_anchor", "blockers": [] if benign_empty else blockers})
            if not benign_empty:
                counts.update(blockers)
                readiness_blockers.extend({"package": package, "reason": item} for item in blockers)
            continue
        info = original["packages"][package]
        registry = _merge_supplements(_checked(root, info["registry"]), package, supplements)
        npm = transform(registry, package)
        if not npm["records"]:
            reason = ("incomplete_supplied_version_evidence" if npm["statistics"]["stable_versions_in_history"]
                      else "no_supplied_stable_records")
            exclusions.append({"package": package, "reason": reason})
            if reason == "incomplete_supplied_version_evidence":
                readiness_blockers.append({"package": package, "reason": reason})
                counts.update([reason])
            continue
        if len(npm["records"]) != npm["statistics"]["stable_versions_in_history"]:
            blockers.append("incomplete_supplied_version_evidence")
        if not schema_valid:
            blockers.append("schema_contract_missing_or_mismatched")
        usable = decision["available_full_months"]
        warnings = []
        if decision["unavailable_full_months"]:
            warnings.append("full_calendar_history_overlaps_origin")
        if decision["records_after_origin"]:
            warnings.append("supplied_input_cohort_trimmed_to_origin")
        ghsa = {}
        try:
            history = snapshot(origin)
            evidence[package] = _history_evidence(package, history, origin)
            ghsa = _advisory_values(evidence[package])
            outcome = snapshot(decision["outcome_end"])
            evidence[package] = release_advisory_evidence(package, history, outcome, origin)
            ghsa = _advisory_values(evidence[package])
        except (HistoricalEvidenceError, ValueError, KeyError, OSError) as exc:
            blockers.append("unverified_release_ghsa: " + str(exc))
        downloads = {}
        if "path" in info.get("downloads", {}):
            try:
                downloads = release_downloads(_checked(root, info["downloads"]), package, origin)
            except (ValueError, KeyError, OSError) as exc:
                blockers.append("unverified_downloads: " + str(exc))
        else:
            blockers.append("downloads_unavailable")
        counts.update(blockers)
        readiness_blockers.extend({"package": package, "reason": item} for item in blockers)
        warning_counts.update(warnings)
        decision["candidate_blockers"] = blockers
        decision["candidate_warnings"] = warnings
        decision["measurement_policy"] = "origin-known-fixed-calendar"
        stable_counts = release_counts(registry, origin)
        for partial in npm["records"]:
            source_version = parse_npm_purl(partial["purl"])[1]
            source_published = registry["time"][source_version]
            if parse_timestamp(source_published) > parse_timestamp(origin):
                exclusions.append({"package": package, "purl": partial["purl"],
                                   "reason": "version_published_after_release_origin", "origin": origin})
                continue
            row = blank_record()
            for values in (partial, stable_counts, downloads, ghsa):
                if set(values) - set(COLUMNS):
                    raise ValueError("Release transformer emitted non-schema columns")
                row.update(values)
            errors = validate_record(row)
            missing = [name for name in REQUIRED_COLUMNS if row[name] is None]
            row_blockers = list(blockers)
            if errors:
                row_blockers.append("schema_validation_failed")
            eligible = not row_blockers
            extra_source = supplements["entries"].get(package, {}).get(source_version)
            manifest_source = ({key: extra_source[key] for key in
                                ("source_kind", "path", "stored_sha256", "response_sha256", "url", "fetched_at")}
                               if extra_source else {"source_kind": "original_npm_registry_metadata",
                                                     "path": info["registry"]["path"],
                                                     "stored_sha256": info["registry"]["stored_sha256"]})
            validation_errors.append({"purl": row["purl"], "errors": errors})
            metadata.append({"purl": row["purl"], "package": package, "scope": scope, "role": role,
                             "source_published_at": source_published,
                             "version_manifest_source": manifest_source,
                             "origin": origin, "outcome_end": decision["outcome_end"],
                             "anchor_version": decision["anchor_version"],
                             "available_full_months": usable,
                             "unavailable_full_months": decision["unavailable_full_months"],
                             "month_observation_status": month_observation_status(origin),
                             "measurement_policy": "origin-known-fixed-calendar",
                             "zero_semantics": "Known count in the recorded source at origin, not an eventual full-month total; missing evidence remains null.",
                             "missing_required_columns": missing,
                             "source_eligible": eligible,
                             "quarantined": not eligible or role == "sensitivity",
                             "schema_structurally_valid": not errors,
                             "blockers": row_blockers, "warnings": warnings})
            rows.append(row)
    rows.sort(key=lambda row: row["purl"])
    metadata.sort(key=lambda row: row["purl"])
    validation_errors.sort(key=lambda row: row["purl"])
    eligible_count = sum(item["source_eligible"] for item in metadata)
    ready = (scope == "supplied" and bool(rows) and eligible_count == len(rows)
             and not readiness_blockers)
    encoded = b"".join(json.dumps(row, ensure_ascii=False, separators=(",", ":"),
                                 allow_nan=False).encode("utf-8") + b"\n" for row in rows)
    (output / "candidate-records.jsonl").write_bytes(encoded)
    with (output / "candidate-records.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows({key: "" if value is None else value for key, value in row.items()} for row in rows)
    report = {
        "scope": scope, "role": role, "candidate_records": len(rows), "schema_columns": len(COLUMNS),
        "represented_packages": len({item["package"] for item in metadata}),
        "official_training_records": 0,
        "official_training_records_note": "Compatibility field only; no assertion of instructor endorsement. Use corrected_training_records for the local corrected dataset.",
        "eligible_records": eligible_count,
        "corrected_training_records": eligible_count if role == "primary_corrected" else 0,
        "all_candidates_quarantined": all(item["quarantined"] for item in metadata),
        "ready_for_submission": ready, "publication_permitted": False,
        "readiness_scope": "Methodological readiness of the local primary dataset under the documented supplied-version interpretation; not permission to publish or submit a form.",
        "readiness_blockers": readiness_blockers,
        "candidate_sha256": hashlib.sha256(encoded).hexdigest(),
        "original_acquisition_sha256": inventory["original_acquisition_sha256"],
        "supplemental_source_sha256": supplements["sha256"],
        "supplemental_manifest_versions": sorted(exact_purl(package, version)
                                                 for package, versions in supplements["documents"].items()
                                                 for version in versions),
        "release_acquisition_sha256": sha256(release_path) if release_path.exists() else None,
        "schema_contract_sha256": sha256(root / "schema/record_schema.json") if (root / "schema/record_schema.json").exists() else None,
        "blocker_package_counts": dict(sorted(counts.items())),
        "warning_package_counts": dict(sorted(warning_counts.items())),
        "structurally_valid_candidates": sum(not item["errors"] for item in validation_errors),
        "source_verified_ghsa_packages": sum(value["targets"] is not None for value in evidence.values()),
        "source_verified_history_ghsa_packages": len(evidence),
        "source_verified_ghsa_count_scope": "All source-inspected packages, including packages with no surviving version rows.",
        "represented_source_verified_ghsa_packages": sum(package in {item["package"] for item in metadata}
                                                        and value["targets"] is not None for package, value in evidence.items()),
        "represented_source_verified_history_ghsa_packages": sum(package in {item["package"] for item in metadata}
                                                                for package in evidence),
        "snapshot_boundaries_required": inventory["scopes"][scope]["snapshot_boundaries"],
        "fixed_months": MONTHS,
        "measurement_policy": "origin-known-fixed-calendar",
        "temporal_policy": "Fixed July 2025-June 2026 buckets contain origin-known measurements: GHSA from strictly pre-origin reviewed snapshot, releases with timestamp <= origin, downloads only observed UTC days ending <= origin. Verified future-bucket GHSA/release zeros are known-at-origin counts, not eventual full-month totals. Later version rows are excluded; targets use [origin, origin + 90 days).",
        "interpretation": "Supplied-version highest SemVer with origin-known fixed-calendar measurements is the primary documented reading. All-precutoff is retained only as a sensitivity comparison; neither claims instructor endorsement.",
        "limitations": ["Retrospective npm registry and downloads do not prove historical immutability or publication availability latency.",
                        "Where an original timestamped version manifest was absent, separately hashed public registry/mirror metadata supplements it in memory; mirror provenance is explicit and original sources are unchanged.",
                        "Historical GHSA reconstruction verifies a pinned public Git mirror, not exact GitHub service state.",
                        "Known-ID exclusion covers the earlier reviewed corpus, not every advisory review status or an independent first-publication history.",
                        "Highest version selected from the end-of-window inventory is a retrospective cohort definition; it does not prove future releases were predictable at the chosen origin."]}
    save_json(output / "package-decisions.json", decisions)
    save_json(output / "exclusions.json", exclusions)
    save_json(output / "row-metadata.json", metadata)
    save_json(output / "advisory-evidence.json", evidence)
    save_json(output / "validation.json", {
        "schema_structurally_valid": bool(rows) and all(not item["errors"] for item in validation_errors),
        "ready_for_submission": ready, "role": role, "rows": validation_errors,
        "scope": "Official field order, types and consistency; readiness additionally requires the primary scope and complete source-backed derivation.",
        "reason": "Only genuine source, anchor or schema failures quarantine primary rows. Sensitivity rows remain separate from the corrected primary dataset."})
    save_json(output / "report.json", report)
    artifacts = ("candidate-records.jsonl", "candidate-records.csv", "package-decisions.json",
                 "exclusions.json", "row-metadata.json", "advisory-evidence.json", "validation.json", "report.json")
    save_json(output / "build-status.json", {
        "complete": True, "scope": scope, "role": role, "ready_for_submission": ready,
        "candidate_sha256": report["candidate_sha256"],
        "original_acquisition_sha256": report["original_acquisition_sha256"],
        "supplemental_source_sha256": report["supplemental_source_sha256"],
        "release_acquisition_sha256": report["release_acquisition_sha256"],
        "schema_contract_sha256": report["schema_contract_sha256"],
        "artifact_sha256": {name: sha256(output / name) for name in artifacts},
    })
    return report
