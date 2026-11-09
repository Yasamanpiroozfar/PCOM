"""Derive optional release-time features without changing the official schema."""
from __future__ import annotations

import csv
from datetime import timedelta
import json
from pathlib import Path
import re

from .advisories import utc
from .downloads import monthly_downloads
from .git_evidence import verification_session, verified_source_hashes
from .io import read_json, save_json, sha256
from .npm import MetadataError, parse_timestamp, stable_semver_key
from .release import _snapshot
from .validation import parse_npm_purl


COLUMNS = (
    "purl", "forecast_origin", "package_age_days", "version_age_days",
    "version_major", "version_minor", "version_patch",
    "stable_release_count_30d", "stable_release_count_90d", "stable_release_count_365d",
    "days_since_previous_stable_release",
    "downloads_mean_daily_30d", "downloads_observed_days_30d",
    "downloads_mean_daily_90d", "downloads_observed_days_90d",
    "downloads_mean_daily_previous_30d", "downloads_observed_days_previous_30d",
    "downloads_mean_daily_30d_change_fraction",
    "ghsa_count_30d", "ghsa_high_critical_count_30d",
    "ghsa_count_90d", "ghsa_high_critical_count_90d",
)
SPEC = {
    "version": 1, "columns": list(COLUMNS), "key": "purl",
    "role": "optional_input_features", "official_schema_columns": 224,
    "origin": "Highest stable SemVer among supplied records; publication timestamp T.",
    "ages": "Elapsed seconds divided by 86400 at T; version age uses its exact publication.",
    "semver": "Numeric stable major, minor and patch; build metadata has no precedence.",
    "release_counts": "Distinct stable version names published in [T-N days,T], including the anchor; unknown stable timestamps make cadence unknown.",
    "previous_release": "Elapsed days since the latest stable publication strictly before T; NULL if none or chronology is incomplete.",
    "downloads": "Last 30/90 complete UTC calendar days ending at midnight on T's UTC date; preceding30 is the immediately earlier 30 days. Means use observed days only; coverage is explicit.",
    "download_trend": "(last30 mean / preceding30 mean)-1 only when both windows have all30 days and preceding mean is positive; otherwise NULL.",
    "ghsa": "Distinct qualifying package-wide IDs in the verified origin reviewed snapshot, published in [T-N days,T), with severity at T; high_critical combines those severities.",
    "missingness": "Unavailable measurements are NULL. A verified observation of zero remains zero.",
    "rounding": "Noninteger numeric values rounded to six decimal places; trend uses unrounded window means.",
    "limitations": ["Retrospective registry and download captures do not prove release-time immutability.",
                    "GHSA evidence reflects the preserved reviewed Git mirror state.",
                    "Supplied-cohort selection is retrospective; no outcome is used to select features."],
}


def _number(value):
    return round(value, 6)


def _release_dates(registry):
    dates = []
    created = parse_timestamp(registry["time"]["created"])
    for version in set(registry["versions"]) | set(registry["time"]):
        try:
            stable_semver_key(version)
        except MetadataError:
            continue
        try:
            stamp = parse_timestamp(registry["time"].get(version))
            if stamp < created:
                return None
        except MetadataError:
            return None
        dates.append(stamp)
    return dates


def _package_values(package, registry, downloads, history, origin):
    edge = utc(origin)
    created = parse_timestamp(registry["time"]["created"])
    if registry.get("name") != package or created > edge:
        raise ValueError("Registry identity or creation chronology mismatch")
    result = {"package_age_days": _number((edge - created).total_seconds() / 86400)}
    dates = _release_dates(registry)
    for days in (30, 90, 365):
        result[f"stable_release_count_{days}d"] = (None if dates is None else
            sum(edge - timedelta(days=days) <= stamp <= edge for stamp in dates))
    previous = max((stamp for stamp in dates or [] if stamp < edge), default=None)
    result["days_since_previous_stable_release"] = (None if dates is None or previous is None
        else _number((edge - previous).total_seconds() / 86400))
    midnight = edge.replace(hour=0, minute=0, second=0, microsecond=0)
    if downloads is not None:
        monthly_downloads(downloads, package)
    means, coverage = {}, {}
    for label, days, offset in (("30d", 30, 0), ("90d", 90, 0), ("previous_30d", 30, 30)):
        upper = midnight - timedelta(days=offset)
        lower = upper - timedelta(days=days)
        values = ([] if downloads is None else [item["downloads"] for item in downloads["downloads"]
                  if lower <= utc(item["day"] + "T00:00:00Z") < upper])
        coverage[label] = len(values) if downloads is not None else None
        means[label] = sum(values) / len(values) if values else None
        result[f"downloads_mean_daily_{label}"] = _number(means[label]) if values else None
        result[f"downloads_observed_days_{label}"] = coverage[label]
    result["downloads_mean_daily_30d_change_fraction"] = (
        _number(means["30d"] / means["previous_30d"] - 1)
        if coverage["30d"] == coverage["previous_30d"] == 30 and means["previous_30d"] > 0 else None)
    if history is not None:
        history.require_package(package)
        if history.observed_before != edge or history.committed_at >= edge:
            raise ValueError("GHSA history does not match the feature origin")
    for days in (30, 90):
        selected = (None if history is None else [item for item in history.advisories.values()
                    if package in item.packages and edge - timedelta(days=days) <= item.published < edge
                    and item.active_before(edge)])
        result[f"ghsa_count_{days}d"] = None if selected is None else len({a.ghsa_id for a in selected})
        result[f"ghsa_high_critical_count_{days}d"] = (None if selected is None else
            len({a.ghsa_id for a in selected if a.severity in {"high", "critical"}}))
    return result


def _version_values(record, registry, origin):
    package, version = parse_npm_purl(record["purl"])
    major, minor, patch = stable_semver_key(version)
    published, edge = parse_timestamp(registry["time"][version]), utc(origin)
    if package != registry["name"] or published != parse_timestamp(record["published_at"]) or published > edge:
        raise ValueError("Record publication or package differs from release-time evidence")
    return {"purl": record["purl"], "forecast_origin": origin,
            "version_age_days": _number((edge - published).total_seconds() / 86400),
            "version_major": major, "version_minor": minor, "version_patch": patch}


def derive_features(record, registry, downloads, history, origin):
    package, _ = parse_npm_purl(record["purl"])
    values = {**_package_values(package, registry, downloads, history, origin),
              **_version_values(record, registry, origin)}
    return {name: values[name] for name in COLUMNS}


def _inputs(root):
    root = Path(root)
    bindings = {}

    def bound(name, expected=None):
        path = root / name
        if root.resolve() not in path.resolve().parents:
            raise ValueError("Source path escapes dataset root")
        actual = sha256(path)
        if expected is not None and actual != expected:
            raise ValueError("Feature source hash mismatch: " + name)
        bindings[name] = actual
        return path

    directory = "data/corrected/"
    manifest = read_json(bound(directory + "manifest.json"))
    if not (manifest.get("complete") is True and manifest.get("ready_for_submission") is True
            and manifest.get("scope") == "supplied" and manifest.get("schema_columns") == 224):
        raise ValueError("Verified primary dataset is required before feature derivation")
    for name, digest in manifest["artifact_sha256"].items():
        bound(directory + name, digest)
    for name, digest in manifest["source_sha256"].items():
        bound(name, digest)
    rows = [json.loads(line) for line in bound(directory + "training-records.jsonl", manifest["dataset_sha256"]).read_text(encoding="utf-8").splitlines()]
    if not rows or len(rows) != manifest["records"] or len({row["purl"] for row in rows}) != len(rows):
        raise ValueError("Primary record identity/count mismatch")
    metadata = read_json(bound(directory + "row-metadata.json"))
    by_purl = {item["purl"]: item for item in metadata}
    if len(by_purl) != len(metadata) or set(by_purl) != {row["purl"] for row in rows}:
        raise ValueError("Feature rows do not match primary metadata")
    original = read_json(bound("data/provenance/acquisition.json"))
    acquired = read_json(bound("data/provenance/release-acquisition.json"))
    selection = bound("config/packages.json", original["selection_sha256"])
    if acquired.get("original_acquisition_sha256") != sha256(root / "data/provenance/acquisition.json") or acquired.get("selection_sha256") != sha256(selection):
        raise ValueError("Historical source selection does not match registry sources")
    contexts = {}
    versions_by_package = {}
    for row in rows:
        name, version = parse_npm_purl(row["purl"])
        versions_by_package.setdefault(name, []).append(version)
    for row in rows:
        package, _ = parse_npm_purl(row["purl"])
        item = by_purl[row["purl"]]
        if item.get("package") != package or item.get("source_eligible") is not True or item.get("scope") != "supplied":
            raise ValueError("Primary metadata has an ineligible feature row")
        origin = item["origin"]
        if package in contexts:
            if contexts[package]["origin"] != origin:
                raise ValueError("Package rows have inconsistent forecast origins")
            continue
        info = original["packages"][package]
        registry = read_json(bound(info["registry"]["path"], info["registry"]["stored_sha256"]))
        highest = max(stable_semver_key(version) for version in versions_by_package[package])
        anchors = [version for version in versions_by_package[package] if stable_semver_key(version) == highest]
        if len(anchors) != 1 or parse_timestamp(registry["time"][anchors[0]]) != utc(origin):
            raise ValueError("Feature origin differs from highest supplied record's publication")
        download_info = info.get("downloads", {})
        downloads = (read_json(bound(download_info["path"], download_info["stored_sha256"]))
                     if "path" in download_info else None)
        if downloads is not None:
            monthly_downloads(downloads, package)
        snapshot_info = acquired["snapshots"][origin]
        bound(snapshot_info["bundle_path"], snapshot_info["bundle_sha256"])
        values = _package_values(package, registry, downloads, _snapshot(root, acquired, origin), origin)
        contexts[package] = {
            "registry": {"name": registry["name"], "time": registry["time"],
                         "versions": dict.fromkeys(registry["versions"])},
            "downloads": downloads, "origin": origin, "values": values}
    if len(contexts) != manifest["packages"]:
        raise ValueError("Primary package count mismatch")
    for name, digest in verified_source_hashes(root).items():
        if name in bindings and bindings[name] != digest:
            raise ValueError("Git feature source changed during verification")
        bindings[name] = digest
    return rows, contexts, acquired, dict(sorted(bindings.items()))


def _audit_package(package, context, historical):
    """Recount windows directly, separately from the feature transformation."""
    registry, downloads, origin = context["registry"], context["downloads"], context["origin"]
    edge = parse_timestamp(origin)
    result = {"package_age_days": round((edge - parse_timestamp(registry["time"]["created"])).total_seconds() / 86400, 6)}
    stable = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z")
    dates, complete = [], True
    for version in set(registry["time"]) | set(registry["versions"]):
        if not stable.fullmatch(version):
            continue
        try:
            stamp = parse_timestamp(registry["time"].get(version))
            if stamp < parse_timestamp(registry["time"]["created"]):
                complete = False
            dates.append(stamp)
        except ValueError:
            complete = False
    for length in (30, 90, 365):
        count = sum(0 <= (edge - value).total_seconds() <= length * 86400 for value in dates)
        result[f"stable_release_count_{length}d"] = count if complete else None
    older = [value for value in dates if value < edge]
    result["days_since_previous_stable_release"] = (round(min((edge - value).total_seconds() for value in older) / 86400, 6)
        if complete and older else None)
    aggregates = {}
    for label, lower_offset, upper_offset in (("30d", 30, 0), ("90d", 90, 0), ("previous_30d", 60, 30)):
        upper = edge.date() - timedelta(days=upper_offset)
        lower = edge.date() - timedelta(days=lower_offset)
        values = []
        if downloads is not None:
            for item in downloads["downloads"]:
                if lower.isoformat() <= item["day"] < upper.isoformat():
                    values.append(item["downloads"])
        count = len(values) if downloads is not None else None
        mean = sum(values) / len(values) if values else None
        aggregates[label] = (count, mean)
        result[f"downloads_observed_days_{label}"] = count
        result[f"downloads_mean_daily_{label}"] = round(mean, 6) if mean is not None else None
    current_count, current_mean = aggregates["30d"]
    prior_count, prior_mean = aggregates["previous_30d"]
    result["downloads_mean_daily_30d_change_fraction"] = (round((current_mean - prior_mean) / prior_mean, 6)
        if current_count == prior_count == 30 and prior_mean > 0 else None)
    if historical is None:
        raise ValueError("Independent origin GHSA evidence is unavailable")
    for length in (30, 90):
        identities, serious = set(), set()
        for identity, published, severity in historical["records"]:
            age = (edge - published).total_seconds()
            if 0 < age <= length * 86400:
                identities.add(identity)
                if severity in ("high", "critical"):
                    serious.add(identity)
        result[f"ghsa_count_{length}d"] = len(identities)
        result[f"ghsa_high_critical_count_{length}d"] = len(serious)
    return result


def _audit_rows(root, official, contexts, acquired, features):
    from tools.audit_release import load_snapshot
    expected_purls = [row["purl"] for row in official]
    if [row.get("purl") for row in features] != expected_purls:
        raise ValueError("Feature row order/identity differs from official records")
    package_values = {}
    for package, context in contexts.items():
        historical = load_snapshot(root, acquired, context["origin"], package)
        package_values[package] = _audit_package(package, context, historical)
    for original, actual in zip(official, features):
        package, version = parse_npm_purl(original["purl"])
        context = contexts[package]
        origin = context["origin"]
        stamp = parse_timestamp(context["registry"]["time"][version])
        if stamp != parse_timestamp(original["published_at"]) or stamp > parse_timestamp(origin):
            raise ValueError("Independent version chronology mismatch")
        numbers = version.split("+", 1)[0].split(".")
        expected = {**package_values[package], "purl": original["purl"], "forecast_origin": origin,
                    "version_age_days": round((parse_timestamp(origin) - stamp).total_seconds() / 86400, 6),
                    **dict(zip(("version_major", "version_minor", "version_patch"), map(int, numbers)))}
        if tuple(actual) != COLUMNS or any(actual.get(key) != expected[key] or
                (actual[key] is not None and type(actual[key]) is not type(expected[key])) for key in COLUMNS):
            raise ValueError("Independent feature recount differs for " + original["purl"])
    return {"valid": True, "records": len(features), "field_comparisons": len(features) * len(COLUMNS), "errors": []}


def _destination(root, output):
    destination = Path(output) if output is not None else Path(root) / "data/features"
    resolved = destination.resolve()
    for protected in ("data/processed", "data/raw", "data/provenance", "data/corrected", "data/corrections", "schema", "config"):
        path = (Path(root) / protected).resolve()
        if resolved == path or path in resolved.parents:
            raise ValueError("Feature output cannot overwrite core data or sources")
    return destination


@verification_session
def build_features(root, output=None):
    root = Path(root).resolve()
    destination = _destination(root, output)
    destination.mkdir(parents=True, exist_ok=True)
    save_json(destination / "manifest.json", {"complete": False, "valid": False})
    official, contexts, acquired, bindings = _inputs(root)
    shared = {package: context["values"] for package, context in contexts.items()}
    rows = []
    for record in official:
        package, _ = parse_npm_purl(record["purl"])
        context = contexts[package]
        values = {**shared[package], **_version_values(record, context["registry"], context["origin"])}
        rows.append({key: values[key] for key in COLUMNS})
    audited = _audit_rows(root, official, contexts, acquired, rows)
    raw = b"".join((json.dumps(row, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8") for row in rows)
    (destination / "features.jsonl").write_bytes(raw)
    with (destination / "features.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    save_json(destination / "feature-spec.json", SPEC)
    manifest = {"complete": True, "valid": True, "records": len(rows), "packages": len(contexts),
                "feature_columns": len(COLUMNS), "numeric_features": len(COLUMNS) - 2,
                "source_sha256": bindings, "audit": audited,
                "artifact_sha256": {name: sha256(destination / name) for name in ("features.jsonl", "features.csv", "feature-spec.json")}}
    save_json(destination / "manifest.json", manifest)
    return manifest


@verification_session
def audit_features(root, output=None):
    root = Path(root).resolve()
    destination = _destination(root, output)
    try:
        manifest = read_json(destination / "manifest.json")
        if manifest.get("valid") is not True or manifest.get("complete") is not True:
            raise ValueError("Feature export is incomplete")
        names = {"features.jsonl", "features.csv", "feature-spec.json"}
        if set(manifest.get("artifact_sha256", {})) != names:
            raise ValueError("Feature artifact inventory mismatch")
        for name in names:
            if sha256(destination / name) != manifest["artifact_sha256"][name]:
                raise ValueError("Feature artifact hash mismatch: " + name)
        if read_json(destination / "feature-spec.json") != SPEC:
            raise ValueError("Feature specification mismatch")
        official, contexts, acquired, bindings = _inputs(root)
        if manifest.get("source_sha256") != bindings:
            raise ValueError("Feature source bindings are stale or incomplete")
        features = [json.loads(line) for line in (destination / "features.jsonl").read_text(encoding="utf-8").splitlines()]
        result = _audit_rows(root, official, contexts, acquired, features)
        with (destination / "features.csv").open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames != list(COLUMNS) or list(reader) != [
                    {key: "" if value is None else str(value) for key, value in row.items()} for row in features]:
                raise ValueError("Feature CSV differs from typed JSONL")
        if (manifest.get("records") != len(features) or manifest.get("packages") != len(contexts)
                or manifest.get("feature_columns") != len(COLUMNS) or manifest.get("numeric_features") != len(COLUMNS) - 2
                or manifest.get("audit") != result):
            raise ValueError("Feature manifest counts or audit mismatch")
        return result
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {"valid": False, "records": 0, "field_comparisons": 0, "errors": [str(exc)]}
