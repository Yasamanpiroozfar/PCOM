"""Pure transformations of full npm registry metadata; no network or execution.

The registry document must be fetched with ``Accept: application/json``.  The
absence of a dependency map in that *full*, successfully fetched document means
that no dependencies of that kind were declared. A null/malformed map does not.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timezone
import re
from urllib.parse import quote


HISTORY_START = "2025-07-01T00:00:00.000Z"
CUTOFF = "2026-07-01T00:00:00.000Z"
INT64_MAX = 2**63 - 1
_IDENTIFIER = r"[0-9A-Za-z-]+"
_SEMVER = re.compile(
    rf"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    rf"(?:-({_IDENTIFIER}(?:\.{_IDENTIFIER})*))?"
    rf"(?:\+({_IDENTIFIER}(?:\.{_IDENTIFIER})*))?$"
)
_NAME_PART = r"[a-z0-9][a-z0-9._-]*"
_NAME = re.compile(rf"^(?:@{_NAME_PART}/)?{_NAME_PART}$")
_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$"
)
DEPENDENCY_FIELDS = {
    "dependencies": "dependency_count",
    "optionalDependencies": "optional_dependency_count",
    "peerDependencies": "peer_dependency_count",
    "devDependencies": "dev_dependency_count",
}


class MetadataError(ValueError):
    """A required source fact is absent, malformed, or contradictory."""


def parse_timestamp(value: str) -> datetime:
    """Read an explicit RFC 3339 timezone, returning an aware UTC datetime."""
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        raise MetadataError(f"invalid timezone-qualified timestamp: {value!r}")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MetadataError(f"invalid calendar timestamp: {value!r}") from exc
    return result.astimezone(timezone.utc)


def format_timestamp(value: datetime) -> str:
    """Use the course's exact UTC millisecond representation."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise MetadataError("a naive timestamp cannot be formatted as UTC")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _semver_match(version: str) -> re.Match:
    if not isinstance(version, str):
        raise MetadataError("version must be a string")
    match = _SEMVER.fullmatch(version)
    if match is None:
        raise MetadataError(f"not an exact SemVer 2.0 version: {version!r}")
    prerelease = match.group(4)
    if prerelease and any(part.isdigit() and len(part) > 1 and part[0] == "0"
                          for part in prerelease.split(".")):
        raise MetadataError(f"prerelease numeric identifier has a leading zero: {version!r}")
    return match


def stable_semver_key(version: str) -> tuple[int, int, int]:
    """Stable SemVer precedence. Build metadata does not influence precedence."""
    match = _semver_match(version)
    if match.group(4) is not None:
        raise MetadataError(f"prerelease version excluded: {version!r}")
    return tuple(int(match.group(index)) for index in (1, 2, 3))


def exact_purl(package_name: str, version: str) -> str:
    """Construct a canonical npm PURL, including encoded scope/build metadata."""
    if not isinstance(package_name, str) or not _NAME.fullmatch(package_name):
        raise MetadataError(f"unsupported or invalid npm package name: {package_name!r}")
    stable_semver_key(version)
    result = f"pkg:npm/{quote(package_name, safe='/')}@{quote(version, safe='._-~')}"
    if len(result) > 2048:
        raise MetadataError("PURL exceeds the course maximum length of 2048")
    return result


def _dependency_map(manifest: Mapping, field: str) -> Mapping:
    if field not in manifest:
        return {}
    value = manifest[field]
    if not isinstance(value, Mapping):
        raise MetadataError(f"{field} is present but is not a dependency map")
    if any(not isinstance(name, str) or not name for name in value):
        raise MetadataError(f"{field} contains an invalid dependency name")
    return value


def _bundle_names(value: object, direct_names: set[str]) -> set[str]:
    if value is True:
        return direct_names
    if value is False:
        return set()
    if not isinstance(value, list) or any(not isinstance(name, str) or not name for name in value):
        raise MetadataError("bundling declaration must be a boolean or array of nonempty names")
    return set(value)


def count_dependencies(manifest: Mapping) -> dict[str, int]:
    """Count declared maps independently, including optional peers and overlap.

    The bundle count measures distinct designated direct names, never installed
    or transitive tarball contents. ``true`` designates ordinary and optional
    runtime dependencies; ``false`` designates none. Both npm spellings work.
    Conflicting aliases are rejected instead of guessing a precedence rule.
    """
    if not isinstance(manifest, Mapping):
        raise MetadataError("version manifest must be an object")
    maps = {field: _dependency_map(manifest, field) for field in DEPENDENCY_FIELDS}
    result = {column: len(maps[field]) for field, column in DEPENDENCY_FIELDS.items()}
    direct_names = set(maps["dependencies"]) | set(maps["optionalDependencies"])
    declarations = [_bundle_names(manifest[key], direct_names)
                    for key in ("bundleDependencies", "bundledDependencies") if key in manifest]
    if len(declarations) == 2 and declarations[0] != declarations[1]:
        raise MetadataError("bundleDependencies and bundledDependencies conflict")
    result["bundled_dependency_count"] = len(declarations[0]) if declarations else 0
    return result


def _optional_integer(dist: Mapping, key: str, warnings: list[dict], version: str) -> int | None:
    value = dist.get(key)
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= INT64_MAX:
        warnings.append({"version": version, "reason": "invalid_optional_dist_value", "field": key})
        return None
    return value


def _month_index(date: datetime, cutoff: datetime) -> int:
    # cutoff is the first instant of the month after M0.
    return (cutoff.year * 12 + cutoff.month) - (date.year * 12 + date.month) - 1


def transform(
    packument: Mapping,
    package_name: str,
    *,
    history_start: str = HISTORY_START,
    cutoff: str = CUTOFF,
) -> dict:
    """Transform authentic registry metadata, with explicit exclusions.

    Returns ``records``, ``excluded``, ``warnings``, ``latest_semver``,
    ``latest_semver_candidates`` (ties ignoring build metadata), and statistics.
    Rows cover stable versions published in [history_start, cutoff); npm's
    current dist-tags are never used. Latest is evaluated over all timestamped
    stable versions published before cutoff, including older versions.

    Output rows are intentionally partial: the caller adds independently
    acquired GHSA/download data and all remaining optional schema fields.
    """
    if not isinstance(packument, Mapping) or packument.get("name") != package_name:
        raise MetadataError("packument name does not match the requested package")
    # Validate name even if there are no eligible versions.
    exact_purl(package_name, "0.0.0")
    versions, times = packument.get("versions"), packument.get("time")
    if not isinstance(versions, Mapping) or not isinstance(times, Mapping):
        raise MetadataError("a full packument with versions and time maps is required")
    if any(not isinstance(key, str) for key in versions) or any(not isinstance(key, str) for key in times):
        raise MetadataError("version and time map keys must be strings")
    start, end = parse_timestamp(history_start), parse_timestamp(cutoff)
    if start >= end or start.day != 1 or end.day != 1 or start.time().isoformat() != "00:00:00" or end.time().isoformat() != "00:00:00":
        raise MetadataError("history bounds must be increasing UTC month starts")
    if (end.year - start.year) * 12 + end.month - start.month != 12:
        raise MetadataError("the official history has exactly 12 calendar months")
    created = parse_timestamp(times.get("created"))
    records, exclusions, warnings = [], [], []
    stable_dates: dict[str, datetime] = {}
    stable_count_complete = True
    for version in sorted(set(versions) | set(times)):
        if version in {"created", "modified", "unpublished"}:
            continue
        try:
            stable_semver_key(version)
        except MetadataError as exc:
            if version in versions:
                reason = "prerelease" if "prerelease version excluded" in str(exc) else "noncanonical_semver"
                exclusions.append({"version": version, "reason": reason})
            continue
        try:
            date = parse_timestamp(times.get(version))
            if date < created:
                raise MetadataError("version publication precedes package creation")
        except MetadataError as exc:
            stable_count_complete = False
            exclusions.append({"version": version, "reason": "invalid_publication_timestamp", "detail": str(exc)})
            continue
        stable_dates[version] = date
        if version not in versions:
            exclusions.append({"version": version, "reason": "timestamp_without_version_manifest"})
            continue
        if not start <= date < end:
            exclusions.append({"version": version, "reason": "before_history" if date < start else "at_or_after_cutoff"})
            continue
        manifest = versions[version]
        try:
            if not isinstance(manifest, Mapping):
                raise MetadataError("version manifest is not an object")
            if manifest.get("name") != package_name or manifest.get("version") != version:
                raise MetadataError("manifest package/version does not match registry identity")
            dependencies = count_dependencies(manifest)
        except MetadataError as exc:
            exclusions.append({"version": version, "reason": "invalid_manifest", "detail": str(exc)})
            continue
        dist = manifest.get("dist", {})
        if not isinstance(dist, Mapping):
            warnings.append({"version": version, "reason": "invalid_optional_dist_object"})
            dist = {}
        record = {
            "purl": exact_purl(package_name, version),
            "package_created_at": format_timestamp(created),
            "published_at": format_timestamp(date),
            "unpacked_size": _optional_integer(dist, "unpackedSize", warnings, version),
            "file_count": _optional_integer(dist, "fileCount", warnings, version),
            **dependencies,
        }
        records.append((version, record))

    counts = Counter(_month_index(date, end) for date in stable_dates.values() if start <= date < end)
    for _, record in records:
        for month in range(12):
            record[f"package_stable_release_count_M{month}"] = counts[month] if stable_count_complete else None
    asof_versions = [version for version, date in stable_dates.items() if date < end]
    highest_key = max((stable_semver_key(version) for version in asof_versions), default=None)
    latest_candidates = sorted(version for version in asof_versions if stable_semver_key(version) == highest_key)
    if len(latest_candidates) > 1:
        warnings.append({"reason": "highest_semver_build_metadata_tie", "versions": latest_candidates})
    if not stable_count_complete:
        warnings.append({"reason": "stable_release_counts_unavailable_due_to_invalid_publication_time"})
    # Lexical tie-break only makes the manifest deterministic. It does not assert
    # that one build-metadata variant has higher semantic precedence.
    latest = latest_candidates[0] if latest_candidates else None
    records.sort(key=lambda item: (stable_semver_key(item[0]), item[0]))
    record_versions = {version for version, _ in records}
    return {
        "records": [record for _, record in records],
        "excluded": exclusions,
        "warnings": warnings,
        "latest_semver": latest,
        "latest_semver_candidates": latest_candidates,
        "latest_semver_in_records": latest in record_versions,
        "latest_semver_verified_for_returned_metadata": stable_count_complete,
        "statistics": {
            "versions_in_registry": len(versions),
            "valid_timestamped_stable_versions": len(stable_dates),
            "stable_versions_in_history": sum(start <= date < end for date in stable_dates.values()),
            "records": len(records),
            "stable_release_counts_complete_for_returned_metadata": stable_count_complete,
            "excluded_by_reason": dict(sorted(Counter(item["reason"] for item in exclusions).items())),
        },
    }
