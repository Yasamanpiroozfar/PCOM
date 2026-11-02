"""Strict structural/consistency validation; source evidence is audited separately.

A structurally valid row is not proof that historical source coverage was complete.
This module deliberately never converts missing counts into zero.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from urllib.parse import quote, unquote

from .schema import (COLUMNS, FIELDS, HISTORY_START, HISTORY_END, MONTHS, REQUIRED_COLUMNS,
                     OPTIONAL_COLUMNS, SEVERITIES)

TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
STABLE_SEMVER_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
NAME_PART = re.compile(r"^[A-Za-z0-9~][A-Za-z0-9._~-]*$")


def parse_timestamp(value: str) -> datetime:
    """Require exactly the course RFC3339 UTC millisecond representation."""
    if not isinstance(value, str) or not TIMESTAMP_PATTERN.fullmatch(value):
        raise ValueError("must be UTC RFC3339 with exactly three fractional digits")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("invalid calendar date or time") from exc


def parse_npm_purl(value: str) -> tuple[str, str]:
    """Validate our canonical exact stable-version npm PURL serialization.

    npm scopes are encoded as %40scope; package separators remain literal '/'.
    Query/fragment qualifiers are not part of this submission's record identity.
    Stable SemVer follows the worklog's prerelease exclusion, not a new column.
    """
    if not isinstance(value, str) or len(value) > 2048 or not value.startswith("pkg:npm/"):
        raise ValueError("must be an npm PURL of at most 2048 characters")
    body = value[len("pkg:npm/"):]
    if "?" in body or "#" in body or "@" not in body:
        raise ValueError("must identify an exact version without qualifiers or subpath")
    name_encoded, version_encoded = body.rsplit("@", 1)
    if re.search(r"%(?![0-9A-Fa-f]{2})", name_encoded + version_encoded):
        raise ValueError("invalid percent encoding")
    name, version = unquote(name_encoded, errors="strict"), unquote(version_encoded, errors="strict")
    parts = name.split("/")
    if name.startswith("@"):
        valid_name = len(parts) == 2 and bool(NAME_PART.fullmatch(parts[0][1:])) and bool(NAME_PART.fullmatch(parts[1]))
    else:
        valid_name = len(parts) == 1 and bool(NAME_PART.fullmatch(name))
    if not valid_name:
        raise ValueError("invalid npm package name or scope")
    if not STABLE_SEMVER_PATTERN.fullmatch(version):
        raise ValueError("version must be exact stable SemVer, not a range or prerelease")
    canonical = f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='._-~')}"
    if value != canonical:
        raise ValueError(f"noncanonical PURL; expected {canonical}")
    return name, version


def _prediction_datetime(value: str | datetime | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, str):
        return parse_timestamp(value)
    if isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value):
        return value
    raise ValueError("prediction_at must be a UTC-aware datetime or course-format timestamp")


def validate_record(record: dict, *, prediction_at: str | datetime | None = None) -> list[str]:
    errors = []
    if not isinstance(record, dict):
        return ["record must be a dictionary"]
    keys = tuple(record)
    if keys != COLUMNS:
        missing = [column for column in COLUMNS if column not in record]
        extra = [column for column in record if column not in COLUMNS]
        if missing:
            errors.append("missing columns: " + ", ".join(missing))
        if extra:
            errors.append("unexpected columns: " + ", ".join(extra))
        if not missing and not extra:
            errors.append("column order differs from official expanded schema")
    times = {}
    for field in FIELDS:
        name = field["name"]
        if name not in record:
            continue
        value = record[name]
        if value is None:
            if field["required"]:
                errors.append(f"{name}: required value is missing")
            continue
        if field["type"] == "integer":
            if type(value) is not int:
                errors.append(f"{name}: must be an integer (booleans/floats/strings are invalid)")
            elif not field["minimum"] <= value <= field["maximum"]:
                errors.append(f"{name}: outside [{field['minimum']}, {field['maximum']}]")
        elif field["type"] == "timestamp":
            try:
                times[name] = parse_timestamp(value)
            except (ValueError, TypeError) as exc:
                errors.append(f"{name}: {exc}")
        elif name == "purl":
            try:
                parse_npm_purl(value)
            except (ValueError, TypeError, UnicodeError) as exc:
                errors.append(f"purl: {exc}")
    if len(times) == 2 and times["package_created_at"] > times["published_at"]:
        errors.append("package_created_at must not be after published_at")
    try:
        prediction = _prediction_datetime(prediction_at)
        if prediction:
            if prediction < HISTORY_END:
                errors.append("prediction_at precedes the end of the required history window (temporal leakage)")
            if times.get("published_at") and times["published_at"] < HISTORY_START:
                errors.append("published_at precedes the required history window")
            if times.get("published_at") and times["published_at"] >= prediction:
                errors.append("published_at must precede the end-exclusive prediction cutoff")
    except ValueError as exc:
        errors.append(str(exc))
    for severity in SEVERITIES:
        lifetime = record.get(f"ghsa_{severity}_count")
        monthly = [record.get(f"ghsa_{severity}_count_M{i}") for i in range(12)]
        if type(lifetime) is int and all(type(v) is int and v >= 0 for v in monthly):
            if sum(monthly) > lifetime:
                errors.append(f"ghsa_{severity}_count: 12-month sum exceeds lifetime count")
    for month in MONTHS:
        observed = record.get(f"package_download_days_observed_{month}")
        downloads = record.get(f"package_downloads_{month}")
        if type(observed) is int and observed == 0 and downloads is not None:
            errors.append(f"package_downloads_{month}: must be missing with zero observed days")
        if type(observed) is int and observed > 0 and downloads is None:
            errors.append(f"package_downloads_{month}: observations counted but their sum is missing")
    return errors


def validate_dataset(records, *, prediction_at: str | datetime | None = None) -> dict:
    """Return JSON-serializable evidence, including empty-dataset rejection."""
    rows = list(records)
    errors, seen = [], {}
    coverage = {name: 0 for name in COLUMNS}
    for index, record in enumerate(rows, 1):
        errors.extend({"row": index, "error": error}
                      for error in validate_record(record, prediction_at=prediction_at))
        if not isinstance(record, dict):
            continue
        purl = record.get("purl")
        if isinstance(purl, str):
            if purl in seen:
                errors.append({"row": index, "error": f"duplicate purl also at row {seen[purl]}: {purl}"})
            else:
                seen[purl] = index
        for name in COLUMNS:
            coverage[name] += record.get(name) is not None
    if not rows:
        errors.append({"row": None, "error": "dataset is empty; no real records validated"})
    return {"valid": not errors, "row_count": len(rows), "column_count": len(COLUMNS),
            "required_column_count": len(REQUIRED_COLUMNS), "optional_column_count": len(OPTIONAL_COLUMNS),
            "errors": errors, "nonmissing_counts": coverage,
            "required_coverage": {name: coverage[name] for name in REQUIRED_COLUMNS},
            "optional_coverage": {name: coverage[name] for name in OPTIONAL_COLUMNS},
            "scope": "Structural and consistency checks; historical authenticity requires provenance audit."}


def read_jsonl(path: Path | str) -> list[dict]:
    with Path(path).open(encoding="utf-8") as source:
        return [json.loads(line) for line in source if line.strip()]


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--prediction-at")
    args = parser.parse_args()
    report = validate_dataset(read_jsonl(args.dataset), prediction_at=args.prediction_at)
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["valid"] else 1)
