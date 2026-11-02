"""Observed daily npm download counts; absent days are never invented."""
from collections import defaultdict
from datetime import date

from pcom01.schema import MONTHS


def monthly_downloads(payload, package):
    if not isinstance(payload, dict) or payload.get("package") != package:
        raise ValueError("download response package mismatch")
    if not isinstance(payload.get("downloads"), list):
        raise ValueError("download response has no daily observations")
    observations = defaultdict(dict)
    seen = set()
    month_indices = {value: key for key, value in MONTHS.items()}
    for item in payload["downloads"]:
        if not isinstance(item, dict):
            raise ValueError("malformed daily observation")
        day, count = item.get("day"), item.get("downloads")
        if not isinstance(day, str) or date.fromisoformat(day).isoformat() != day:
            raise ValueError("invalid daily observation date")
        if day in seen:
            raise ValueError("duplicate day in download response")
        seen.add(day)
        if type(count) is not int or not 0 <= count <= 2**63 - 1:
            raise ValueError("download counts must be nonnegative integers")
        if not "2025-07-01" <= day < "2026-07-01":
            raise ValueError("out-of-window daily observation")
        observations[day[:7]][day] = count
    result = {}
    for month, suffix in month_indices.items():
        daily = observations[month]
        total = sum(daily.values())
        if total > 2**63 - 1:
            raise ValueError("monthly download sum exceeds signed 64-bit range")
        # Zero days observed is known coverage, but the total is unknown.
        result[f"package_download_days_observed_{suffix}"] = len(daily)
        result[f"package_downloads_{suffix}"] = total if daily else None
    return result
