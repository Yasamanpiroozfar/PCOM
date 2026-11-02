"""Official, ordered 224-column course schema and fixed monthly windows."""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = PROJECT_ROOT / "schema" / "record_schema.json"
SEVERITIES = ("low", "moderate", "high", "critical", "unknown")


def load_contract(path: Path | str = SCHEMA_PATH) -> dict:
    contract = json.loads(Path(path).read_text(encoding="utf-8"))
    fields = contract["fields"]
    if len(fields) != 224 or len({f["name"] for f in fields}) != 224:
        raise ValueError("Contract must contain exactly 224 distinct ordered columns")
    if sum(f["required"] for f in fields) != 78:
        raise ValueError("Contract must contain exactly 78 required fields")
    return contract


CONTRACT = load_contract()
FIELDS = tuple(CONTRACT["fields"])
COLUMNS = tuple(field["name"] for field in FIELDS)
REQUIRED_COLUMNS = tuple(field["name"] for field in FIELDS if field["required"])
OPTIONAL_COLUMNS = tuple(field["name"] for field in FIELDS if not field["required"])
FIELD_BY_NAME = {field["name"]: field for field in FIELDS}
MONTHS = dict(CONTRACT["months"])


def _month_window(month: str) -> tuple[datetime, datetime]:
    year, number = map(int, month.split("-"))
    next_year, next_month = (year + 1, 1) if number == 12 else (year, number + 1)
    return (datetime(year, number, 1, tzinfo=timezone.utc),
            datetime(next_year, next_month, 1, tzinfo=timezone.utc))


MONTH_WINDOWS = {name: _month_window(month) for name, month in MONTHS.items()}
HISTORY_START = MONTH_WINDOWS["M11"][0]
HISTORY_END = MONTH_WINDOWS["M0"][1]
TARGET_COLUMNS = tuple(f"target_ghsa_{severity}_count_90d" for severity in SEVERITIES)


def blank_record() -> dict:
    """All fields start unknown; callers must provide evidence before writing zero."""
    return dict.fromkeys(COLUMNS, None)
