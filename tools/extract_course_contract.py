"""Read the original course workbooks without altering them; emit a schema contract.

This intentionally uses only Python's standard library and reads XLSX XML in memory.
It never evaluates formulas or exports/re-saves the source workbooks.
"""
from __future__ import annotations

import argparse
import calendar
from datetime import date, timedelta
import hashlib
import json
from pathlib import Path
import posixpath
import re
import xml.etree.ElementTree as ET
import zipfile

MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
NS = {"m": MAIN}
SCHEMA_FILE = "PCOM-01 Record Schema [Public].xlsx"
ORGANIZATION_FILE = "PCOM Organization [Public].xlsx"


def inspect_workbook(path: Path) -> dict:
    """Read all sheets, values and formula definitions/cached results in a workbook."""
    with zipfile.ZipFile(path) as archive:
        bad_entry = archive.testzip()
        if bad_entry:
            raise ValueError(f"Corrupt ZIP member in {path.name}: {bad_entry}")
        shared = []
        if "xl/sharedStrings.xml" in archive.namelist():
            root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            shared = ["".join(t.text or "" for t in item.findall(".//m:t", NS))
                      for item in root.findall("m:si", NS)]
        rels = {item.attrib["Id"]: item.attrib["Target"] for item in
                ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))}
        workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        sheets = []
        for sheet in workbook.findall("m:sheets/m:sheet", NS):
            target = rels[sheet.attrib[f"{{{REL}}}id"]]
            member = target.lstrip("/") if target.startswith("/") else posixpath.normpath("xl/" + target)
            root = ET.fromstring(archive.read(member))
            cells, formulas = {}, {}
            for cell in root.findall("m:sheetData/m:row/m:c", NS):
                address, kind = cell.attrib["r"], cell.attrib.get("t")
                value = cell.find("m:v", NS)
                if kind == "inlineStr":
                    inline = cell.find("m:is", NS)
                    contents = "".join(t.text or "" for t in inline.findall(".//m:t", NS))
                elif value is not None:
                    contents = shared[int(value.text)] if kind == "s" else value.text
                else:
                    contents = None
                if contents not in (None, ""):
                    cells[address] = contents
                formula = cell.find("m:f", NS)
                if formula is not None:
                    formulas[address] = {"expression": formula.text,
                                         "attributes": dict(formula.attrib),
                                         "cached_value": contents}
            sheets.append({"name": sheet.attrib["name"],
                           "visibility": sheet.attrib.get("state", "visible"),
                           "cells": cells, "formulas": formulas})
    return {"filename": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "worksheets": sheets}


def expand_fields(cells: dict[str, str]) -> list[dict]:
    fields = []
    row = 5
    while row <= 82:
        name = cells.get(f"C{row}")
        if not name:
            row += 1
            continue
        if name == "…":
            raise ValueError(f"Unexpected unattached ellipsis at C{row}")
        if not cells.get(f"D{row}"):
            raise ValueError(f"Missing field type at D{row}")
        monthly = name.endswith("_M0")
        last_row = row + 2 if monthly else row
        if monthly:
            assert cells.get(f"C{row + 1}") == "…"
            assert cells.get(f"C{last_row}") == name[:-1] + "11"
            assert cells[f"D{last_row}"] == cells[f"D{row}"]
            assert cells[f"E{last_row}"] == cells[f"E{row}"]
        for month in range(12) if monthly else (None,):
            field_name = re.sub(r"_M0$", f"_M{month}", name) if monthly else name
            explanation = cells.get(f"H{row}", "")
            if monthly:
                explanation = re.sub(r"\bM0\b", f"M{month}", explanation)
            constraints = cells[f"E{row}"]
            field_type = cells[f"D{row}"]
            record = {
                "name": field_name,
                "type": "integer" if field_type.startswith("Integer") else
                        "timestamp" if field_type.startswith("Timestamp") else "string",
                "required": constraints.startswith("Required"),
                "nullable": constraints.startswith("Optional"),
                "official_type": field_type,
                "constraints": constraints,
                "origin": cells.get(f"G{row}", ""),
                "description": explanation,
                "source": {"sheet": "Schema", "rows": [row, last_row],
                           "field_cell": f"C{row}", "constraint_cell": f"E{row}"},
            }
            if monthly:
                record["month_index"] = month
            if record["type"] == "integer":
                record.update(minimum=0, maximum=2**63 - 1)
                if field_name.startswith("package_download_days_observed_"):
                    absolute_month = 2026 * 12 + 5 - month
                    y, m = divmod(absolute_month, 12)
                    record["maximum"] = calendar.monthrange(y, m + 1)[1]
            fields.append(record)
        row = last_row + 1
    assert len(fields) == 224, len(fields)
    assert len({f["name"] for f in fields}) == 224
    assert sum(f["required"] for f in fields) == 78
    return fields


def build(course_dir: Path, output_dir: Path) -> dict:
    schema_book = inspect_workbook(course_dir / SCHEMA_FILE)
    organization = inspect_workbook(course_dir / ORGANIZATION_FILE)
    schema_sheets = {s["name"]: s for s in schema_book["worksheets"]}
    documentation = schema_sheets["Documentation"]["cells"]
    assert documentation["B2"] == "M0 = June 2026"
    assert documentation["B3"] == "M1 = May 2026"
    assert documentation["B5"] == "M11 = July 2025"
    months = {}
    for i in range(12):
        absolute = 2026 * 12 + 5 - i
        year, zero_month = divmod(absolute, 12)
        months[f"M{i}"] = f"{year:04}-{zero_month + 1:02}"
    contract = {
        "contract_version": 1,
        "source_file": SCHEMA_FILE,
        "source_sha256": schema_book["sha256"],
        "column_order_policy": "Workbook Schema sheet top-to-bottom; each M0 ... M11 range expanded in increasing index order.",
        "months": months,
        "month_source": {"sheet": "Documentation", "cells": ["B2", "B3", "B5"]},
        "field_count": 224, "required_count": 78, "optional_count": 146,
        "fields": expand_fields(schema_sheets["Schema"]["cells"]),
    }
    def inventory(book):
        return {"filename": book["filename"], "sha256": book["sha256"],
                "worksheets": [{"name": s["name"], "visibility": s["visibility"],
                                "nonempty_cell_count": len(s["cells"]),
                                "formula_cell_count": len(s["formulas"])} for s in book["worksheets"]]}
    schedule = organization["worksheets"][0]["cells"]
    serial = float(schedule["B14"])
    assigned = date(1899, 12, 30) + timedelta(days=serial)
    evidence = {
        "method": "Read-only ZIP/XML inspection of every worksheet. Formula definitions and cached results read, not recalculated.",
        "workbooks": [inventory(schema_book), inventory(organization)],
        "schedule": {"assigned_date": assigned.isoformat(), "source_cells": ["PCOM-01!B14", "PCOM-01!N14", "PCOM-01!N11"],
                     "assignment": schedule["N14"], "deadline_header": schedule["N11"],
                     "inferred_due_date": (assigned + timedelta(days=7)).isoformat(),
                     "caveat": "Due date inferred from due-next-week header; no precise deadline time established."},
        "ambiguities": [
            {"source": "Schema!C5:H7", "issue": "No prediction or collection timestamp is defined as a column; store run-level cutoffs and collection provenance separately."},
            {"source": "Schema!F6:F7", "issue": "Example package creation is 2026-07-01 but example publication is 2026-04-08; examples cannot form one chronological record."},
            {"source": "Schema!C78:H82", "issue": "Five severity targets include unknown, whereas worklog describes a four-tuple. Preserve all five contract columns."},
            {"source": "Schema!H56:H82", "issue": "At prediction and at outcome end require historical advisory state. Current metadata alone is not sufficient evidence."},
            {"source": "Schema!H78:H82", "issue": "Targets affect any version of the package, not necessarily the exact version named in the record PURL."},
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, content in (("record_schema.json", contract), ("course_evidence.json", evidence)):
        (output_dir / name).write_text(json.dumps(content, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    (output_dir / "columns.txt").write_text("\n".join(f["name"] for f in contract["fields"]) + "\n", encoding="utf-8", newline="\n")
    return {"columns": len(contract["fields"]), "required": sum(f["required"] for f in contract["fields"]),
            "optional": sum(f["nullable"] for f in contract["fields"]), "source_sha256": schema_book["sha256"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--course-dir", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parents[1] / "schema")
    args = parser.parse_args()
    print(json.dumps(build(args.course_dir, args.output_dir), indent=2))
