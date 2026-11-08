"""Compare corrected records with the original dataset."""
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcom01.io import read_json, save_json, sha256
from pcom01.schema import COLUMNS
from pcom01.validation import parse_npm_purl


def main():
    original_path = ROOT / "data/processed/training.jsonl"
    old = {row["purl"]: row for line in original_path.read_text(encoding="utf-8").splitlines()
           for row in [json.loads(line)]}
    targets = [name for name in COLUMNS if name.startswith("target_")]
    old_by_package = {parse_npm_purl(identity)[0]: row for identity, row in old.items()}
    scenarios = {}
    for scope in ("supplied", "all-precutoff"):
        folder = ROOT / "data/corrections" / scope
        rows = [json.loads(line) for line in (folder / "candidate-records.jsonl").read_text(encoding="utf-8").splitlines()]
        new = {row["purl"]: row for row in rows}
        metadata = read_json(folder / "row-metadata.json")
        field_changes = Counter()
        row_changes = []
        for identity in sorted(new):
            if identity not in old:
                continue
            before, after = old[identity], new[identity]
            changed = [name for name in COLUMNS if before[name] != after[name]]
            field_changes.update(changed)
            row_changes.append({"purl": identity, "changed_columns": changed})
        packages = {}
        for item in metadata:
            package, identity = item["package"], item["purl"]
            if package in packages:
                continue
            packages[package] = {
                "origin": item["origin"], "outcome_end": item["outcome_end"],
                "anchor_version": item["anchor_version"],
                "old_common_cutoff_targets": {name: old_by_package[package][name] for name in targets},
                "new_release_origin_targets": {name: new[identity][name] for name in targets},
                "targets_measured": all(new[identity][name] is not None for name in targets),
                "target_vector_changed": any(old_by_package[package][name] != new[identity][name] for name in targets)}
        scenarios[scope] = {
            "candidate_sha256": sha256(folder / "candidate-records.jsonl"),
            "original_rows": len(old), "candidate_rows": len(new),
            "removed_purls": sorted(set(old) - set(new)),
            "added_purls": sorted(set(new) - set(old)),
            "added_row_count": len(set(new) - set(old)),
            "changed_row_count": sum(bool(item["changed_columns"]) for item in row_changes),
            "changed_cell_count": sum(field_changes.values()),
            "change_count_scope": "Changes compare surviving original rows only; recovered new rows are listed separately in added_purls.",
            "changed_cells_by_column": dict(sorted(field_changes.items())),
            "package_target_comparison": packages, "row_changes": row_changes,
            "role": "primary_corrected" if scope == "supplied" else "sensitivity",
            "interpretation": "Primary supplied-version origin-known measurements." if scope == "supplied" else "Alternative all-precutoff version universe; sensitivity analysis only."}
    report = {"original_dataset_sha256": sha256(original_path), "scenarios": scenarios,
              "primary_scope": "supplied", "publication_permitted": False}
    save_json(ROOT / "reports/correction-comparison.json", report)
    print(json.dumps({scope: {key: item[key] for key in ("candidate_rows", "changed_row_count", "changed_cell_count", "removed_purls")}
                      for scope, item in scenarios.items()}, indent=2))


if __name__ == "__main__":
    main()
