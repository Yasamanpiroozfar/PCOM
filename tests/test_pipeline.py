"""Offline integration tests with explicitly synthetic sources, never real data.

These fixtures prove transformations, evidence checking, and replay behavior.
They do not establish that the public-source acquisition has succeeded.
"""
import csv
from pathlib import Path
import tempfile
import unittest

from pcom01.advisories import _build_snapshot
from pcom01.io import read_json, save_json, sha256
from pcom01.pipeline import build, CUTOFF, OUTCOME_END
from pcom01.schema import COLUMNS


PACKAGE = "test-fixture"
OLD_ID = "GHSA-2345-2345-2345"
NEW_ID = "GHSA-3456-3456-3456"


def advisory(ghsa_id, published, severity):
    return {"id": ghsa_id, "published": published, "modified": published,
            "database_specific": {"github_reviewed": True,
                                  "github_reviewed_at": published, "severity": severity},
            "affected": [{"package": {"ecosystem": "npm", "name": PACKAGE}}]}


def prepare(root, *, download_failure=False, historical_issue=False):
    """Persist synthetic pinned sources only inside a TemporaryDirectory."""
    save_json(root / "config/packages.json", {"packages": [{"name": PACKAGE}]})
    registry = {
        "name": PACKAGE,
        "time": {"created": "2020-01-01T00:00:00.000Z",
                 "1.0.0": "2025-07-15T00:00:00.000Z",
                 "2.0.0": "2026-06-15T00:00:00.000Z"},
        "versions": {v: {"name": PACKAGE, "version": v, "dependencies": {"dep": "^1.0.0"}}
                     for v in ("1.0.0", "2.0.0")},
    }
    registry_path = root / "data/raw/registry/fixture.json.gz"
    save_json(registry_path, registry)
    old = advisory(OLD_ID, "2026-06-01T00:00:00Z", "LOW")
    future = advisory(NEW_ID, "2026-07-15T00:00:00Z", "HIGH")
    snapshots = {}
    for label, boundary, committed, docs in (
        ("history", CUTOFF, "2026-06-30T23:00:00Z", [old]),
        ("outcome", OUTCOME_END, "2026-09-28T23:00:00Z", [old, future]),
    ):
        snapshot = _build_snapshot(((f"advisories/github-reviewed/{d['id']}.json", d) for d in docs),
                                   [PACKAGE], boundary, "a" * 40, committed, "b" * 64)
        evidence = snapshot.provenance()
        if historical_issue and label == "history":
            evidence["issues"] = {PACKAGE: ["Synthetic unresolved historical evidence"]}
        path = root / f"data/raw/advisories-{label}.json.gz"
        save_json(path, {"records": snapshot.raw_records(), "provenance": evidence})
        snapshots[label] = {"bundle_path": path.relative_to(root).as_posix(), "bundle_sha256": sha256(path)}
    entry = {"registry": {"path": registry_path.relative_to(root).as_posix(),
                          "stored_sha256": sha256(registry_path)}}
    failures = []
    if download_failure:
        failures.append({"package": PACKAGE, "source": "downloads", "error": "Synthetic test failure"})
        entry["downloads"] = {"failure": failures[0]}
    else:
        path = root / "data/raw/downloads/fixture.json.gz"
        save_json(path, {"package": PACKAGE,
                         "downloads": [{"day": "2026-06-01", "downloads": 0},
                                       {"day": "2026-06-02", "downloads": 17}]})
        entry["downloads"] = {"path": path.relative_to(root).as_posix(), "stored_sha256": sha256(path)}
    save_json(root / "data/provenance/acquisition.json", {
        "selection_sha256": sha256(root / "config/packages.json"),
        "input_cutoff_exclusive": CUTOFF, "outcome_end_exclusive": OUTCOME_END,
        "snapshots": snapshots, "packages": {PACKAGE: entry}, "failures": failures,
    })


class PipelineIntegrationTests(unittest.TestCase):
    def test_build_real_shape_from_synthetic_sources_and_package_count_unit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            report = build(root)
            rows = [__import__("json").loads(line) for line in
                    (root / "data/processed/training.jsonl").read_text().splitlines()]
            self.assertEqual(len(rows), 2)
            self.assertTrue(report["validation"]["valid"])
            self.assertEqual(tuple(rows[0]), COLUMNS)
            self.assertEqual(rows[0]["dependency_count"], 1)
            self.assertEqual(rows[0]["ghsa_low_count"], 1)
            self.assertEqual(rows[0]["ghsa_low_count_M0"], 1)
            self.assertEqual(rows[0]["target_ghsa_high_count_90d"], 1)
            self.assertEqual(rows[0]["package_downloads_M0"], 17)
            self.assertEqual(rows[0]["package_download_days_observed_M0"], 2)
            self.assertIsNone(rows[0]["package_downloads_M1"])
            self.assertEqual(rows[0]["package_download_days_observed_M1"], 0)
            self.assertIsNone(rows[0]["issues_opened_M0"])
            self.assertEqual(report["row_target_totals"]["target_ghsa_high_count_90d"], 2)
            self.assertEqual(report["package_target_totals"]["target_ghsa_high_count_90d"], 1)
            evidence = read_json(root / "data/processed/advisory-evidence.json")[PACKAGE]
            self.assertEqual(evidence["targets"]["high"], [NEW_ID])
            with (root / "data/processed/training.csv").open(newline="", encoding="utf-8") as stream:
                reader = csv.DictReader(stream)
                self.assertEqual(tuple(reader.fieldnames), COLUMNS)
                self.assertEqual(next(reader)["issues_opened_M0"], "")

    def test_full_offline_rebuild_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            build(root)
            replay = root / "replay"
            build(root, output=replay)
            outputs = list((root / "data/processed").iterdir())
            self.assertGreater(len(outputs), 5)
            for original in outputs:
                self.assertEqual(original.read_bytes(), (replay / original.name).read_bytes(), original.name)

    def test_failed_optional_source_remains_null_and_reported(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root, download_failure=True)
            report = build(root)
            self.assertEqual(len(report["source_failures"]), 1)
            self.assertEqual(report["validation"]["optional_coverage"]["package_downloads_M0"], 0)
            self.assertEqual(report["validation"]["optional_coverage"]["package_download_days_observed_M0"], 0)

    def test_unverified_historical_counts_never_enter_final_training_data(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root, historical_issue=True)
            with self.assertRaises(ValueError):
                build(root)
            self.assertFalse((root / "data/processed/training.jsonl").exists())

    def test_source_hash_mismatch_prevents_final_dataset(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prepare(root)
            save_json(root / "data/raw/registry/fixture.json.gz", {"tampered": True})
            with self.assertRaises(ValueError):
                build(root)
            self.assertFalse((root / "data/processed/training.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
