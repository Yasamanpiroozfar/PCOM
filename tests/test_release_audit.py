"""Independent audit regressions using only synthetic two-scope source captures.

Tampering tests reseal every affected checksum deliberately: the audit must
reject false measurements by comparing raw evidence, not just hash consistency.
"""
import csv
import json
from pathlib import Path
import tempfile
import unittest

from pcom01.io import read_json, save_json, sha256
from pcom01.release import build_release
from pcom01.schema import COLUMNS, SCHEMA_PATH
from tools.audit_release import audit
from test_release import prepare_sources


class IndependentReleaseAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        prepare_sources(self.root)
        for scope in ("supplied", "all-precutoff"):
            build_release(self.root, scope)

    def reseal(self, scope="supplied", *, edit_rows=None, edit_report=None):
        folder = self.root / "data/corrections" / scope
        rows = [json.loads(line) for line in (folder / "candidate-records.jsonl").read_text().splitlines()]
        if edit_rows is not None:
            edit_rows(rows)
            encoded = b"".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")).encode() + b"\n" for row in rows)
            (folder / "candidate-records.jsonl").write_bytes(encoded)
            with (folder / "candidate-records.csv").open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=COLUMNS, lineterminator="\n")
                writer.writeheader()
                writer.writerows({key: "" if value is None else value for key, value in row.items()} for row in rows)
        report = read_json(folder / "report.json")
        report["candidate_sha256"] = sha256(folder / "candidate-records.jsonl")
        if edit_report is not None:
            edit_report(report)
        save_json(folder / "report.json", report)
        state = read_json(folder / "build-status.json")
        state["candidate_sha256"] = report["candidate_sha256"]
        state["artifact_sha256"] = {name: sha256(folder / name) for name in state["artifact_sha256"]}
        save_json(folder / "build-status.json", state)

    def test_clean_primary_passes_independent_readiness_without_promoting_sensitivity(self):
        result = audit(self.root)
        self.assertTrue(result["valid_candidate_derivation"])
        self.assertTrue(result["ready_for_submission"])
        self.assertTrue(result["scopes"]["supplied"]["ready_for_submission"])
        self.assertFalse(result["scopes"]["all-precutoff"]["ready_for_submission"])
        self.assertEqual(set(result["scopes"]), {"supplied", "all-precutoff"})
        for details in result["scopes"].values():
            self.assertEqual(details["candidate_records_audited"], 2)
            self.assertEqual(details["source_value_comparisons"], 448)
            self.assertEqual(details["errors"], [])

    def test_resealed_dependency_tamper_is_caught_by_direct_source_comparison(self):
        self.reseal(edit_rows=lambda rows: rows[0].update(dependency_count=999))
        result = audit(self.root)
        self.assertFalse(result["valid_candidate_derivation"])
        self.assertFalse(result["ready_for_submission"])
        self.assertTrue(result["scopes"]["all-precutoff"]["valid_candidate_derivation"])
        errors = result["scopes"]["supplied"]["errors"]
        self.assertTrue(any("dependency_count: direct source disagreement" in message for message in errors))
        self.assertFalse(any("hash mismatch" in message or "digest mismatch" in message or "CSV/JSONL" in message for message in errors))

    def test_resealed_future_observation_and_unapproved_publication_are_both_detected(self):
        # The fixture's June source really contains 999999 downloads, but that
        # day occurs after the May release origin and cannot be an input.
        def add_future_observation(rows):
            for row in rows:
                row["package_downloads_M0"] = 999999
                row["package_download_days_observed_M0"] = 1

        self.reseal(edit_rows=add_future_observation,
                    edit_report=lambda report: report.update(ready_for_submission=True, publication_permitted=True))
        result = audit(self.root)
        self.assertFalse(result["valid_candidate_derivation"])
        errors = result["scopes"]["supplied"]["errors"]
        self.assertTrue(any("package_downloads_M0: direct source disagreement" in message for message in errors))
        self.assertTrue(any("publication" in message.lower() for message in errors))
        self.assertFalse(any("hash mismatch" in message or "digest mismatch" in message or "CSV/JSONL" in message for message in errors))

    def test_sensitivity_readiness_claim_is_rejected_even_with_consistent_measurements(self):
        self.reseal("all-precutoff", edit_report=lambda report: report.update(ready_for_submission=True))
        result = audit(self.root)
        self.assertFalse(result["scopes"]["all-precutoff"]["valid_candidate_derivation"])
        self.assertFalse(result["scopes"]["all-precutoff"]["ready_for_submission"])
        self.assertTrue(any("readiness" in message.lower() for message in result["scopes"]["all-precutoff"]["errors"]))


if __name__ == "__main__":
    unittest.main()
