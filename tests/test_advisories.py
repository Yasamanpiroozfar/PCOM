"""Synthetic unit fixtures only; none of these records belong to the dataset."""

import copy
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

from pcom01.advisories import (
    HistoricalEvidenceError, derive_features, load_snapshot_archive,
    month_window, package_evidence, restore_snapshot, severity_category, utc,
)


CUTOFF = "2026-07-01T00:00:00Z"
END = "2026-09-29T00:00:00Z"
HISTORY_SHA = "1" * 40
OUTCOME_SHA = "2" * 40


def advisory(suffix="2345", published="2026-06-10T12:00:00Z", severity="HIGH", package="test-package"):
    return {
        "id": f"GHSA-2345-6789-{suffix}",
        "published": published,
        "modified": published,
        "aliases": ["CVE-2026-00001"],
        "affected": [{"package": {"ecosystem": "npm", "name": package}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}],
        "database_specific": {"github_reviewed": True, "github_reviewed_at": published, "severity": severity},
    }


class AdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.counter = 0

    def snapshot(self, documents, boundary=CUTOFF, sha=HISTORY_SHA, commit="2026-06-30T23:00:00Z", packages=("test-package",), prefix=None):
        self.counter += 1
        path = Path(self.temp.name) / f"snapshot-{self.counter}.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for index, document in enumerate(documents):
                root = prefix or f"advisory-database-{sha}"
                name = f"{root}/advisories/github-reviewed/2026/{index:02}/{document['id']}/{document['id']}.json"
                payload = json.dumps(document).encode()
                item = tarfile.TarInfo(name)
                item.size = len(payload)
                archive.addfile(item, io.BytesIO(payload))
        return load_snapshot_archive(path, packages, boundary, sha, commit)

    def outcome(self, documents, **kwargs):
        return self.snapshot(documents, boundary=END, sha=OUTCOME_SHA, commit="2026-09-28T23:00:00Z", **kwargs)

    def test_known_counts_and_seventy_columns(self):
        history = self.snapshot([
            advisory("2345", "2026-06-01T00:00:00Z", "LOW"),
            advisory("2346", "2025-07-01T00:00:00Z", "HIGH"),
            advisory("2347", "2025-06-30T23:59:59Z", "CRITICAL"),
            advisory("2348", "2026-02-15T12:00:00Z", None),
        ])
        outcome = self.outcome([advisory("2355", "2026-07-01T00:00:00Z", "MODERATE")])
        values = derive_features("test-package", history, outcome, CUTOFF)
        self.assertEqual(len(values), 70)
        self.assertEqual(values["ghsa_low_count_M0"], 1)
        self.assertEqual(values["ghsa_high_count_M11"], 1)
        self.assertEqual(values["ghsa_critical_count"], 1)
        self.assertEqual(sum(values[f"ghsa_critical_count_M{i}"] for i in range(12)), 0)
        self.assertEqual(values["ghsa_unknown_count_M4"], 1)
        self.assertEqual(values["target_ghsa_moderate_count_90d"], 1)

    def test_month_mapping_and_cross_year(self):
        self.assertEqual(tuple(str(x.date()) for x in month_window(0, CUTOFF)), ("2026-06-01", "2026-07-01"))
        self.assertEqual(tuple(str(x.date()) for x in month_window(11, CUTOFF)), ("2025-07-01", "2025-08-01"))
        self.assertEqual(tuple(str(x.date()) for x in month_window(6, CUTOFF)), ("2025-12-01", "2026-01-01"))
        for index in (-1, 12, True):
            with self.assertRaises(HistoricalEvidenceError):
                month_window(index, CUTOFF)

    def test_timezone_required(self):
        with self.assertRaises(HistoricalEvidenceError):
            utc("2026-07-01T00:00:00")

    def test_duplicate_documents_and_affected_entries_count_once(self):
        record = advisory()
        record["affected"] *= 3
        history = self.snapshot([record, copy.deepcopy(record)])
        values = derive_features("test-package", history, self.outcome([record]), CUTOFF)
        self.assertEqual(values["ghsa_high_count"], 1)

    def test_same_cve_two_distinct_ghsas_count_twice(self):
        history = self.snapshot([advisory("2345"), advisory("2346")])
        values = derive_features("test-package", history, self.outcome([advisory("2345")]), CUTOFF)
        self.assertEqual(values["ghsa_high_count"], 2)

    def test_conflicting_duplicate_refuses_snapshot(self):
        first, second = advisory(), advisory(severity="LOW")
        with self.assertRaises(HistoricalEvidenceError):
            self.snapshot([first, second])

    def test_future_severity_revision_does_not_change_features(self):
        before = advisory(severity="LOW")
        after = advisory(severity="CRITICAL")
        after["modified"] = "2026-08-01T00:00:00Z"
        after["database_specific"]["github_reviewed_at"] = after["modified"]
        values = derive_features("test-package", self.snapshot([before]), self.outcome([after]), CUTOFF)
        self.assertEqual(values["ghsa_low_count"], 1)
        self.assertEqual(values["ghsa_critical_count"], 0)
        self.assertEqual(values["target_ghsa_critical_count_90d"], 0)

    def test_future_mapping_cannot_leak_into_history(self):
        before = advisory(package="other-package")
        after = advisory(package="test-package")
        after["modified"] = "2026-08-01T00:00:00Z"
        values = derive_features("test-package", self.snapshot([before]), self.outcome([after]), CUTOFF)
        self.assertEqual(values["ghsa_high_count"], 0)
        self.assertEqual(values["target_ghsa_high_count_90d"], 0)

    def test_exact_90_day_window(self):
        history = self.snapshot([advisory(package="other-package")])
        outcome = self.outcome([
            advisory("2355", "2026-07-01T00:00:00Z"),
            advisory("2356", "2026-09-28T23:59:59.999Z"),
        ])
        self.assertEqual(derive_features("test-package", history, outcome, CUTOFF)["target_ghsa_high_count_90d"], 2)
        self.assertEqual(package_evidence("test-package", history, outcome, CUTOFF)["outcome_end_exclusive"], END)

    def test_end_boundary_advisory_is_future_information(self):
        outcome = self.outcome([advisory("2355", END)])
        with self.assertRaises(HistoricalEvidenceError):
            derive_features("test-package", self.snapshot([advisory()]), outcome, CUTOFF)

    def test_snapshot_after_cutoff_rejected(self):
        with self.assertRaises(HistoricalEvidenceError):
            self.snapshot([advisory()], commit=CUTOFF)

    def test_future_modified_timestamp_blocks_counts(self):
        record = advisory()
        record["modified"] = "2026-08-01T00:00:00Z"
        history = self.snapshot([record])
        with self.assertRaises(HistoricalEvidenceError):
            derive_features("test-package", history, self.outcome([advisory()]), CUTOFF)

    def test_future_review_timestamp_blocks_counts(self):
        record = advisory()
        record["database_specific"]["github_reviewed_at"] = "2026-07-02T00:00:00Z"
        with self.assertRaises(HistoricalEvidenceError):
            self.snapshot([record]).require_package("test-package")

    def test_unreviewed_record_cannot_be_silently_counted_as_zero(self):
        record = advisory()
        record["database_specific"]["github_reviewed"] = False
        with self.assertRaises(HistoricalEvidenceError):
            self.snapshot([record]).require_package("test-package")

    def test_withdrawn_records_excluded_as_of_own_snapshot(self):
        historical = advisory()
        historical["withdrawn"] = "2026-06-15T00:00:00Z"
        historical["modified"] = historical["withdrawn"]
        target = advisory("2355", "2026-07-15T00:00:00Z")
        target["withdrawn"] = "2026-08-15T00:00:00Z"
        target["modified"] = target["withdrawn"]
        values = derive_features("test-package", self.snapshot([historical]), self.outcome([target]), CUTOFF)
        self.assertEqual(values["ghsa_high_count"], 0)
        self.assertEqual(values["target_ghsa_high_count_90d"], 0)

    def test_later_withdrawal_does_not_erase_historical_count(self):
        before, after = advisory(), advisory()
        after["withdrawn"] = "2026-08-01T00:00:00Z"
        after["modified"] = after["withdrawn"]
        values = derive_features("test-package", self.snapshot([before]), self.outcome([after]), CUTOFF)
        self.assertEqual(values["ghsa_high_count"], 1)

    def test_all_recognized_severities_and_unknown(self):
        for raw, expected in [("LOW", "low"), ("MODERATE", "moderate"), ("HIGH", "high"), ("CRITICAL", "critical"), (None, "unknown"), ("MEDIUM", "unknown"), (7, "unknown")]:
            self.assertEqual(severity_category(raw), expected)

    def test_revised_publication_does_not_make_known_id_new(self):
        before = advisory(package="other-package")
        after = advisory(published="2026-08-01T00:00:00Z")
        values = derive_features("test-package", self.snapshot([before]), self.outcome([after]), CUTOFF)
        self.assertEqual(values["target_ghsa_high_count_90d"], 0)

    def test_package_wide_not_exact_version_matching(self):
        record = advisory(suffix="2355", published="2026-08-01T00:00:00Z")
        record["affected"][0]["versions"] = ["99.0.0"]
        values = derive_features("test-package", self.snapshot([advisory(package="other")]), self.outcome([record]), CUTOFF)
        self.assertEqual(values["target_ghsa_high_count_90d"], 1)

    def test_modified_before_publication_is_a_preserved_source_warning(self):
        record = advisory(published="2026-06-10T00:00:00Z")
        record["modified"] = "2026-06-09T00:00:00Z"
        history = self.snapshot([record])
        values = derive_features("test-package", history, self.outcome([record]), CUTOFF)
        self.assertEqual(values["ghsa_high_count"], 1)
        self.assertEqual(values["ghsa_high_count_M0"], 1)
        self.assertTrue(any("precedes published" in warning for warning in history.warnings))
        self.assertEqual(history.raw_records()[0]["document"]["modified"], record["modified"])

    def test_rejected_record_is_retained_for_independent_audit(self):
        record = advisory()
        record["modified"] = "2026-08-01T00:00:00Z"
        history = self.snapshot([record])
        self.assertEqual(history.raw_records()[0]["document"], record)
        with self.assertRaises(HistoricalEvidenceError):
            history.require_package("test-package")

    def test_export_omits_narrative_but_preserves_measurements_and_source_hash(self):
        import hashlib
        record = advisory()
        record["details"] = "An unrelated signed URL would be narrative, not a measurement."
        expected = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        history = self.snapshot([record])
        exported = history.raw_records()[0]
        self.assertNotIn("details", exported["document"])
        self.assertEqual(exported["source_document_sha256"], expected)
        self.assertEqual(exported["document"]["affected"], record["affected"])
        self.assertIn("details", record)
        replay = restore_snapshot(history.raw_records(), history.provenance())
        self.assertEqual(replay.raw_records()[0]["source_document_sha256"], expected)

    def test_unknown_package_fails_instead_of_zero(self):
        with self.assertRaises(HistoricalEvidenceError):
            self.snapshot([advisory()]).require_package("unscanned")

    def test_empty_archive_fails(self):
        with self.assertRaises(HistoricalEvidenceError):
            self.snapshot([])

    def test_wrong_archive_commit_root_fails(self):
        with self.assertRaises(HistoricalEvidenceError):
            self.snapshot([advisory()], prefix="advisory-database-" + OUTCOME_SHA)

    def test_malformed_mapping_prevents_false_complete_scan(self):
        record = advisory(package="unselected")
        record["affected"] = "broken"
        with self.assertRaises(HistoricalEvidenceError):
            self.snapshot([record])

    def test_missing_publication_blocks_selected_package(self):
        record = advisory()
        del record["published"]
        with self.assertRaises(HistoricalEvidenceError):
            self.snapshot([record]).require_package("test-package")

    def test_replay_reproduces_counts_and_inventory(self):
        history = self.snapshot([advisory(), advisory("2346", package="unselected")])
        outcome = self.outcome([advisory("2355", "2026-08-01T00:00:00Z")])
        restored_history = restore_snapshot(history.raw_records(), history.provenance())
        restored_outcome = restore_snapshot(outcome.raw_records(), outcome.provenance())
        self.assertEqual(restored_history.all_ghsa_ids, history.all_ghsa_ids)
        self.assertEqual(derive_features("test-package", restored_history, restored_outcome, CUTOFF), derive_features("test-package", history, outcome, CUTOFF))

    def test_zero_advisory_selection_replays_with_complete_scan_evidence(self):
        history = self.snapshot([advisory(package="unselected")])
        restored = restore_snapshot(history.raw_records(), history.provenance())
        self.assertEqual(restored.advisories, {})
        restored.require_package("test-package")
        bad = history.provenance()
        bad["reviewed_files_scanned"] = 0
        with self.assertRaises(HistoricalEvidenceError):
            restore_snapshot([], bad)

    def test_wrong_outcome_boundary_rejected(self):
        with self.assertRaises(HistoricalEvidenceError):
            derive_features("test-package", self.snapshot([advisory()]), self.snapshot([advisory()]), CUTOFF)


if __name__ == "__main__":
    unittest.main()
