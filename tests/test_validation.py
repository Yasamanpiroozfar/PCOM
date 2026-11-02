"""Explicit expected positive, negative, and boundary cases; fixtures are synthetic."""
from datetime import datetime, timezone
import unittest

from pcom01.schema import blank_record, REQUIRED_COLUMNS
from pcom01.validation import parse_npm_purl, parse_timestamp, validate_record, validate_dataset


def fixture():
    row = blank_record()
    for name in REQUIRED_COLUMNS:
        row[name] = 0
    row.update(purl="pkg:npm/example@1.2.3",
               package_created_at="2020-01-01T00:00:00.000Z",
               published_at="2026-04-08T18:39:24.455Z")
    return row


class ValidationTests(unittest.TestCase):
    def test_complete_required_core_and_null_optional_valid(self):
        self.assertEqual(validate_record(fixture(), prediction_at="2026-07-01T00:00:00.000Z"), [])

    def test_missing_extra_and_reordered_columns(self):
        missing = fixture()
        missing.pop("ghsa_low_count")
        self.assertTrue(any("missing columns" in e for e in validate_record(missing)))
        extra = fixture()
        extra["extra"] = 0
        self.assertTrue(any("unexpected columns" in e for e in validate_record(extra)))
        reordered = dict(reversed(list(fixture().items())))
        self.assertIn("column order differs from official expanded schema", validate_record(reordered))

    def test_required_missing_and_optional_null(self):
        row = fixture()
        row["dependency_count"] = None
        self.assertIn("dependency_count: required value is missing", validate_record(row))
        row = fixture()
        row["unpacked_size"] = ""
        self.assertTrue(any("unpacked_size" in e for e in validate_record(row)))

    def test_integer_type_and_signed64_boundaries(self):
        for value in (False, True, "1", 1.0, -1, 2**63):
            with self.subTest(value=value):
                row = fixture()
                row["dependency_count"] = value
                self.assertTrue(any("dependency_count" in e for e in validate_record(row)))
        row = fixture()
        row["dependency_count"] = 2**63 - 1
        self.assertEqual(validate_record(row), [])

    def test_timestamp_invalid_dates_precision_and_offsets(self):
        invalid = ["2026-02-30T00:00:00.000Z", "2026-01-01", "2026-01-01T00:00:00Z",
                   "2026-01-01T00:00:00.00Z", "2026-01-01T00:00:00.0000Z",
                   "2026-01-01T00:00:00.000+00:00", "2026-01-01T24:00:00.000Z"]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_timestamp(value)
        self.assertEqual(parse_timestamp("2024-02-29T00:00:00.000Z").year, 2024)

    def test_example_creation_after_publication_rejected(self):
        row = fixture()
        row["package_created_at"] = "2026-07-01T00:00:00.000Z"
        self.assertIn("package_created_at must not be after published_at", validate_record(row))

    def test_purl_scopes_build_metadata_and_invalid_identities(self):
        self.assertEqual(parse_npm_purl("pkg:npm/%40scope/name@1.2.3%2Bbuild.7"),
                         ("@scope/name", "1.2.3+build.7"))
        invalid = ["pkg:maven/example@1.2.3", "pkg:npm/example", "pkg:npm/example@latest",
                   "pkg:npm/example@%5E1.2.3", "pkg:npm/example@1.2.3-rc.1",
                   "pkg:npm/example@01.2.3", "pkg:npm/example@1.2", "pkg:npm/example@v1.2.3",
                   "pkg:npm/@scope/name@1.2.3", "pkg:npm/%40scope/name@1.2.3+build",
                   "pkg:npm/example@1.2.3?x=y", "pkg:npm/example@1.2.3#path",
                   "pkg:npm/%40scope/sub/name@1.2.3", "pkg:npm/a%ZZ@1.2.3"]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_npm_purl(value)

    def test_duplicate_and_empty_datasets_rejected(self):
        report = validate_dataset([fixture(), fixture()])
        self.assertFalse(report["valid"])
        self.assertTrue(any("duplicate purl" in e["error"] for e in report["errors"]))
        self.assertFalse(validate_dataset([])["valid"])
        self.assertTrue(validate_dataset([fixture()])["valid"])

    def test_prediction_boundary_and_no_future_months(self):
        row = fixture()
        row["published_at"] = "2026-07-01T00:00:00.000Z"
        self.assertTrue(any("published_at must precede" in e for e in
                            validate_record(row, prediction_at="2026-07-01T00:00:00.000Z")))
        self.assertTrue(any("temporal leakage" in e for e in
                            validate_record(fixture(), prediction_at="2026-06-15T00:00:00.000Z")))
        self.assertTrue(validate_record(fixture(), prediction_at=datetime(2026, 7, 1)))
        self.assertEqual(validate_record(fixture(), prediction_at=datetime(2026, 7, 1, tzinfo=timezone.utc)), [])

    def test_monthly_ghsa_cannot_exceed_lifetime(self):
        row = fixture()
        row["ghsa_unknown_count_M11"] = 1
        self.assertTrue(any("12-month sum exceeds" in e for e in validate_record(row)))
        row["ghsa_unknown_count"] = 2
        self.assertEqual(validate_record(row), [])

    def test_download_coverage_boundaries_and_zero_observations(self):
        row = fixture()
        row["package_downloads_M4"] = 0
        row["package_download_days_observed_M4"] = 28
        self.assertEqual(validate_record(row), [])
        row["package_download_days_observed_M4"] = 29
        self.assertTrue(any("outside [0, 28]" in e for e in validate_record(row)))
        row["package_download_days_observed_M4"] = 0
        row["package_downloads_M4"] = 3
        self.assertTrue(any("zero observed days" in e for e in validate_record(row)))

    def test_coverage_reports_nulls_separately_from_zero(self):
        report = validate_dataset([fixture()])
        self.assertEqual(report["required_coverage"]["ghsa_unknown_count"], 1)
        self.assertEqual(report["optional_coverage"]["issues_opened_M0"], 0)
        self.assertEqual(report["row_count"], 1)


if __name__ == "__main__":
    unittest.main()
