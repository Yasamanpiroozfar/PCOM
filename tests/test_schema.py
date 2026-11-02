"""Independent expected contract values transcribed from the course workbook."""
import unittest

from pcom01.schema import (COLUMNS, REQUIRED_COLUMNS, OPTIONAL_COLUMNS, MONTHS,
                           MONTH_WINDOWS, CONTRACT, blank_record)


class SchemaTests(unittest.TestCase):
    def test_exact_names_and_order_from_workbook(self):
        base = ["purl", "package_created_at", "published_at", "unpacked_size", "file_count",
                "dependency_count", "optional_dependency_count", "peer_dependency_count",
                "dev_dependency_count", "bundled_dependency_count"]
        optional_families = ["package_downloads", "package_download_days_observed",
                             "package_stable_release_count", "issues_opened", "issues_closed",
                             "issues_reopened", "pull_requests_opened", "pull_requests_closed_unmerged",
                             "pull_requests_merged", "pull_requests_reopened", "issues_open_at_month_end",
                             "pull_requests_open_at_month_end"]
        severity = ["low", "moderate", "high", "critical", "unknown"]
        expected = (base + [f"{family}_M{i}" for family in optional_families for i in range(12)]
                    + [f"ghsa_{s}_count" for s in severity]
                    + [f"ghsa_{s}_count_M{i}" for s in severity for i in range(12)]
                    + [f"target_ghsa_{s}_count_90d" for s in severity])
        self.assertEqual(tuple(expected), COLUMNS)
        self.assertEqual(len(set(COLUMNS)), 224)
        self.assertEqual(len(REQUIRED_COLUMNS), 78)
        self.assertEqual(len(OPTIONAL_COLUMNS), 146)
        self.assertIn("target_ghsa_unknown_count_90d", REQUIRED_COLUMNS)
        self.assertIn("package_downloads_M11", OPTIONAL_COLUMNS)
        self.assertNotIn("collected_at", COLUMNS)

    def test_month_direction_and_calendar_boundaries(self):
        self.assertEqual(list(MONTHS.values()), ["2026-06", "2026-05", "2026-04", "2026-03",
                                               "2026-02", "2026-01", "2025-12", "2025-11",
                                               "2025-10", "2025-09", "2025-08", "2025-07"])
        self.assertEqual(MONTH_WINDOWS["M11"][0].isoformat(), "2025-07-01T00:00:00+00:00")
        self.assertEqual(MONTH_WINDOWS["M0"][1].isoformat(), "2026-07-01T00:00:00+00:00")
        self.assertEqual((MONTH_WINDOWS["M4"][1] - MONTH_WINDOWS["M4"][0]).days, 28)
        for i in range(11):
            self.assertEqual(MONTH_WINDOWS[f"M{i+1}"][1], MONTH_WINDOWS[f"M{i}"][0])

    def test_initial_values_are_unknown_not_fabricated_zero(self):
        row = blank_record()
        self.assertEqual(tuple(row), COLUMNS)
        self.assertTrue(all(value is None for value in row.values()))
        self.assertEqual(CONTRACT["source_sha256"],
                         "243a32bcd9e9b6d23cbde133a790f8e81ef518ece6e1e408adbb39815f033413")


if __name__ == "__main__":
    unittest.main()
