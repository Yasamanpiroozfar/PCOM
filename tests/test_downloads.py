"""Hand-computed synthetic daily observations, separate from acquired data."""

import unittest

from pcom01.downloads import monthly_downloads


def payload(*observations):
    return {"package": "sample", "downloads": [{"day": day, "downloads": count} for day, count in observations]}


class DownloadsTests(unittest.TestCase):
    def test_known_sums_month_mapping_and_zero_observed_day(self):
        result = monthly_downloads(payload(("2025-07-01", 3), ("2025-07-02", 4), ("2026-06-01", 0), ("2026-06-30", 5)), "sample")
        self.assertEqual(result["package_downloads_M11"], 7)
        self.assertEqual(result["package_download_days_observed_M11"], 2)
        self.assertEqual(result["package_downloads_M0"], 5)
        self.assertEqual(result["package_download_days_observed_M0"], 2)
        self.assertEqual(result["package_download_days_observed_M1"], 0)
        self.assertIsNone(result["package_downloads_M1"])
        self.assertEqual(len(result), 24)

    def test_reported_zero_is_not_missing(self):
        result = monthly_downloads(payload(("2026-06-03", 0)), "sample")
        self.assertEqual(result["package_downloads_M0"], 0)
        self.assertEqual(result["package_download_days_observed_M0"], 1)

    def test_empty_response_has_known_zero_coverage_and_unknown_totals(self):
        result = monthly_downloads(payload(), "sample")
        for index in range(12):
            self.assertEqual(result[f"package_download_days_observed_M{index}"], 0)
            self.assertIsNone(result[f"package_downloads_M{index}"])

    def test_duplicate_days_rejected_even_identical(self):
        for second in [1, 2]:
            with self.subTest(second=second), self.assertRaisesRegex(ValueError, "duplicate"):
                monthly_downloads(payload(("2026-06-03", 1), ("2026-06-03", second)), "sample")

    def test_outside_input_window_rejected(self):
        for day in ["2025-06-30", "2026-07-01"]:
            with self.subTest(day=day), self.assertRaisesRegex(ValueError, "out-of-window"):
                monthly_downloads(payload((day, 1)), "sample")

    def test_invalid_dates_rejected(self):
        for day in ["2026-02-30", "2026-6-3", "20260603", None]:
            with self.subTest(day=day), self.assertRaises(ValueError):
                monthly_downloads(payload((day, 1)), "sample")

    def test_invalid_count_types_rejected(self):
        for count in [-1, None, True, False, "1", 1.0]:
            with self.subTest(count=count), self.assertRaises(ValueError):
                monthly_downloads(payload(("2026-06-03", count)), "sample")

    def test_int64_overflow_rejected(self):
        with self.assertRaises(ValueError):
            monthly_downloads(payload(("2026-06-03", 2**63)), "sample")
        with self.assertRaises(ValueError):
            monthly_downloads(payload(("2026-06-03", 2**63-1), ("2026-06-04", 1)), "sample")

    def test_package_mismatch_and_missing_array(self):
        for value in [{"package": "another", "downloads": []}, {"package": "sample"}, None]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                monthly_downloads(value, "sample")

    def test_malformed_observation(self):
        with self.assertRaises(ValueError):
            monthly_downloads({"package": "sample", "downloads": [None]}, "sample")


if __name__ == "__main__":
    unittest.main()
