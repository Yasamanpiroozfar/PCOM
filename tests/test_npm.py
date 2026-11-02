"""Synthetic unit fixtures: these are never included in the acquired dataset."""

import copy
import unittest

from pcom01.npm import (
    MetadataError, count_dependencies, exact_purl, format_timestamp,
    parse_timestamp, stable_semver_key, transform,
)


def fixture():
    timestamps = {
        "created": "2020-01-01T00:00:00.000Z",
        "1.0.0": "2025-06-30T23:59:59.999Z",
        "2.0.0": "2025-07-01T00:00:00.000Z",
        "2.1.0": "2026-06-30T23:59:59.999Z",
        "3.0.0": "2026-07-01T00:00:00.000Z",
        "4.0.0-beta.1": "2026-01-01T00:00:00.000Z",
    }
    return {
        "name": "sample",
        "time": timestamps,
        "dist-tags": {"latest": "3.0.0"},
        "versions": {version: {"name": "sample", "version": version}
                     for version in timestamps if version != "created"},
    }


class SemverTests(unittest.TestCase):
    def test_numeric_precedence_not_lexical(self):
        self.assertGreater(stable_semver_key("2.10.0"), stable_semver_key("2.9.9"))

    def test_build_metadata_ignored(self):
        self.assertEqual(stable_semver_key("1.2.3+001"), stable_semver_key("1.2.3+zzz"))

    def test_invalid_and_prerelease_versions(self):
        for version in ["1.2", "v1.2.3", "01.2.3", "1.2.3-alpha", "1.2.3-01", "1.2.3+", "1.2.3+bad..build", None]:
            with self.subTest(version=version), self.assertRaises(MetadataError):
                stable_semver_key(version)

    def test_purls(self):
        self.assertEqual(exact_purl("express", "4.21.0"), "pkg:npm/express@4.21.0")
        self.assertEqual(exact_purl("@scope/pkg", "1.0.0+build.1"), "pkg:npm/%40scope/pkg@1.0.0%2Bbuild.1")
        for name in ["https://npmjs.com/pkg", "@scope", "a/b", "bad name", "../bad", "MixedCase"]:
            with self.subTest(name=name), self.assertRaises(MetadataError):
                exact_purl(name, "1.0.0")


class DependencyTests(unittest.TestCase):
    def test_absent_maps_are_verified_empty_in_full_manifest(self):
        self.assertEqual(count_dependencies({}), {
            "dependency_count": 0, "optional_dependency_count": 0,
            "peer_dependency_count": 0, "dev_dependency_count": 0,
            "bundled_dependency_count": 0,
        })

    def test_independent_maps_and_optional_peers(self):
        result = count_dependencies({
            "dependencies": {"a": "1", "b": "2"},
            "optionalDependencies": {"a": "1"},
            "peerDependencies": {"p": "*", "q": "*"},
            "peerDependenciesMeta": {"q": {"optional": True}},
            "devDependencies": {"d": "*"},
            "bundleDependencies": ["a", "b", "a"],
        })
        self.assertEqual(list(result.values()), [2, 1, 2, 1, 2])

    def test_bundling_alias_and_boolean(self):
        manifest = {"dependencies": {"a": "1"}, "optionalDependencies": {"a": "1", "b": "2"}}
        self.assertEqual(count_dependencies({**manifest, "bundledDependencies": True})["bundled_dependency_count"], 2)
        self.assertEqual(count_dependencies({**manifest, "bundleDependencies": False})["bundled_dependency_count"], 0)
        self.assertEqual(count_dependencies({**manifest, "bundledDependencies": ["a", "a"]})["bundled_dependency_count"], 1)

    def test_equivalent_alias_lists(self):
        result = count_dependencies({"bundleDependencies": ["a", "b"], "bundledDependencies": ["b", "a", "a"]})
        self.assertEqual(result["bundled_dependency_count"], 2)

    def test_conflicting_aliases_rejected(self):
        with self.assertRaises(MetadataError):
            count_dependencies({"bundleDependencies": ["a"], "bundledDependencies": ["b"]})

    def test_malformed_maps_not_zero(self):
        for value in [None, [], "a", False]:
            with self.subTest(value=value), self.assertRaises(MetadataError):
                count_dependencies({"dependencies": value})
        for value in [None, "a", {}, ["a", 4]]:
            with self.subTest(value=value), self.assertRaises(MetadataError):
                count_dependencies({"bundleDependencies": value})


class TimestampTests(unittest.TestCase):
    def test_normalize_timezone_and_milliseconds(self):
        self.assertEqual(format_timestamp(parse_timestamp("2026-06-30T23:00:00+02:00")), "2026-06-30T21:00:00.000Z")
        self.assertEqual(format_timestamp(parse_timestamp("2026-06-30T23:00:00.123456Z")), "2026-06-30T23:00:00.123Z")

    def test_invalid_calendar_and_no_timezone(self):
        for value in ["2026-02-30T00:00:00Z", "2026-01-01", "2026-01-01T00:00:00", None, "2026-01-01T00:00:60Z"]:
            with self.subTest(value=value), self.assertRaises(MetadataError):
                parse_timestamp(value)


class TransformationTests(unittest.TestCase):
    def test_window_boundaries_and_month_mapping(self):
        result = transform(fixture(), "sample")
        self.assertEqual([row["purl"] for row in result["records"]], ["pkg:npm/sample@2.0.0", "pkg:npm/sample@2.1.0"])
        row = result["records"][0]
        self.assertEqual(row["package_stable_release_count_M11"], 1)
        self.assertEqual(row["package_stable_release_count_M0"], 1)
        self.assertEqual(row["package_stable_release_count_M1"], 0)
        self.assertIsNone(row["unpacked_size"])
        self.assertIsNone(row["file_count"])
        self.assertEqual(result["latest_semver"], "2.1.0")

    def test_highest_semver_not_publication_timestamp_or_dist_tag(self):
        data = fixture()
        data["versions"]["1.9.9"] = {"name": "sample", "version": "1.9.9"}
        data["time"]["1.9.9"] = "2026-06-30T23:59:59.999Z"
        data["time"]["2.1.0"] = "2025-12-01T00:00:00Z"
        self.assertEqual(transform(data, "sample")["latest_semver"], "2.1.0")

    def test_build_metadata_ties_are_reported(self):
        data = fixture()
        for version in ["2.2.0+z", "2.2.0+a"]:
            data["versions"][version] = {"name": "sample", "version": version}
            data["time"][version] = "2026-01-01T00:00:00Z"
        result = transform(data, "sample")
        self.assertEqual(result["latest_semver_candidates"], ["2.2.0+a", "2.2.0+z"])
        self.assertIn("highest_semver_build_metadata_tie", [item["reason"] for item in result["warnings"]])

    def test_null_dependency_excludes_record(self):
        data = fixture()
        data["versions"]["2.0.0"]["dependencies"] = None
        result = transform(data, "sample")
        self.assertEqual(len(result["records"]), 1)
        self.assertIn({"version": "2.0.0", "reason": "invalid_manifest", "detail": "dependencies is present but is not a dependency map"}, result["excluded"])

    def test_chronological_inconsistency_excludes_record(self):
        data = fixture()
        data["time"]["2.0.0"] = "2019-01-01T00:00:00Z"
        result = transform(data, "sample")
        self.assertEqual(len(result["records"]), 1)
        self.assertIsNone(result["records"][0]["package_stable_release_count_M11"])

    def test_missing_timestamp_does_not_create_false_zero_counts(self):
        data = fixture()
        del data["time"]["2.0.0"]
        result = transform(data, "sample")
        self.assertEqual(len(result["records"]), 1)
        self.assertFalse(result["statistics"]["stable_release_counts_complete_for_returned_metadata"])
        self.assertFalse(result["latest_semver_verified_for_returned_metadata"])
        self.assertIsNone(result["records"][0]["package_stable_release_count_M11"])

    def test_timestamp_only_release_counted_but_no_fabricated_record(self):
        data = fixture()
        del data["versions"]["2.0.0"]
        result = transform(data, "sample")
        self.assertEqual(len(result["records"]), 1)
        self.assertEqual(result["records"][0]["package_stable_release_count_M11"], 1)
        self.assertIn({"version": "2.0.0", "reason": "timestamp_without_version_manifest"}, result["excluded"])

    def test_identity_mismatch_and_abbreviated_document(self):
        data = fixture()
        with self.assertRaises(MetadataError):
            transform(data, "another")
        del data["time"]
        with self.assertRaises(MetadataError):
            transform(data, "sample")
        data = fixture()
        data["versions"]["2.0.0"]["version"] = "2.0.1"
        self.assertEqual(len(transform(data, "sample")["records"]), 1)

    def test_optional_invalid_not_coerced(self):
        data = fixture()
        data["versions"]["2.0.0"]["dist"] = {"unpackedSize": False, "fileCount": -1}
        result = transform(data, "sample")
        self.assertIsNone(result["records"][0]["unpacked_size"])
        self.assertIsNone(result["records"][0]["file_count"])
        self.assertEqual(len(result["warnings"]), 2)

    def test_malformed_registry_map_key_is_reported(self):
        data = fixture()
        data["versions"][42] = {}
        with self.assertRaises(MetadataError):
            transform(data, "sample")

    def test_zero_is_preserved_for_observed_optional_metadata(self):
        data = fixture()
        data["versions"]["2.0.0"]["dist"] = {"unpackedSize": 0, "fileCount": 0}
        row = transform(data, "sample")["records"][0]
        self.assertEqual(row["unpacked_size"], 0)
        self.assertEqual(row["file_count"], 0)

    def test_determinism_and_no_source_mutation(self):
        data = fixture()
        original = copy.deepcopy(data)
        self.assertEqual(transform(data, "sample"), transform(data, "sample"))
        self.assertEqual(data, original)

    def test_reject_wrong_history_length(self):
        with self.assertRaises(MetadataError):
            transform(fixture(), "sample", history_start="2025-01-01T00:00:00Z")


if __name__ == "__main__":
    unittest.main()
