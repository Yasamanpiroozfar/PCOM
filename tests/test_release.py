"""Release-origin regression tests; all fixtures are synthetic and local only.

These tests exercise the documented primary interpretation and evidence
boundaries. Dataset readiness does not grant permission to publish. Fixed
monthly buckets contain only observations known at the origin.
"""
import copy
import csv
import json
from datetime import timedelta
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pcom01.advisories import HistoricalEvidenceError, _build_snapshot, utc
from pcom01.io import read_json, save_json, sha256
from pcom01.schema import COLUMNS, SCHEMA_PATH, TARGET_COLUMNS


PACKAGE = "release-test-fixture"
ORIGIN = "2026-05-15T12:34:56.789Z"
END = "2026-08-13T12:34:56.789Z"
OLD_ID = "GHSA-2345-2345-2345"
NEW_ID = "GHSA-3456-3456-3456"


def registry_fixture():
    times = {
        "created": "2020-01-01T00:00:00.000Z",
        "1.0.0": "2025-07-15T00:00:00.000Z",
        "2.0.0": ORIGIN,
        # A lower SemVer published later cannot be input at 2.0.0's origin.
        "1.9.0": "2026-06-15T00:00:00.000Z",
        "3.0.0-beta.1": "2026-06-20T00:00:00.000Z",
        "3.0.0": "2026-07-01T00:00:00.000Z",
    }
    return {
        "name": PACKAGE,
        "time": times,
        "dist-tags": {"latest": "3.0.0"},
        "versions": {v: {"name": PACKAGE, "version": v,
                         "dependencies": {"declared-dependency": "^1.0.0"}}
                     for v in times if v != "created"},
    }


def advisory(ghsa_id=OLD_ID, published="2026-04-01T00:00:00.000Z",
             severity="LOW", package=PACKAGE):
    return {
        "id": ghsa_id, "published": published, "modified": published,
        "database_specific": {"github_reviewed": True,
                              "github_reviewed_at": published,
                              "severity": severity},
        "affected": [{"package": {"ecosystem": "npm", "name": package},
                      # Deliberately does not match any input record version:
                      # the course target is package-wide, not version-specific.
                      "versions": ["99.0.0"]}],
    }


def snapshot(documents, boundary, *, sha="a" * 40):
    committed = utc(boundary) - timedelta(seconds=1)
    return _build_snapshot(
        ((f"advisories/github-reviewed/{d['id']}.json", d) for d in documents),
        [PACKAGE], boundary, sha, committed, "b" * 64)


def prepare_sources(root, *, with_snapshots=True):
    """Persist independent source captures with verifiable digests."""
    (root / "schema").mkdir(parents=True, exist_ok=True)
    (root / "schema/record_schema.json").write_bytes(SCHEMA_PATH.read_bytes())
    save_json(root / "config/packages.json", {"packages": [{"name": PACKAGE}]})
    registry_path = root / "data/raw/registry/fixture.json.gz"
    save_json(registry_path, registry_fixture())
    download_path = root / "data/raw/downloads/fixture.json.gz"
    save_json(download_path, {
        "package": PACKAGE,
        "downloads": [
            {"day": "2025-07-01", "downloads": 7},
            {"day": "2026-04-30", "downloads": 11},
            {"day": "2026-05-01", "downloads": 101},
            {"day": "2026-05-14", "downloads": 13},
            {"day": "2026-05-15", "downloads": 999},
            {"day": "2026-05-16", "downloads": 1001},
            {"day": "2026-05-30", "downloads": 10001},
            {"day": "2026-06-30", "downloads": 999999},
        ],
    })
    save_json(root / "data/provenance/acquisition.json", {
        "selection_sha256": sha256(root / "config/packages.json"),
        "input_cutoff_exclusive": "2026-07-01T00:00:00.000Z",
        "outcome_end_exclusive": "2026-09-29T00:00:00.000Z",
        "packages": {PACKAGE: {
            "registry": {"path": registry_path.relative_to(root).as_posix(),
                         "stored_sha256": sha256(registry_path)},
            "downloads": {"path": download_path.relative_to(root).as_posix(),
                          "stored_sha256": sha256(download_path)},
        }},
        "snapshots": {}, "failures": [],
    })
    if with_snapshots:
        snapshots = {}
        old = advisory()
        fresh = advisory(NEW_ID, ORIGIN, "HIGH")
        for i, (boundary, docs) in enumerate(((ORIGIN, [old]), (END, [old, fresh]))):
            snap = snapshot(docs, boundary, sha=str(i + 1) * 40)
            path = root / f"data/raw/release-advisories-{i}.json.gz"
            save_json(path, {"records": snap.raw_records(), "provenance": snap.provenance()})
            snapshots[boundary] = {
                "bundle_path": path.relative_to(root).as_posix(),
                "bundle_sha256": sha256(path), "boundary": boundary,
                "archive_sha256": "b" * 64,
                "commit": {"sha": snap.commit_sha,
                           "committed_at": snap.committed_at.isoformat().replace("+00:00", "Z")},
            }
        save_json(root / "data/provenance/release-acquisition.json", {
            "selection_sha256": sha256(root / "config/packages.json"),
            "original_acquisition_sha256": sha256(root / "data/provenance/acquisition.json"),
            "snapshots": snapshots, "failures": [],
            "requested_sources_complete": True,
            "requested_boundaries": [ORIGIN, END],
            "missing_requested_boundaries": [],
        })


class ReleaseAnchorTests(unittest.TestCase):
    def test_scope_must_be_explicit_and_supported(self):
        from pcom01.release import select_anchor
        with self.assertRaises(TypeError):
            select_anchor(registry_fixture(), PACKAGE)
        with self.assertRaises(ValueError):
            select_anchor(registry_fixture(), PACKAGE, "guess")

    def test_highest_semver_not_timestamp_dist_tag_or_prerelease(self):
        from pcom01.release import select_anchor
        for scope in ("supplied", "all-precutoff"):
            with self.subTest(scope=scope):
                decision = select_anchor(registry_fixture(), PACKAGE, scope)
                self.assertEqual(decision["anchor_version"], "2.0.0")
                self.assertEqual(decision["origin"], ORIGIN)
                self.assertEqual(decision["outcome_end"], END)

    def test_older_higher_semver_changes_origin_only_for_all_pre_cutoff(self):
        from pcom01.release import select_anchor
        data = registry_fixture()
        data["versions"]["18.0.0"] = {"name": PACKAGE, "version": "18.0.0"}
        data["time"]["18.0.0"] = "2025-05-27T14:27:19.495Z"
        data["versions"]["17.7.3"] = {"name": PACKAGE, "version": "17.7.3"}
        data["time"]["17.7.3"] = "2026-06-19T02:08:41.275Z"
        supplied = select_anchor(data, PACKAGE, "supplied")
        all_pre = select_anchor(data, PACKAGE, "all-precutoff")
        self.assertEqual(supplied["anchor_version"], "17.7.3")
        self.assertEqual(supplied["outcome_end"], "2026-09-17T02:08:41.275Z")
        self.assertEqual(all_pre["anchor_version"], "18.0.0")
        self.assertEqual(all_pre["outcome_end"], "2025-08-25T14:27:19.495Z")

    def test_build_metadata_precedence_tie_does_not_choose_lexically(self):
        from pcom01.release import select_anchor
        data = registry_fixture()
        for version in ("4.0.0+first", "4.0.0+second"):
            data["versions"][version] = {"name": PACKAGE, "version": version}
            data["time"][version] = ORIGIN
        decision = select_anchor(data, PACKAGE, "supplied")
        self.assertIsNone(decision["anchor_version"])
        self.assertIsNone(decision["origin"])
        self.assertIn("highest_semver_precedence_tie", decision["blockers"])

    def test_unknown_stable_version_timestamp_cannot_establish_highest(self):
        from pcom01.release import select_anchor
        for bad in (None, "2026-02-30T00:00:00.000Z", "2026-06-01T00:00:00"):
            data = registry_fixture()
            data["versions"]["19.0.0"] = {"name": PACKAGE, "version": "19.0.0"}
            data["time"]["19.0.0"] = bad
            with self.subTest(value=bad):
                decision = select_anchor(data, PACKAGE, "all-precutoff")
                self.assertIsNone(decision["origin"])
                self.assertIn("unknown_stable_release_timestamp", decision["blockers"])

    def test_submillisecond_origin_is_not_silently_shifted(self):
        from pcom01.release import select_anchor
        data = registry_fixture()
        data["time"]["2.0.0"] = "2026-05-15T12:34:56.789123Z"
        decision = select_anchor(data, PACKAGE, "supplied")
        self.assertIsNone(decision["origin"])
        self.assertIn("anchor_timestamp_exceeds_schema_millisecond_precision", decision["blockers"])

    def test_build_metadata_version_has_canonical_supplied_record_identity(self):
        from pcom01.release import select_anchor
        data = registry_fixture()
        data["versions"]["4.0.0+build.1"] = {"name": PACKAGE, "version": "4.0.0+build.1"}
        data["time"]["4.0.0+build.1"] = ORIGIN
        decision = select_anchor(data, PACKAGE, "supplied")
        self.assertEqual(decision["anchor_version"], "4.0.0+build.1")
        self.assertTrue(decision["anchor_in_supplied_records"])

    def test_full_month_coverage_is_available_only_at_its_actual_end(self):
        from pcom01.release import available_months
        just_before = available_months("2026-06-01T00:00:00.000Z")
        self.assertNotIn("M0", just_before)
        self.assertIn("M1", just_before)
        self.assertNotIn("M1", available_months("2026-05-31T23:59:59.999Z"))


class ReleaseAdvisoryTests(unittest.TestCase):
    def features(self, before, after):
        from pcom01.release import release_advisory_features
        return release_advisory_features(
            PACKAGE, snapshot(before, ORIGIN), snapshot(after, END, sha="c" * 40), ORIGIN)

    def test_exact_arbitrary_timestamp_90_day_window_and_package_wide_labels(self):
        old = advisory(package="unrelated-package")
        first = advisory(NEW_ID, ORIGIN, "HIGH")
        last = advisory("GHSA-4567-4567-4567", "2026-08-13T12:34:56.788Z", None)
        values = self.features([old], [old, first, last])
        self.assertEqual(values["target_ghsa_high_count_90d"], 1)
        self.assertEqual(values["target_ghsa_unknown_count_90d"], 1)
        self.assertEqual(set(TARGET_COLUMNS), {key for key in values if key.startswith("target_")})
        self.assertEqual(len(values), 70)
        self.assertEqual(values["ghsa_high_count_M0"], 0)
        self.assertEqual(values["ghsa_high_count_M1"], 0)
        self.assertEqual(values["ghsa_high_count_M2"], 0)

    def test_fixed_month_mapping_does_not_silently_roll_back(self):
        old = advisory()
        values = self.features([old], [old])
        # M2 remains April, even for a May15 release.
        self.assertEqual(values["ghsa_low_count_M2"], 1)
        self.assertEqual(values["ghsa_low_count_M1"], 0)
        self.assertEqual(values["ghsa_low_count_M0"], 0)
        self.assertEqual(values["ghsa_low_count"], 1)

    def test_partial_month_uses_known_ids_and_future_bucket_zero_is_not_future_truth(self):
        old = advisory()
        known_may = advisory("GHSA-4567-4567-4567", "2026-05-14T12:00:00.000Z", "LOW")
        future_june = advisory(NEW_ID, "2026-06-01T00:00:00.000Z", "HIGH")
        values = self.features([old, known_may], [old, known_may, future_june])
        self.assertEqual(values["ghsa_low_count"], 2)
        self.assertEqual(values["ghsa_low_count_M1"], 1)
        self.assertEqual(values["ghsa_low_count_M2"], 1)
        # Zero measures origin-known June IDs, while the actual future count
        # is nonzero. The outcome tree must not change the input measurement.
        self.assertEqual(values["ghsa_high_count_M0"], 0)
        self.assertEqual(values["target_ghsa_high_count_90d"], 1)

    def test_end_timestamp_and_future_snapshot_are_rejected_not_counted_zero(self):
        from pcom01.release import release_advisory_features
        old = advisory()
        for after in ([old, advisory(NEW_ID, END)],):
            with self.assertRaises(HistoricalEvidenceError):
                self.features([old], after)
        before = snapshot([old], ORIGIN)
        before.committed_at = utc(ORIGIN)
        with self.assertRaises(HistoricalEvidenceError):
            release_advisory_features(PACKAGE, before, snapshot([old], END), ORIGIN)

    def test_wrong_boundary_and_unscanned_package_do_not_produce_zero(self):
        from pcom01.release import release_advisory_features
        old = advisory()
        wrong_end = snapshot([old], "2026-08-14T12:34:56.789Z")
        with self.assertRaises(HistoricalEvidenceError):
            release_advisory_features(PACKAGE, snapshot([old], ORIGIN), wrong_end, ORIGIN)
        with self.assertRaises(HistoricalEvidenceError):
            release_advisory_features("not-scanned", snapshot([old], ORIGIN), snapshot([old], END), ORIGIN)

    def test_outcome_revision_cannot_change_historical_severity(self):
        before = advisory(severity="LOW")
        revised = copy.deepcopy(before)
        revised["database_specific"]["severity"] = "CRITICAL"
        revised["modified"] = "2026-06-01T00:00:00.000Z"
        values = self.features([before], [revised])
        self.assertEqual(values["ghsa_low_count"], 1)
        self.assertEqual(values["ghsa_critical_count"], 0)
        self.assertEqual(values["target_ghsa_critical_count_90d"], 0)

    def test_new_mapping_or_revised_publication_cannot_make_known_id_new(self):
        before = advisory(package="unrelated-package")
        revised = advisory(published="2026-06-01T00:00:00.000Z", severity="CRITICAL")
        values = self.features([before], [revised])
        self.assertEqual(values["ghsa_critical_count"], 0)
        self.assertEqual(values["target_ghsa_critical_count_90d"], 0)

    def test_later_withdrawal_does_not_erase_historical_observation(self):
        before = advisory()
        after = copy.deepcopy(before)
        after["withdrawn"] = "2026-06-01T00:00:00.000Z"
        after["modified"] = after["withdrawn"]
        values = self.features([before], [after])
        self.assertEqual(values["ghsa_low_count"], 1)
        self.assertEqual(values["target_ghsa_low_count_90d"], 0)


class ReleaseObservationTests(unittest.TestCase):
    def test_downloads_keep_only_whole_utc_days_ended_by_origin(self):
        from pcom01.release import release_downloads
        payload = {"package": PACKAGE, "downloads": [
            {"day": "2026-05-14", "downloads": 13},
            {"day": "2026-05-15", "downloads": 999},
            {"day": "2026-06-01", "downloads": 999999},
        ]}
        for origin in (ORIGIN, "2026-05-15T00:00:00.000Z"):
            with self.subTest(origin=origin):
                values = release_downloads(payload, PACKAGE, origin)
                self.assertEqual(values["package_downloads_M1"], 13)
                self.assertEqual(values["package_download_days_observed_M1"], 1)
                self.assertIsNone(values["package_downloads_M0"])
                self.assertEqual(values["package_download_days_observed_M0"], 0)
        before_day_end = release_downloads(payload, PACKAGE, "2026-05-14T23:59:59.999Z")
        self.assertIsNone(before_day_end["package_downloads_M1"])
        self.assertEqual(before_day_end["package_download_days_observed_M1"], 0)

    def test_observed_zero_downloads_differ_from_unobserved_future_total(self):
        from pcom01.release import release_downloads
        values = release_downloads({"package": PACKAGE, "downloads": [
            {"day": "2026-05-01", "downloads": 0}]}, PACKAGE, ORIGIN)
        self.assertEqual(values["package_downloads_M1"], 0)
        self.assertEqual(values["package_download_days_observed_M1"], 1)
        self.assertIsNone(values["package_downloads_M0"])
        self.assertEqual(values["package_download_days_observed_M0"], 0)

    def test_bad_download_source_does_not_become_verified_zero_after_filtering(self):
        from pcom01.release import release_downloads
        for payload in ({"package": PACKAGE}, {"package": PACKAGE, "downloads": [
            {"day": "2026-06-01", "downloads": "invalid"}]}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                release_downloads(payload, PACKAGE, ORIGIN)

    def test_stable_counts_include_anchor_and_exclude_fractionally_later_versions(self):
        from pcom01.release import release_counts
        data = registry_fixture()
        data["versions"]["1.8.0"] = {"name": PACKAGE, "version": "1.8.0"}
        data["time"]["1.8.0"] = "2026-05-15T12:34:56.788999Z"
        data["time"]["1.9.0"] = "2026-05-15T12:34:56.789100Z"
        values = release_counts(data, ORIGIN)
        self.assertEqual(values["package_stable_release_count_M1"], 2)
        self.assertEqual(values["package_stable_release_count_M0"], 0)
        self.assertEqual(values["package_stable_release_count_M11"], 1)

    def test_unknown_stable_timestamp_keeps_release_counts_unknown(self):
        from pcom01.release import release_counts
        data = registry_fixture()
        data["time"]["1.9.0"] = None
        self.assertTrue(all(value is None for value in release_counts(data, ORIGIN).values()))


class ReleasePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def build(self, **kwargs):
        from pcom01.release import build_release
        return build_release(self.root, "supplied", **kwargs)

    def rows(self, output=None):
        directory = output or self.root / "data/corrections/supplied"
        return [json.loads(line) for line in (directory / "candidate-records.jsonl").read_text().splitlines()]

    def bind_original(self, original):
        path = self.root / "data/provenance/acquisition.json"
        save_json(path, original)
        release_path = self.root / "data/provenance/release-acquisition.json"
        release = read_json(release_path)
        release["selection_sha256"] = original["selection_sha256"]
        release["original_acquisition_sha256"] = sha256(path)
        save_json(release_path, release)

    def test_later_version_excluded_anchor_included_without_changing_months(self):
        prepare_sources(self.root)
        report = self.build()
        rows = self.rows()
        self.assertEqual([row["purl"] for row in rows], [
            f"pkg:npm/{PACKAGE}@1.0.0", f"pkg:npm/{PACKAGE}@2.0.0"])
        self.assertEqual(report["source_verified_ghsa_packages"], 1)
        for row in rows:
            self.assertEqual(tuple(row), COLUMNS)
            self.assertEqual(row["package_downloads_M2"], 11)
            self.assertEqual(row["package_download_days_observed_M2"], 1)
            self.assertEqual(row["package_stable_release_count_M11"], 1)
            self.assertEqual(row["package_stable_release_count_M1"], 1)
            self.assertEqual(row["package_stable_release_count_M0"], 0)
            self.assertEqual(row["package_downloads_M1"], 114)
            self.assertEqual(row["package_download_days_observed_M1"], 2)
            self.assertIsNone(row["package_downloads_M0"])
            self.assertEqual(row["package_download_days_observed_M0"], 0)
            self.assertEqual(row["ghsa_low_count_M2"], 1)
            self.assertEqual(row["ghsa_low_count_M1"], 0)
            self.assertEqual(row["ghsa_low_count_M0"], 0)
            self.assertEqual(row["target_ghsa_high_count_90d"], 1)
            # No complete historical issue/PR source was captured.
            self.assertIsNone(row["issues_opened_M1"])
            self.assertIsNone(row["issues_opened_M0"])
        exclusions = read_json(self.root / "data/corrections/supplied/exclusions.json")
        later = [item for item in exclusions if item["reason"] == "version_published_after_release_origin"]
        self.assertEqual([item["purl"] for item in later], [f"pkg:npm/{PACKAGE}@1.9.0"])

    def test_later_version_with_same_formatted_millisecond_cannot_leak(self):
        prepare_sources(self.root)
        registry_path = self.root / "data/raw/registry/fixture.json.gz"
        data = read_json(registry_path)
        data["time"]["1.9.0"] = "2026-05-15T12:34:56.789100Z"
        save_json(registry_path, data)
        original_path = self.root / "data/provenance/acquisition.json"
        original = read_json(original_path)
        original["packages"][PACKAGE]["registry"]["stored_sha256"] = sha256(registry_path)
        save_json(original_path, original)
        release_path = self.root / "data/provenance/release-acquisition.json"
        acquired = read_json(release_path)
        acquired["original_acquisition_sha256"] = sha256(original_path)
        save_json(release_path, acquired)
        self.build()
        self.assertEqual([row["purl"] for row in self.rows()], [
            f"pkg:npm/{PACKAGE}@1.0.0", f"pkg:npm/{PACKAGE}@2.0.0"])
        self.assertTrue(all(row["package_stable_release_count_M1"] == 1 for row in self.rows()))
        decisions = read_json(self.root / "data/corrections/supplied/package-decisions.json")
        self.assertEqual(decisions[PACKAGE]["records_after_origin"], [f"pkg:npm/{PACKAGE}@1.9.0"])

    def test_valid_primary_is_ready_without_claiming_official_endorsement_or_publication_permission(self):
        prepare_sources(self.root)
        report = self.build()
        self.assertEqual(report["schema_columns"], 224)
        self.assertEqual(report["candidate_records"], 2)
        self.assertEqual(report["official_training_records"], 0)
        self.assertEqual(report["role"], "primary_corrected")
        self.assertEqual(report["eligible_records"], 2)
        self.assertEqual(report["corrected_training_records"], 2)
        self.assertEqual(report["structurally_valid_candidates"], 2)
        self.assertFalse(report["all_candidates_quarantined"])
        self.assertTrue(report["ready_for_submission"])
        self.assertFalse(report["publication_permitted"])
        output = self.root / "data/corrections/supplied"
        self.assertFalse((output / "training.csv").exists())
        self.assertFalse((self.root / "data/processed").exists())
        metadata = read_json(output / "row-metadata.json")
        for item in metadata:
            self.assertEqual(item["missing_required_columns"], [])
            self.assertTrue(item["schema_structurally_valid"])
            self.assertTrue(item["source_eligible"])
            self.assertEqual(item["measurement_policy"], "origin-known-fixed-calendar")
            self.assertFalse(item["quarantined"])
            self.assertEqual(item["blockers"], [])
        with (output / "candidate-records.csv").open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            self.assertEqual(tuple(reader.fieldnames), COLUMNS)
            row = next(reader)
            self.assertEqual(row["ghsa_low_count_M0"], "0")
            self.assertEqual(row["target_ghsa_unknown_count_90d"], "0")

    def test_missing_snapshot_keeps_every_ghsa_value_unknown(self):
        prepare_sources(self.root, with_snapshots=False)
        report = self.build()
        self.assertEqual(report["source_verified_ghsa_packages"], 0)
        self.assertFalse(report["ready_for_submission"])
        for row in self.rows():
            for key in COLUMNS:
                if key.startswith(("ghsa_", "target_ghsa_")):
                    self.assertIsNone(row[key], key)
        self.assertTrue(any("missing_release_snapshot" in key for key in report["blocker_package_counts"]))

    def test_sensitivity_scope_is_never_promoted_to_primary_even_when_sources_are_valid(self):
        from pcom01.release import build_release
        prepare_sources(self.root)
        report = build_release(self.root, "all-precutoff")
        self.assertEqual(report["candidate_records"], 2)
        self.assertEqual(report["structurally_valid_candidates"], 2)
        self.assertEqual(report["role"], "sensitivity")
        self.assertEqual(report["eligible_records"], 2)
        self.assertEqual(report["corrected_training_records"], 0)
        self.assertFalse(report["ready_for_submission"])
        self.assertFalse(report["publication_permitted"])
        self.assertTrue(report["all_candidates_quarantined"])

    def test_selected_package_with_missing_registry_cannot_be_silently_dropped_for_readiness(self):
        prepare_sources(self.root)
        selection_path = self.root / "config/packages.json"
        save_json(selection_path, {"packages": [{"name": PACKAGE}, {"name": "missing-source-fixture"}]})
        original = read_json(self.root / "data/provenance/acquisition.json")
        original["selection_sha256"] = sha256(selection_path)
        original["packages"]["missing-source-fixture"] = {"registry": {"failure": "source unavailable"}}
        self.bind_original(original)
        report = self.build()
        self.assertEqual(report["candidate_records"], 2)
        self.assertEqual(report["structurally_valid_candidates"], 2)
        self.assertFalse(report["ready_for_submission"])
        self.assertIn("registry_unavailable", report["blocker_package_counts"])

    def test_empty_observation_cohort_is_not_submission_ready(self):
        prepare_sources(self.root)
        registry_path = self.root / "data/raw/registry/fixture.json.gz"
        data = registry_fixture()
        for version in data["versions"]:
            data["time"][version] = "2024-01-01T00:00:00.000Z"
        save_json(registry_path, data)
        original = read_json(self.root / "data/provenance/acquisition.json")
        original["packages"][PACKAGE]["registry"]["stored_sha256"] = sha256(registry_path)
        self.bind_original(original)
        report = self.build()
        self.assertEqual(report["candidate_records"], 0)
        self.assertFalse(report["ready_for_submission"])

    def test_verified_package_without_in_window_releases_is_a_documented_exclusion(self):
        prepare_sources(self.root)
        no_rows = "no-window-releases-fixture"
        selection_path = self.root / "config/packages.json"
        save_json(selection_path, {"packages": [{"name": PACKAGE}, {"name": no_rows}]})
        registry_path = self.root / "data/raw/registry/no-window.json.gz"
        save_json(registry_path, {"name": no_rows, "time": {
            "created": "2020-01-01T00:00:00.000Z", "1.0.0": "2024-01-01T00:00:00.000Z"},
            "versions": {"1.0.0": {"name": no_rows, "version": "1.0.0"}}})
        original = read_json(self.root / "data/provenance/acquisition.json")
        original["selection_sha256"] = sha256(selection_path)
        original["packages"][no_rows] = {"registry": {
            "path": registry_path.relative_to(self.root).as_posix(), "stored_sha256": sha256(registry_path)}}
        self.bind_original(original)
        report = self.build()
        self.assertEqual(report["candidate_records"], 2)
        self.assertTrue(report["ready_for_submission"])
        exclusions = read_json(self.root / "data/corrections/supplied/exclusions.json")
        self.assertTrue(any(item["package"] == no_rows and item["reason"] == "no_supplied_stable_records"
                            for item in exclusions))

    def test_missing_download_source_leaves_coverage_unknown_not_zero(self):
        prepare_sources(self.root)
        original_path = self.root / "data/provenance/acquisition.json"
        original = read_json(original_path)
        original["packages"][PACKAGE]["downloads"] = {"failure": "synthetic missing source"}
        save_json(original_path, original)
        release_path = self.root / "data/provenance/release-acquisition.json"
        acquired = read_json(release_path)
        acquired["original_acquisition_sha256"] = sha256(original_path)
        save_json(release_path, acquired)
        report = self.build()
        self.assertFalse(report["ready_for_submission"])
        self.assertEqual(report["source_verified_ghsa_packages"], 1)
        for row in self.rows():
            self.assertEqual(row["ghsa_high_count_M0"], 0)
            for key in COLUMNS:
                if key.startswith(("package_downloads_", "package_download_days_observed_")):
                    self.assertIsNone(row[key], key)

    def test_missing_history_is_not_reconstructed_from_later_outcome_tree(self):
        prepare_sources(self.root)
        path = self.root / "data/provenance/release-acquisition.json"
        manifest = read_json(path)
        del manifest["snapshots"][ORIGIN]
        save_json(path, manifest)
        report = self.build()
        self.assertFalse(report["ready_for_submission"])
        self.assertEqual(report["source_verified_ghsa_packages"], 0)
        self.assertTrue(all(row["ghsa_low_count"] is None for row in self.rows()))

    def test_missing_outcome_preserves_verified_history_but_never_invents_labels(self):
        prepare_sources(self.root)
        path = self.root / "data/provenance/release-acquisition.json"
        manifest = read_json(path)
        del manifest["snapshots"][END]
        save_json(path, manifest)
        report = self.build()
        self.assertFalse(report["ready_for_submission"])
        self.assertEqual(report["source_verified_ghsa_packages"], 0)
        self.assertEqual(report["source_verified_history_ghsa_packages"], 1)
        for row in self.rows():
            self.assertEqual(row["ghsa_low_count"], 1)
            self.assertEqual(row["ghsa_low_count_M2"], 1)
            self.assertTrue(all(row[key] is None for key in TARGET_COLUMNS))

    def test_mismatched_snapshot_provenance_is_not_trusted_despite_bundle_hash(self):
        prepare_sources(self.root)
        path = self.root / "data/provenance/release-acquisition.json"
        manifest = read_json(path)
        manifest["snapshots"][ORIGIN]["commit"]["sha"] = "f" * 40
        save_json(path, manifest)
        report = self.build()
        self.assertEqual(report["source_verified_history_ghsa_packages"], 0)
        self.assertTrue(all(row["ghsa_low_count"] is None for row in self.rows()))

    def test_pinned_source_tamper_is_not_accepted(self):
        prepare_sources(self.root)
        path = self.root / "data/raw/registry/fixture.json.gz"
        bad = registry_fixture()
        bad["time"]["2.0.0"] = "2026-06-25T12:34:56.789Z"
        save_json(path, bad)
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.build()

    def test_different_local_schema_cannot_claim_the_loaded_official_contract(self):
        prepare_sources(self.root)
        path = self.root / "schema/record_schema.json"
        schema = read_json(path)
        schema["months"]["M0"] = "2026-05"
        save_json(path, schema)
        with self.assertRaisesRegex(ValueError, "Schema contract is missing or differs"):
            self.build()
        status = read_json(self.root / "data/corrections/supplied/build-status.json")
        self.assertFalse(status["complete"])
        self.assertFalse(status["ready_for_submission"])

    def test_snapshot_hash_tamper_is_quarantined_not_counted(self):
        prepare_sources(self.root)
        path = self.root / "data/raw/release-advisories-1.json.gz"
        bad = read_json(path)
        bad["records"][1]["document"]["database_specific"]["severity"] = "CRITICAL"
        save_json(path, bad)
        report = self.build()
        self.assertFalse(report["ready_for_submission"])
        self.assertEqual(report["source_verified_ghsa_packages"], 0)
        self.assertTrue(all(row["target_ghsa_high_count_90d"] is None for row in self.rows()))

    def test_original_output_is_protected(self):
        prepare_sources(self.root)
        target = self.root / "data/processed"
        target.mkdir(parents=True)
        sentinel = target / "training.jsonl"
        sentinel.write_text("preserved original\n")
        for output in (target, target / "nested"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                self.build(output=output)
        self.assertEqual(sentinel.read_text(), "preserved original\n")

    def test_every_output_reproduces_byte_for_byte(self):
        prepare_sources(self.root)
        self.build()
        replay = self.root / "replay"
        self.build(output=replay)
        original = self.root / "data/corrections/supplied"
        self.assertEqual({p.name for p in original.iterdir()}, {p.name for p in replay.iterdir()})
        for path in original.iterdir():
            self.assertEqual(path.read_bytes(), (replay / path.name).read_bytes(), path.name)

    def test_successful_build_seals_all_candidate_artifacts_and_source_hashes(self):
        prepare_sources(self.root)
        report = self.build()
        output = self.root / "data/corrections/supplied"
        status = read_json(output / "build-status.json")
        self.assertTrue(status["complete"])
        self.assertTrue(status["ready_for_submission"])
        self.assertEqual(status["candidate_sha256"], sha256(output / "candidate-records.jsonl"))
        self.assertEqual(status["original_acquisition_sha256"], sha256(self.root / "data/provenance/acquisition.json"))
        self.assertEqual(status["release_acquisition_sha256"], sha256(self.root / "data/provenance/release-acquisition.json"))
        self.assertIn("schema_contract_sha256", report)
        self.assertNotIn("original_schema_sha256", report)
        self.assertEqual(set(status["artifact_sha256"]), {p.name for p in output.iterdir()} - {"build-status.json"})
        for name, digest in status["artifact_sha256"].items():
            self.assertEqual(digest, sha256(output / name))

    def test_tampered_source_rebuild_invalidates_previous_success_status(self):
        prepare_sources(self.root)
        self.build()
        output = self.root / "data/corrections/supplied"
        previous = (output / "candidate-records.jsonl").read_bytes()
        path = self.root / "data/raw/registry/fixture.json.gz"
        save_json(path, {"changed": "untrusted"})
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            self.build()
        status = read_json(output / "build-status.json")
        self.assertFalse(status["complete"])
        self.assertNotIn("candidate_sha256", status)
        self.assertEqual((output / "candidate-records.jsonl").read_bytes(), previous)

    def test_interrupted_artifact_write_cannot_leave_success_status(self):
        prepare_sources(self.root)
        self.build()
        output = self.root / "data/corrections/supplied"

        def interrupted(path, payload):
            if path.name == "row-metadata.json":
                raise OSError("synthetic interrupted output write")
            return save_json(path, payload)

        with patch("pcom01.release.save_json", side_effect=interrupted):
            with self.assertRaisesRegex(OSError, "interrupted output write"):
                self.build()
        status = read_json(output / "build-status.json")
        self.assertFalse(status["complete"])
        self.assertFalse(status["ready_for_submission"])


if __name__ == "__main__":
    unittest.main()
