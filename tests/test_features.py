"""Optional feature windows, provenance and independent recount checks."""
from datetime import timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pcom01.advisories import utc
from pcom01.dataset_export import build_corrected
from pcom01.features import COLUMNS, audit_features, build_features, derive_features
from pcom01.io import read_json, save_json, sha256
from pcom01.npm import exact_purl
from test_release import PACKAGE, ORIGIN, END, OLD_ID, NEW_ID, advisory, prepare_sources, registry_fixture, snapshot


def record(version="2.0.0", registry=None):
    registry = registry or registry_fixture()
    return {"purl": exact_purl(PACKAGE, version), "published_at": registry["time"][version]}


class FeatureWindowTests(unittest.TestCase):
    def setUp(self):
        self.registry = registry_fixture()
        self.history = snapshot([advisory()], ORIGIN)

    def derive(self, downloads=None, history=None, registry=None, version="2.0.0"):
        registry = registry or self.registry
        return derive_features(record(version, registry), registry, downloads,
                               self.history if history is None else history, ORIGIN)

    def test_versions_ages_and_cadence_exclude_later_releases(self):
        result = self.derive()
        self.assertEqual(tuple(result), COLUMNS)
        self.assertEqual((result["version_major"], result["version_minor"], result["version_patch"]), (2, 0, 0))
        self.assertEqual(result["version_age_days"], 0.0)
        self.assertEqual(result["stable_release_count_30d"], 1)
        self.assertEqual(result["stable_release_count_90d"], 1)
        self.assertEqual(result["stable_release_count_365d"], 2)
        age = (utc(ORIGIN) - utc(self.registry["time"]["1.0.0"])).total_seconds() / 86400
        self.assertEqual(result["days_since_previous_stable_release"], round(age, 6))
        self.assertEqual(self.derive(version="1.0.0")["version_age_days"], round(age, 6))

    def test_release_lower_boundary_included_but_future_and_prerelease_excluded(self):
        for version, shift in (("1.2.0", -30), ("1.3.0", -31), ("1.4.0-beta.1", -1), ("9.0.0", 1)):
            self.registry["versions"][version] = {"name": PACKAGE, "version": version}
            self.registry["time"][version] = (utc(ORIGIN) + timedelta(days=shift)).isoformat()
        self.assertEqual(self.derive()["stable_release_count_30d"], 2)

    def test_unknown_stable_timestamp_does_not_become_zero_cadence(self):
        self.registry["versions"]["1.5.0"] = {"name": PACKAGE, "version": "1.5.0"}
        result = self.derive()
        self.assertIsNone(result["stable_release_count_30d"])
        self.assertIsNone(result["days_since_previous_stable_release"])

    def test_same_day_partial_observation_and_future_downloads_are_excluded(self):
        payload = {"package": PACKAGE, "downloads": [
            {"day": "2026-05-14", "downloads": 8},
            {"day": "2026-05-15", "downloads": 99999},
            {"day": "2026-05-16", "downloads": 99999}]}
        result = self.derive(payload)
        self.assertEqual(result["downloads_mean_daily_30d"], 8.0)
        self.assertEqual(result["downloads_observed_days_30d"], 1)
        self.assertIsNone(result["downloads_mean_daily_30d_change_fraction"])

    def test_midnight_origin_includes_previous_completed_day(self):
        origin = "2026-05-15T00:00:00.000Z"
        self.registry["time"]["2.0.0"] = origin
        result = derive_features(record(registry=self.registry), self.registry,
            {"package": PACKAGE, "downloads": [{"day": "2026-05-14", "downloads": 0}]},
            snapshot([advisory()], origin), origin)
        self.assertEqual(result["downloads_mean_daily_30d"], 0.0)
        self.assertEqual(result["downloads_observed_days_30d"], 1)

    def test_missing_source_empty_coverage_and_observed_zero_are_distinct(self):
        missing = self.derive()
        empty = self.derive({"package": PACKAGE, "downloads": []})
        zero = self.derive({"package": PACKAGE, "downloads": [{"day": "2026-05-14", "downloads": 0}]})
        self.assertIsNone(missing["downloads_observed_days_30d"])
        self.assertEqual(empty["downloads_observed_days_30d"], 0)
        self.assertIsNone(empty["downloads_mean_daily_30d"])
        self.assertEqual(zero["downloads_mean_daily_30d"], 0.0)

    def test_trend_requires_two_complete_windows_and_positive_baseline(self):
        edge = utc(ORIGIN).date()
        days = [{"day": (edge - timedelta(days=i)).isoformat(), "downloads": 20 if i <= 30 else 10}
                for i in range(1, 61)]
        payload = {"package": PACKAGE, "downloads": days}
        self.assertEqual(self.derive(payload)["downloads_mean_daily_30d_change_fraction"], 1.0)
        self.assertIsNone(self.derive({**payload, "downloads": days[:-1]})["downloads_mean_daily_30d_change_fraction"])
        for item in days[30:]:
            item["downloads"] = 0
        self.assertIsNone(self.derive(payload)["downloads_mean_daily_30d_change_fraction"])

    def test_duplicate_download_day_is_rejected(self):
        item = {"day": "2026-05-14", "downloads": 5}
        with self.assertRaisesRegex(ValueError, "duplicate day"):
            self.derive({"package": PACKAGE, "downloads": [item, item]})

    def test_ghsa_rolling_boundary_severity_and_withdrawal(self):
        boundary = (utc(ORIGIN) - timedelta(days=30)).isoformat()
        older = (utc(ORIGIN) - timedelta(days=30, seconds=1)).isoformat()
        documents = [advisory(OLD_ID, boundary, "HIGH"), advisory(NEW_ID, older, "CRITICAL"),
                     advisory("GHSA-4567-4567-4567", "2026-05-01T00:00:00Z", "LOW")]
        documents[-1]["withdrawn"] = "2026-05-02T00:00:00Z"
        values = self.derive(history=snapshot(documents, ORIGIN))
        self.assertEqual(values["ghsa_count_30d"], 1)
        self.assertEqual(values["ghsa_high_critical_count_30d"], 1)
        self.assertEqual(values["ghsa_count_90d"], 2)

    def test_wrong_ghsa_boundary_fails(self):
        with self.assertRaisesRegex(ValueError, "origin"):
            self.derive(history=snapshot([advisory()], "2026-05-16T12:34:56.789Z"))

    def test_later_version_and_wrong_record_timestamp_fail(self):
        with self.assertRaisesRegex(ValueError, "release-time evidence"):
            self.derive(version="1.9.0")
        wrong = {**record(), "published_at": "2026-05-14T00:00:00.000Z"}
        with self.assertRaisesRegex(ValueError, "release-time evidence"):
            derive_features(wrong, self.registry, None, self.history, ORIGIN)

    def test_missing_history_remains_unknown(self):
        result = derive_features(record(), self.registry, None, None, ORIGIN)
        self.assertIsNone(result["ghsa_count_30d"])
        self.assertIsNone(result["ghsa_high_critical_count_90d"])


class FeatureExportTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        prepare_sources(self.root)
        build_corrected(self.root)
        self.output = self.root / "data/features"

    def test_export_is_independently_audited_source_bound_and_reproducible(self):
        core_before = {path.name: path.read_bytes() for path in (self.root / "data/corrected").iterdir()}
        manifest = build_features(self.root)
        self.assertTrue(manifest["valid"])
        self.assertEqual(manifest["feature_columns"], 22)
        audited = audit_features(self.root)
        self.assertTrue(audited["valid"], audited)
        self.assertEqual(audited["field_comparisons"], 44)
        self.assertIn("data/raw/registry/fixture.json.gz", manifest["source_sha256"])
        self.assertIn("data/raw/downloads/fixture.json.gz", manifest["source_sha256"])
        self.assertIn("data/raw/release-advisories-0.json.gz", manifest["source_sha256"])
        self.assertNotIn("data/raw/release-advisories-1.json.gz", manifest["source_sha256"])
        replay = self.root / "replay-features"
        build_features(self.root, replay)
        self.assertEqual({p.name for p in self.output.iterdir()}, {"features.jsonl", "features.csv", "feature-spec.json", "manifest.json"})
        for path in self.output.iterdir():
            self.assertEqual(path.read_bytes(), (replay / path.name).read_bytes())
        self.assertEqual(core_before, {path.name: path.read_bytes() for path in (self.root / "data/corrected").iterdir()})

    def test_outcome_advisories_do_not_enter_feature_counts(self):
        build_features(self.root)
        rows = [json.loads(line) for line in (self.output / "features.jsonl").read_text().splitlines()]
        for row in rows:
            self.assertEqual(row["ghsa_count_90d"], 1)
            self.assertEqual(row["ghsa_high_critical_count_90d"], 0)
            self.assertEqual(row["downloads_mean_daily_30d"], round(125 / 3, 6))

    def test_tamper_is_detected_even_after_artifact_hash_is_resealed(self):
        build_features(self.root)
        path = self.output / "features.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[0]["ghsa_count_30d"] = 1234
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        manifest = read_json(self.output / "manifest.json")
        manifest["artifact_sha256"][path.name] = sha256(path)
        save_json(self.output / "manifest.json", manifest)
        result = audit_features(self.root)
        self.assertFalse(result["valid"])
        self.assertIn("Independent feature recount", result["errors"][0])

    def test_source_mutation_invalidates_previous_feature_export(self):
        build_features(self.root)
        source = self.root / "data/raw/downloads/fixture.json.gz"
        payload = read_json(source)
        payload["downloads"][0]["downloads"] += 1
        save_json(source, payload)
        self.assertFalse(audit_features(self.root)["valid"])
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            build_features(self.root)
        self.assertFalse(read_json(self.output / "manifest.json")["complete"])

    def test_missing_ghsa_source_cannot_leave_stale_feature_export_valid(self):
        build_features(self.root)
        (self.root / "data/raw/release-advisories-0.json.gz").unlink()
        with self.assertRaises(OSError):
            build_features(self.root)
        self.assertFalse(read_json(self.output / "manifest.json")["complete"])
        self.assertFalse(audit_features(self.root)["valid"])

    def test_later_snapshot_cannot_be_relabelled_as_forecast_origin(self):
        path = self.root / "data/corrected/row-metadata.json"
        metadata = read_json(path)
        for item in metadata:
            item["origin"] = END
        save_json(path, metadata)
        manifest_path = self.root / "data/corrected/manifest.json"
        manifest = read_json(manifest_path)
        manifest["artifact_sha256"][path.name] = sha256(path)
        save_json(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, "highest supplied record"):
            build_features(self.root)
        self.assertFalse(read_json(self.output / "manifest.json")["complete"])

    def test_git_shard_tampering_cannot_reuse_prior_feature_audit_cache(self):
        from test_git_evidence import git_fixture
        git_fixture(self.root)
        build_corrected(self.root)
        manifest = build_features(self.root)
        self.assertTrue(audit_features(self.root)["valid"])
        bindings = manifest["source_sha256"]
        self.assertIn("data/provenance/git-blob-shards.json", bindings)
        alias = self.root / ".." / self.root.name
        self.assertEqual(build_features(alias)["source_sha256"], bindings)
        self.assertTrue(audit_features(alias)["valid"])
        shard = next(name for name in bindings if name.startswith("data/raw/git-blob-shards/"))
        (self.root / shard).write_bytes(b"changed original Git source")
        result = audit_features(self.root)
        self.assertFalse(result["valid"])
        self.assertTrue(any("hash mismatch" in error for error in result["errors"]))

    def test_git_inventory_delta_ancestors_are_explicit_feature_sources(self):
        from test_git_evidence import git_fixture
        from pcom01.git_evidence import inventory_tree_id
        acquisition = git_fixture(self.root)
        info = acquisition["snapshots"][ORIGIN]
        source = info["git_source"]
        path = self.root / source["inventory_path"]
        inventory = read_json(path)
        base_entries = inventory["entries"][:1]
        base_tree = inventory_tree_id(base_entries)
        base_path = self.root / "data/raw/git-reviewed-trees" / (base_tree + ".json.gz")
        save_json(base_path, {"schema_version": 1, "tree_sha": base_tree, "entries": base_entries})
        save_json(path, {"schema_version": 1, "tree_sha": inventory["tree_sha"],
                         "base_tree_sha": base_tree, "base_sha256": sha256(base_path),
                         "deleted": [], "entries": inventory["entries"][1:]})
        source["inventory_sha256"] = sha256(path)
        bundle_path = self.root / info["bundle_path"]
        bundle = read_json(bundle_path)
        bundle["provenance"]["git_source"] = source
        save_json(bundle_path, bundle)
        info["bundle_sha256"] = sha256(bundle_path)
        save_json(self.root / "data/provenance/release-acquisition.json", acquisition)
        build_corrected(self.root)
        manifest = build_features(self.root)
        self.assertIn(base_path.relative_to(self.root).as_posix(), manifest["source_sha256"])
        self.assertTrue(audit_features(self.root)["valid"])
        base_path.write_bytes(b"changed ancestor inventory")
        self.assertFalse(audit_features(self.root)["valid"])

    def test_independent_audit_catches_corrupted_builder_output(self):
        from pcom01 import features
        original = features._package_values
        def wrong(*args, **kwargs):
            values = original(*args, **kwargs)
            values["stable_release_count_30d"] += 1
            return values
        with patch("pcom01.features._package_values", side_effect=wrong):
            with self.assertRaisesRegex(ValueError, "Independent feature recount"):
                build_features(self.root)
        self.assertFalse(read_json(self.output / "manifest.json")["complete"])

    def test_feature_output_cannot_overwrite_core_or_source_directories(self):
        for name in ("data/corrected", "data/processed", "data/raw", "data/provenance", "schema", "config"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "overwrite"):
                build_features(self.root, self.root / name)


if __name__ == "__main__":
    unittest.main()
