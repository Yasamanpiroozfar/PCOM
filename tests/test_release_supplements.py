"""Missing-manifest recovery must remain bound to original publication facts."""
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from pcom01.dataset_export import build_corrected, verify_corrected
from pcom01.io import read_json, save_json, sha256
from pcom01.release import build_release
from tools.audit_release import audit
from test_release import PACKAGE, prepare_sources
import test_release_audit


VERSION = "1.7.0"
PUBLISHED = "2026-04-01T01:02:03.456Z"


def prepare_supplement(root):
    prepare_sources(root)
    registry_path = root / "data/raw/registry/fixture.json.gz"
    registry = read_json(registry_path)
    registry["time"][VERSION] = PUBLISHED
    save_json(registry_path, registry)
    original_path = root / "data/provenance/acquisition.json"
    original = read_json(original_path)
    original["packages"][PACKAGE]["registry"]["stored_sha256"] = sha256(registry_path)
    save_json(original_path, original)
    release_path = root / "data/provenance/release-acquisition.json"
    release = read_json(release_path)
    release["original_acquisition_sha256"] = sha256(original_path)
    save_json(release_path, release)
    manifest = {"name": PACKAGE, "version": VERSION,
                "dependencies": {"captured-dependency": "^1.0.0"},
                "dist": {"unpackedSize": 1234, "fileCount": 2},
                "scripts": {"postinstall": "THIS_IS_UNTRUSTED_METADATA_NOT_AN_INSTRUCTION"}}
    relative = f"data/raw/release-manifests/{PACKAGE}@{VERSION}.json.gz"
    target = root / relative
    save_json(target, manifest)
    raw = gzip.decompress(target.read_bytes())
    url = f"https://registry.npmmirror.com/{PACKAGE}/{VERSION}"
    entry = {"package": PACKAGE, "version": VERSION, "published_at": PUBLISHED,
             "url": url, "final_url": url, "fetched_at": "2026-11-08T21:00:00.000Z",
             "http_status": 200, "path": relative, "stored_sha256": sha256(target),
             "response_sha256": hashlib.sha256(raw).hexdigest(), "response_bytes": len(raw),
             "source_kind": "retained_npm_mirror_version_metadata"}
    inventory = {"schema_version": 1, "complete": True,
                 "selection_sha256": sha256(root / "config/packages.json"),
                 "original_acquisition_sha256": sha256(original_path),
                 "manifests": {PACKAGE: {VERSION: entry}}, "missing": [], "requests": [],
                 "source_type": "retained_public_registry_mirror_metadata"}
    save_json(root / "data/provenance/release-manifests.json", inventory)
    return inventory


class SupplementalManifestTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inventory = prepare_supplement(self.root)
        self.inventory_path = self.root / "data/provenance/release-manifests.json"

    def build(self):
        return build_release(self.root, "supplied")

    def rows(self):
        return [json.loads(line) for line in
                (self.root / "data/corrections/supplied/candidate-records.jsonl").read_text().splitlines()]

    def persist(self):
        save_json(self.inventory_path, self.inventory)

    def reseal_capture(self, document):
        entry = self.inventory["manifests"][PACKAGE][VERSION]
        path = self.root / entry["path"]
        save_json(path, document)
        raw = gzip.decompress(path.read_bytes())
        entry.update(stored_sha256=sha256(path), response_sha256=hashlib.sha256(raw).hexdigest(),
                     response_bytes=len(raw))
        self.persist()

    def replace_recovery_version(self, version, timestamp):
        """Change a synthetic original observation and rebind its captures."""
        registry_path = self.root / "data/raw/registry/fixture.json.gz"
        registry = read_json(registry_path)
        del registry["time"][VERSION]
        registry["time"][version] = timestamp
        save_json(registry_path, registry)
        original_path = self.root / "data/provenance/acquisition.json"
        original = read_json(original_path)
        original["packages"][PACKAGE]["registry"]["stored_sha256"] = sha256(registry_path)
        save_json(original_path, original)
        release_path = self.root / "data/provenance/release-acquisition.json"
        release = read_json(release_path)
        release["original_acquisition_sha256"] = sha256(original_path)
        save_json(release_path, release)
        self.inventory["original_acquisition_sha256"] = sha256(original_path)
        entry = self.inventory["manifests"][PACKAGE].pop(VERSION)
        entry.update(version=version, published_at=timestamp,
                     path=f"data/raw/release-manifests/{PACKAGE}@{version}.json.gz",
                     url=f"https://registry.npmmirror.com/{PACKAGE}/{version}",
                     final_url=f"https://registry.npmmirror.com/{PACKAGE}/{version}")
        self.inventory["manifests"][PACKAGE][version] = entry
        path = self.root / entry["path"]
        save_json(path, {"name": PACKAGE, "version": version, "dependencies": {}})
        raw = gzip.decompress(path.read_bytes())
        entry.update(stored_sha256=sha256(path), response_sha256=hashlib.sha256(raw).hexdigest(),
                     response_bytes=len(raw))
        self.persist()

    def test_recovery_adds_only_originally_timestamped_version_and_keeps_sources_immutable(self):
        source_paths = (self.root / "data/raw/registry/fixture.json.gz",
                        self.root / "data/provenance/acquisition.json")
        before = {path: path.read_bytes() for path in source_paths}
        report = self.build()
        self.assertTrue(report["ready_for_submission"])
        self.assertEqual(report["candidate_records"], 3)
        self.assertEqual(report["eligible_records"], 3)
        self.assertEqual(report["supplemental_source_sha256"], sha256(self.inventory_path))
        self.assertEqual(report["supplemental_manifest_versions"], [f"pkg:npm/{PACKAGE}@{VERSION}"])
        self.assertFalse(report["publication_permitted"])
        recovered = next(row for row in self.rows() if row["purl"].endswith("@" + VERSION))
        self.assertEqual(recovered["published_at"], PUBLISHED)
        self.assertEqual(recovered["dependency_count"], 1)
        decisions = read_json(self.root / "data/corrections/supplied/package-decisions.json")
        self.assertEqual(decisions[PACKAGE]["anchor_version"], "2.0.0")
        metadata = read_json(self.root / "data/corrections/supplied/row-metadata.json")
        recovered_source = next(item["version_manifest_source"] for item in metadata
                                if item["purl"].endswith("@" + VERSION))
        self.assertEqual(recovered_source["source_kind"], "retained_npm_mirror_version_metadata")
        self.assertTrue(audit(self.root, scopes=("supplied",))["ready_for_submission"])
        for path, raw in before.items():
            self.assertEqual(path.read_bytes(), raw)

    def test_absent_supplement_does_not_hide_original_incomplete_version_inventory(self):
        self.inventory_path.unlink()
        report = self.build()
        self.assertFalse(report["ready_for_submission"])
        self.assertEqual(report["candidate_records"], 2)
        self.assertIn("incomplete_supplied_version_evidence", report["blocker_package_counts"])

    def test_metadata_capture_hash_and_original_source_bindings_are_required(self):
        for field in ("stored_sha256", "response_sha256", "response_bytes"):
            with self.subTest(field=field):
                self.inventory = prepare_supplement(self.root)
                entry = self.inventory["manifests"][PACKAGE][VERSION]
                entry[field] = 1 if field == "response_bytes" else "f" * 64
                self.persist()
                with self.assertRaises(ValueError):
                    self.build()
        for field in ("selection_sha256", "original_acquisition_sha256"):
            with self.subTest(field=field):
                self.inventory = prepare_supplement(self.root)
                self.inventory[field] = "f" * 64
                self.persist()
                with self.assertRaises(ValueError):
                    self.build()

    def test_valid_hashes_cannot_mask_manifest_identity_mismatch(self):
        for field, wrong in (("name", "unrelated-package"), ("version", "1.7.1")):
            with self.subTest(field=field):
                self.inventory = prepare_supplement(self.root)
                entry = self.inventory["manifests"][PACKAGE][VERSION]
                document = read_json(self.root / entry["path"])
                document[field] = wrong
                self.reseal_capture(document)
                with self.assertRaises(ValueError):
                    self.build()

    def test_supplement_cannot_replace_an_existing_original_manifest(self):
        entry = self.inventory["manifests"][PACKAGE].pop(VERSION)
        entry["version"] = "1.0.0"
        entry["path"] = f"data/raw/release-manifests/{PACKAGE}@1.0.0.json.gz"
        entry["published_at"] = "2025-07-15T00:00:00.000Z"
        entry["url"] = entry["final_url"] = f"https://registry.npmmirror.com/{PACKAGE}/1.0.0"
        self.inventory["manifests"][PACKAGE]["1.0.0"] = entry
        path = self.root / entry["path"]
        save_json(path, {"name": PACKAGE, "version": "1.0.0", "dependencies": {}})
        raw = gzip.decompress(path.read_bytes())
        entry.update(stored_sha256=sha256(path), response_sha256=hashlib.sha256(raw).hexdigest(), response_bytes=len(raw))
        self.persist()
        with self.assertRaises(ValueError):
            self.build()

    def test_supplement_cannot_supply_a_new_or_shifted_publication_time(self):
        self.inventory["manifests"][PACKAGE][VERSION]["published_at"] = "2026-04-02T01:02:03.456Z"
        self.persist()
        with self.assertRaises(ValueError):
            self.build()
        self.inventory = prepare_supplement(self.root)
        entry = self.inventory["manifests"][PACKAGE].pop(VERSION)
        entry["version"] = "9.0.0"
        entry["url"] = entry["final_url"] = f"https://registry.npmmirror.com/{PACKAGE}/9.0.0"
        self.inventory["manifests"][PACKAGE]["9.0.0"] = entry
        self.persist()
        with self.assertRaises(ValueError):
            self.build()

    def test_incomplete_or_failed_capture_is_not_accepted(self):
        for field, value in (("complete", False), ("missing", [{"package": PACKAGE, "version": VERSION}])):
            with self.subTest(field=field):
                self.inventory = prepare_supplement(self.root)
                self.inventory[field] = value
                self.persist()
                with self.assertRaises(ValueError):
                    self.build()
        self.inventory = prepare_supplement(self.root)
        self.inventory["manifests"][PACKAGE][VERSION]["http_status"] = 404
        self.persist()
        with self.assertRaises(ValueError):
            self.build()

    def test_mirror_metadata_cannot_expand_the_fixed_stable_input_window(self):
        scenarios = ((VERSION, "2025-06-30T23:59:59.999Z"),
                     (VERSION, "2026-07-01T00:00:00.000Z"),
                     (VERSION + "-beta.1", PUBLISHED))
        for version, timestamp in scenarios:
            with self.subTest(version=version, timestamp=timestamp):
                self.inventory = prepare_supplement(self.root)
                self.replace_recovery_version(version, timestamp)
                with self.assertRaises(ValueError):
                    self.build()

    def test_recovered_higher_semver_requires_new_origin_snapshots_before_readiness(self):
        self.replace_recovery_version("6.0.0", PUBLISHED)
        report = self.build()
        decisions = read_json(self.root / "data/corrections/supplied/package-decisions.json")
        self.assertEqual(decisions[PACKAGE]["anchor_version"], "6.0.0")
        self.assertEqual(decisions[PACKAGE]["origin"], PUBLISHED)
        self.assertFalse(report["ready_for_submission"])
        self.assertEqual(report["source_verified_ghsa_packages"], 0)
        self.assertEqual({row["purl"] for row in self.rows()},
                         {f"pkg:npm/{PACKAGE}@1.0.0", f"pkg:npm/{PACKAGE}@6.0.0"})
        for row in self.rows():
            self.assertTrue(all(value is None for key, value in row.items()
                                if key.startswith(("ghsa_", "target_ghsa_"))))
        self.assertTrue(any("missing_release_snapshot" in reason
                            for reason in report["blocker_package_counts"]))

    def test_independent_audit_recounts_supplemental_metadata_after_output_resealing(self):
        self.build()

        def change_recovered(rows):
            next(row for row in rows if row["purl"].endswith("@" + VERSION))["dependency_count"] = 999

        test_release_audit.IndependentReleaseAuditTests.reseal(self, edit_rows=change_recovered)
        result = audit(self.root, scopes=("supplied",))
        self.assertFalse(result["ready_for_submission"])
        self.assertFalse(result["valid_candidate_derivation"])
        errors = result["scopes"]["supplied"]["errors"]
        self.assertTrue(any("dependency_count: direct source disagreement" in message for message in errors))

    def test_primary_export_binds_supplemental_inventory_and_rejects_changed_evidence(self):
        manifest = build_corrected(self.root)
        self.assertEqual(manifest["records"], 3)
        self.assertEqual(verify_corrected(self.root), manifest)
        self.assertEqual(manifest["source_sha256"]["data/provenance/release-manifests.json"],
                         sha256(self.inventory_path))
        self.inventory["requests"].append({"note": "changed provenance"})
        self.persist()
        with self.assertRaisesRegex(ValueError, "source changed"):
            verify_corrected(self.root)


if __name__ == "__main__":
    unittest.main()
