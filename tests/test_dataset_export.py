"""Primary export gates checked with small authentic-format local fixtures."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pcom01.dataset_export import build_corrected, verify_corrected
from pcom01.io import read_json, save_json, sha256
from test_release import prepare_sources


class CorrectedExportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        prepare_sources(self.root)
        self.output = self.root / "data/corrected"

    def test_export_recounts_sources_and_matches_primary_derivation(self):
        manifest = build_corrected(self.root)
        self.assertEqual(verify_corrected(self.root), manifest)
        self.assertTrue(manifest["complete"])
        self.assertTrue(manifest["ready_for_submission"])
        self.assertFalse(manifest["publication_permitted"])
        self.assertEqual((manifest["records"], manifest["packages"], manifest["schema_columns"]), (2, 1, 224))
        self.assertEqual(manifest["scope"], "supplied")
        self.assertEqual(manifest["dataset_sha256"], sha256(self.output / "training-records.jsonl"))
        self.assertFalse((self.root / "data/processed").exists())
        for target, source in manifest["derivation_artifact_map"].items():
            self.assertEqual((self.output / target).read_bytes(),
                             (self.root / "data/corrections/supplied" / source).read_bytes())

    def test_export_reproduces_every_sealed_artifact_byte_for_byte(self):
        build_corrected(self.root)
        replay = self.root / "replay"
        build_corrected(self.root, output=replay)
        original_files = {path.name for path in self.output.iterdir()}
        self.assertEqual(original_files, {path.name for path in replay.iterdir()})
        self.assertEqual(len(original_files), 10)
        for name in original_files:
            self.assertEqual((self.output / name).read_bytes(), (replay / name).read_bytes(), name)

    def test_missing_source_invalidates_previous_export_instead_of_leaving_it_ready(self):
        build_corrected(self.root)
        path = self.root / "data/provenance/release-acquisition.json"
        acquisition = read_json(path)
        acquisition["snapshots"].pop(next(iter(acquisition["snapshots"])))
        save_json(path, acquisition)
        with self.assertRaisesRegex(ValueError, "checks failed"):
            build_corrected(self.root)
        manifest = read_json(self.output / "manifest.json")
        self.assertFalse(manifest["complete"])
        self.assertFalse(manifest["ready_for_submission"])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            verify_corrected(self.root)

    def test_failed_independent_audit_withholds_export(self):
        with patch("tools.audit_release.audit", return_value={"valid_candidate_derivation": False}):
            with self.assertRaisesRegex(ValueError, "Independent source audit failed"):
                build_corrected(self.root)
        self.assertFalse((self.output / "training-records.jsonl").exists())
        self.assertFalse(read_json(self.output / "manifest.json")["complete"])

    def test_interrupted_export_cannot_leave_a_valid_manifest(self):
        build_corrected(self.root)
        original_write = Path.write_bytes

        def interrupted(path, payload):
            if path == self.output / "training-records.csv.part":
                raise OSError("synthetic interrupted export")
            return original_write(path, payload)

        with patch.object(Path, "write_bytes", interrupted):
            with self.assertRaisesRegex(OSError, "interrupted export"):
                build_corrected(self.root)
        self.assertFalse(read_json(self.output / "manifest.json")["complete"])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            verify_corrected(self.root)

    def test_same_count_export_tamper_is_rejected_even_after_resealing_manifest(self):
        build_corrected(self.root)
        path = self.output / "training-records.jsonl"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[0]["dependency_count"] = 999
        path.write_bytes(b"".join(json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in rows))
        manifest_path = self.output / "manifest.json"
        manifest = read_json(manifest_path)
        manifest["dataset_sha256"] = sha256(path)
        manifest["artifact_sha256"][path.name] = sha256(path)
        save_json(manifest_path, manifest)
        with self.assertRaisesRegex(ValueError, "differs from source-audited derivation"):
            verify_corrected(self.root)

    def test_primary_cannot_overwrite_sources_or_original_archive(self):
        for directory in ("data/processed", "data/corrections", "data/raw",
                          "data/provenance", "schema"):
            for suffix in ("", "/nested"):
                with self.subTest(directory=directory + suffix):
                    with self.assertRaisesRegex(ValueError, "cannot overwrite"):
                        build_corrected(self.root, output=self.root / (directory + suffix))


if __name__ == "__main__":
    unittest.main()
