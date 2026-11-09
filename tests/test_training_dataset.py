"""Expanded cohort size, isolation and reproduction gates."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pcom01.dataset_export import build_corrected, verify_corrected
from pcom01.training_dataset import (MINIMUM_PACKAGES, build_expanded, dataset_root,
                            original_submission, reproduce_expanded, verify_expanded, _original_subset)
from pcom01.io import read_json, save_json, sha256
from test_release import prepare_sources


class ExpandedTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repository = Path(temporary.name)
        self.root = dataset_root(self.repository)
        prepare_sources(self.root)
        contract = self.repository / "schema/record_schema.json"
        contract.parent.mkdir(parents=True)
        contract.write_bytes((self.root / "schema/record_schema.json").read_bytes())
        self.archived = self.repository / "data/processed/training.jsonl"
        self.archived.parent.mkdir(parents=True)
        self.archived.write_bytes(b"original dataset\n")
        self.previous = self.repository / "data/corrected/training-records.jsonl"
        self.previous.parent.mkdir(parents=True)
        self.previous.write_bytes(b"original corrected cohort\n")
        finish = patch("pcom01.training_dataset._finish", return_value={"valid": True})
        finish.start()
        self.addCleanup(finish.stop)

    def assert_originals_untouched(self):
        self.assertEqual(self.archived.read_bytes(), b"original dataset\n")
        self.assertEqual(self.previous.read_bytes(), b"original corrected cohort\n")

    def test_record_volume_cannot_substitute_for_verified_package_count(self):
        with self.assertRaisesRegex(ValueError, "At least 300 verified packages.*found 1"):
            build_expanded(self.repository)
        manifest = read_json(self.root / "data/corrected/manifest.json")
        self.assertFalse(manifest["complete"])
        self.assertFalse(manifest["ready_for_submission"])
        self.assertFalse((self.root / "data/corrected/training-records.jsonl").exists())
        self.assert_originals_untouched()

    def test_source_audited_builder_receives_isolated_root_and_no_upper_limit(self):
        manifest = {"packages": 700, "complete": True}
        with patch("pcom01.training_dataset.build_corrected", return_value=manifest) as builder:
            self.assertEqual(build_expanded(self.repository), manifest)
        builder.assert_called_once_with(
            self.root, output=self.root / "data/corrected",
            original_submission=original_submission(), minimum_packages=300)
        self.assertEqual(MINIMUM_PACKAGES, 300)
        self.assert_originals_untouched()

    def test_verification_requires_same_minimum_and_archive_reference(self):
        with patch("pcom01.training_dataset.verify_corrected", return_value={"packages": 300}) as verifier:
            self.assertEqual(verify_expanded(self.repository)["packages"], 300)
        verifier.assert_called_once_with(self.root, original_submission=original_submission(),
                                         minimum_packages=300)

    def test_small_valid_export_does_not_pass_expanded_validation(self):
        build_corrected(self.root, original_submission=original_submission())
        with self.assertRaisesRegex(ValueError, "300 verified packages"):
            verify_expanded(self.repository)
        self.assert_originals_untouched()

    def test_archive_pointer_is_verified_independently_of_dataset_bytes(self):
        expected = original_submission()
        built = build_corrected(self.root, original_submission=expected)
        self.assertEqual(built["original_submission"], expected)
        self.assertEqual(verify_corrected(self.root, original_submission=expected), built)
        with self.assertRaisesRegex(ValueError, "Original submission reference"):
            verify_corrected(self.root, original_submission={**expected, "path": "data/processed"})

    def test_changed_schema_cannot_be_used_for_expanded_export(self):
        (self.root / "schema/record_schema.json").write_bytes(b"{}\n")
        with self.assertRaisesRegex(ValueError, "unchanged official schema"):
            build_expanded(self.repository)
        self.assert_originals_untouched()

    def test_expanded_output_cannot_overwrite_other_datasets(self):
        for path in (self.repository / "data/corrected", self.repository / "data/processed",
                     self.root / "data/raw", self.repository / "arbitrary"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "isolated replay directory"):
                build_expanded(self.repository, output=path)
        self.assert_originals_untouched()

    def test_invalid_minimum_cannot_start_export(self):
        for minimum in (0, -1, True, 1.5):
            with self.subTest(minimum=minimum), self.assertRaisesRegex(ValueError, "positive integer"):
                build_corrected(self.root, minimum_packages=minimum)
        self.assertFalse((self.root / "data/corrected").exists())

    def _replay(self, *, differing=False, extra=False):
        source = self.root / "data/corrected"
        source.mkdir(parents=True)
        for name, payload in {"one.json": b"{}\n", "two.csv": b"a,b\n1,2\n"}.items():
            (source / name).write_bytes(payload)
        feature_source = self.root / "data/features"
        feature_source.mkdir(parents=True)
        (feature_source / "features.jsonl").write_bytes(b"{}\n")

        def regenerate(repository, output):
            self.assertEqual(repository, self.repository)
            self.assertEqual(output, self.repository / "reports/replay/expanded")
            output.mkdir(parents=True)
            for path in source.iterdir():
                (output / path.name).write_bytes(path.read_bytes())
            feature_replay = self.repository / "reports/replay/expanded-features"
            feature_replay.mkdir(parents=True)
            (feature_replay / "features.jsonl").write_bytes(b"{}\n")
            if differing:
                (output / "one.json").write_bytes(b"{\"changed\":true}\n")
            if extra:
                (output / "unexpected.json").write_bytes(b"{}\n")

        with patch("pcom01.training_dataset.verify_expanded", return_value={"packages": 300}), \
                patch("pcom01.training_dataset.build_expanded", side_effect=regenerate):
            report = reproduce_expanded(self.repository)
        self.assert_originals_untouched()
        self.assertEqual(report, read_json(self.repository / "reports/expanded-reproducibility.json"))
        return report

    def test_reproduction_compares_bytes_in_ignored_replay_directory(self):
        report = self._replay()
        self.assertTrue(report["all_identical"])
        self.assertTrue(report["file_sets_equal"])
        self.assertEqual(len(report["files"]), 3)
        self.assertIn("features/features.jsonl", report["files"])

    def test_reproduction_rejects_changed_bytes(self):
        self.assertFalse(self._replay(differing=True)["all_identical"])

    def test_reproduction_rejects_extra_files(self):
        report = self._replay(extra=True)
        self.assertFalse(report["all_identical"])
        self.assertFalse(report["file_sets_equal"])

    def test_cli_routes_expansion_without_legacy_or_original_build(self):
        from pcom01.pipeline import main
        manifest = {"complete": True, "records": 1200, "packages": 300, "schema_columns": 224,
                    "dataset_sha256": "test", "ready_for_submission": True}
        for command, function in (("build-expanded", "build_expanded"),
                                  ("validate-expanded", "verify_expanded")):
            with self.subTest(command=command), patch("pcom01.pipeline.ROOT", self.repository), \
                    patch("sys.argv", ["run.py", command]), \
                    patch("pcom01.training_dataset." + function, return_value=manifest) as action, \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(main(), 0)
                action.assert_called_once_with(self.repository)
        self.assert_originals_untouched()


class OriginalSubsetTests(unittest.TestCase):
    def test_changed_or_missing_original_records_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "data/corrected/training-records.jsonl"
            original.parent.mkdir(parents=True)
            row = {"purl": "pkg:npm/test@1.0.0", "target_ghsa_high_count_90d": 2}
            original.write_text(json.dumps(row) + "\n", encoding="utf-8")
            save_json(original.parent / "manifest.json", {"records": 1, "dataset_sha256": sha256(original)})
            expanded = root / "expanded.jsonl"
            expanded.write_bytes(original.read_bytes())
            self.assertTrue(_original_subset(root, expanded)["all_identical"])
            expanded.write_text(json.dumps({**row, "target_ghsa_high_count_90d": 3}) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "changed"):
                _original_subset(root, expanded)
            expanded.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "omits"):
                _original_subset(root, expanded)


if __name__ == "__main__":
    unittest.main()
