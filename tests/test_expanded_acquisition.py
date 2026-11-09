"""Source-integrity and cohort-admission checks for npm acquisition."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from pcom01.io import save_json, sha256
from tools.acquire_expanded_npm import ROOT, acquire, registry_candidate, verify_candidates


def registry():
    return {"name": "cohort-test", "time": {
        "created": "2020-01-01T00:00:00Z",
        "1.0.0": "2025-08-01T00:00:00Z",
        "2.0.0": "2026-06-01T00:00:00Z"},
        "versions": {version: {"name": "cohort-test", "version": version}
                     for version in ("1.0.0", "2.0.0")}}


class ExpandedAcquisitionTests(unittest.TestCase):
    def test_candidate_pool_must_match_verified_search_results(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            root = repository / "datasets/training"
            source = repository / "config/packages.json"
            save_json(source, {"packages": [{"name": "base", "role": "utility"}]})
            save_json(repository / "data/provenance/acquisition.json", {"selection_sha256": sha256(source)})
            path = root / "data/raw/search/parser.json.gz"
            save_json(path, {"objects": [{"package": {"name": "extra"}}]})
            url = "https://registry.npmjs.org/-/v1/search?text=parser&size=2&from=0"
            candidates = {"search_terms": ["parser"], "results_per_term": 2,
                "requests": [{"term": "parser", "path": "data/raw/search/parser.json.gz", "url": url,
                              "stored_sha256": sha256(path), "http": {"url": url, "status": 200}}],
                "packages": [{"name": "base", "roles": ["utility"], "original": True},
                             {"name": "extra", "roles": ["parser"], "original": False}]}
            with patch("tools.acquire_expanded_npm.ROOT", repository), patch("tools.acquire_expanded_npm.SEARCH_TERMS", ("parser",)), patch("tools.acquire_expanded_npm.SEARCH_SIZE", 2):
                self.assertEqual(verify_candidates(root, candidates), candidates)
                candidates["packages"].append({"name": "invented", "roles": ["parser"], "original": False})
                with self.assertRaisesRegex(ValueError, "differs"):
                    verify_candidates(root, candidates)
                candidates["packages"].pop()
                save_json(path, {"objects": [{"package": {"name": "changed"}}]})
                with self.assertRaisesRegex(ValueError, "binding"):
                    verify_candidates(root, candidates)

    def test_collector_cannot_overwrite_archived_dataset_root(self):
        with patch("tools.acquire_expanded_npm.freeze_candidates") as freeze:
            for path in (ROOT, ROOT / "data", ROOT / "data/raw", ROOT.parent / "homework3"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    acquire(path)
            freeze.assert_not_called()

    def screen(self, payload, tamper=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "data/raw/registry/cohort-test.json.gz"
            save_json(path, payload)
            info = {"registry": {"path": path.relative_to(root).as_posix(), "stored_sha256": sha256(path)}}
            if tamper:
                path.write_bytes(b"altered source")
            with patch("tools.acquire_expanded_npm.PublicClient") as client:
                client.return_value.events = []
                result = registry_candidate(root, {"name": "cohort-test"}, info, {})
                client.return_value.json.assert_not_called()
            return result[2]

    def test_admission_uses_release_metadata_not_advisory_outcomes(self):
        payload = registry()
        first = self.screen(payload)
        payload["advisories"] = [{"severity": "critical", "count": 999}]
        self.assertTrue(first["accepted"])
        self.assertEqual(first, self.screen(payload))

    def test_missing_manifest_inside_window_blocks_package(self):
        payload = registry()
        del payload["versions"]["1.0.0"]
        result = self.screen(payload)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "missing_version_manifests")

    def test_missing_manifest_boundary_uses_utc_instant(self):
        payload = registry()
        payload["time"]["0.9.0"] = "2025-07-01T01:00:00+02:00"
        self.assertTrue(self.screen(payload)["accepted"])
        payload["time"]["0.9.0"] = "2025-06-30T23:00:00-02:00"
        self.assertFalse(self.screen(payload)["accepted"])

    def test_invalid_manifest_is_not_silently_omitted(self):
        payload = registry()
        payload["versions"]["1.0.0"]["dependencies"] = ["invalid-map"]
        result = self.screen(payload)
        self.assertFalse(result["accepted"])
        self.assertEqual(result["reason"], "incomplete_version_inventory")

    def test_retained_source_tampering_has_no_network_fallback(self):
        result = self.screen(registry(), tamper=True)
        self.assertFalse(result["accepted"])
        self.assertIn("hash mismatch", result["detail"])


if __name__ == "__main__":
    unittest.main()
