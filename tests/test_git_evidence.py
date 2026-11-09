"""Offline Git object proofs, complete package coverage and fail-closed replay."""
import base64
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from pcom01.advisories import _build_snapshot, utc
from pcom01.git_evidence import clear_inventory_cache, inventory_tree_id, object_id, verify_git_source
from pcom01.io import read_json, save_json, sha256
from pcom01.release import build_release
from tools.audit_release import audit
from test_release import PACKAGE, ORIGIN, END, NEW_ID, advisory, prepare_sources


def tree(items):
    return b"".join(mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(oid)
                    for name, mode, oid in sorted(items, key=lambda value: value[0] + ("/" if value[1] == "40000" else "")))


def git_fixture(root):
    prepare_sources(root)
    old, fresh = advisory(), advisory(NEW_ID, ORIGIN, "HIGH")
    unrelated = advisory("GHSA-4567-4567-4567", "2025-06-01T00:00:00.000Z", package="unselected-package")
    documents = [old, fresh, unrelated]
    originals, groups = {}, {}
    for document in documents:
        raw = json.dumps(document, indent=2).encode()
        oid = object_id("blob", raw)
        originals[document["id"]] = (oid, raw)
        groups.setdefault(oid[:2], {})[oid] = base64.b64encode(raw).decode()
    shards = {}
    for prefix, objects in groups.items():
        path = root / "data/raw/git-blob-shards" / (prefix + ".json.gz")
        save_json(path, {"schema_version": 1, "objects": objects})
        shards[prefix] = {"path": path.relative_to(root).as_posix(), "sha256": sha256(path), "objects": len(objects)}
    index_path = root / "data/provenance/git-blob-shards.json"
    save_json(index_path, {"schema_version": 1, "shards": shards, "unique_objects": len(originals)})
    acquisition_path = root / "data/provenance/release-acquisition.json"
    acquisition = read_json(acquisition_path)
    acquisition.update(final_source_binding_sealed=True, source_kind="git_reviewed_tree", snapshots={})
    for boundary, current in ((ORIGIN, [old, unrelated]), (END, documents)):
        entries = [{"path": "2026/" + item["id"] + ".json", "mode": "100644",
                    "blob_sha": originals[item["id"]][0]} for item in current]
        year = tree([(item["id"] + ".json", "100644", originals[item["id"]][0]) for item in current])
        reviewed = tree([("2026", "40000", object_id("tree", year))])
        reviewed_sha = object_id("tree", reviewed)
        advisory_tree = tree([("github-reviewed", "40000", reviewed_sha)])
        root_tree = tree([("advisories", "40000", object_id("tree", advisory_tree))])
        epoch = int(utc(boundary).timestamp()) - 1
        commit = ("tree " + object_id("tree", root_tree) + "\nauthor Fixture <fixture@example.invalid> " + str(epoch)
                  + " +0000\ncommitter Fixture <fixture@example.invalid> " + str(epoch) + " +0000\n\nSynthetic test tree\n").encode()
        commit_sha = object_id("commit", commit)
        committed = datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")
        inventory_path = root / "data/raw/git-reviewed-trees" / (reviewed_sha + ".json.gz")
        save_json(inventory_path, {"schema_version": 1, "tree_sha": reviewed_sha,
                                   "entries": sorted(entries, key=lambda item: item["path"])})
        source = {"commit_object_base64": base64.b64encode(commit).decode(),
                  "root_tree_base64": base64.b64encode(root_tree).decode(),
                  "advisories_tree_base64": base64.b64encode(advisory_tree).decode(),
                  "reviewed_tree_sha": reviewed_sha,
                  "inventory_path": inventory_path.relative_to(root).as_posix(),
                  "inventory_sha256": sha256(inventory_path),
                  "selection_sha256": sha256(root / "config/packages.json"),
                  "blob_index_sha256": sha256(index_path)}
        snapshot = _build_snapshot((("advisories/github-reviewed/2026/" + item["id"] + ".json", item)
                                    for item in current), [PACKAGE], boundary, commit_sha, committed, None)
        proof = snapshot.provenance()
        proof.update(source_kind="git_reviewed_tree", git_source=source)
        path = root / "data/raw/release-advisories" / (commit_sha + ".json.gz")
        save_json(path, {"provenance": proof, "records": snapshot.raw_records()})
        acquisition["snapshots"][boundary] = {"boundary": boundary, "commit": {
            "sha": commit_sha, "committed_at": committed,
            "html_url": "https://github.com/github/advisory-database/commit/" + commit_sha},
            "source_kind": "git_reviewed_tree", "git_source": source, "archive_sha256": None,
            "bundle_path": path.relative_to(root).as_posix(), "bundle_sha256": sha256(path)}
    save_json(acquisition_path, acquisition)
    return acquisition


class GitEvidenceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.acquisition = git_fixture(self.root)
        clear_inventory_cache()

    def source(self, boundary=ORIGIN):
        info = self.acquisition["snapshots"][boundary]
        return info, read_json(self.root / info["bundle_path"])

    def save_source(self, info, bundle):
        save_json(self.root / info["bundle_path"], bundle)
        info["bundle_sha256"] = sha256(self.root / info["bundle_path"])
        save_json(self.root / "data/provenance/release-acquisition.json", self.acquisition)

    def test_verified_git_transport_builds_and_independently_audits_same_values(self):
        report = build_release(self.root, "supplied")
        self.assertTrue(report["ready_for_submission"])
        checked = audit(self.root, scopes=("supplied",))
        self.assertTrue(checked["ready_for_submission"])
        self.assertEqual(checked["scopes"]["supplied"]["source_value_comparisons"], 448)
        info, bundle = self.source()
        self.assertIsNone(info["archive_sha256"])
        self.assertEqual(bundle["provenance"]["reviewed_files_scanned"], 2)
        self.assertEqual(len(bundle["records"]), 1)

    def test_reviewed_inventory_reconstructs_exact_git_tree(self):
        info, bundle = self.source()
        inventory = read_json(self.root / info["git_source"]["inventory_path"])
        self.assertEqual(inventory_tree_id(inventory["entries"]), inventory["tree_sha"])
        with self.assertRaises(ValueError):
            inventory_tree_id(inventory["entries"] * 2)

    def test_resealed_projection_cannot_omit_matching_package_advisory(self):
        info, bundle = self.source()
        bundle["records"] = []
        self.save_source(info, bundle)
        with self.assertRaisesRegex(ValueError, "omits or duplicates"):
            verify_git_source(self.root, info, bundle)

    def test_changed_original_blob_cannot_pass_even_with_resealed_shard_and_inventory(self):
        info, bundle = self.source()
        source = info["git_source"]
        inventory = read_json(self.root / source["inventory_path"])
        oid = inventory["entries"][0]["blob_sha"]
        index_path = self.root / "data/provenance/git-blob-shards.json"
        index = read_json(index_path)
        shard_path = self.root / index["shards"][oid[:2]]["path"]
        shard = read_json(shard_path)
        shard["objects"][oid] = base64.b64encode(b'{"id":"altered"}').decode()
        save_json(shard_path, shard)
        index["shards"][oid[:2]]["sha256"] = sha256(shard_path)
        save_json(index_path, index)
        source["blob_index_sha256"] = sha256(index_path)
        bundle["provenance"]["git_source"] = source
        with self.assertRaisesRegex(ValueError, "blob digest mismatch"):
            verify_git_source(self.root, info, bundle)

    def test_resealed_tree_omission_cannot_change_complete_corpus(self):
        info, bundle = self.source()
        source = info["git_source"]
        path = self.root / source["inventory_path"]
        inventory = read_json(path)
        inventory["entries"].pop()
        save_json(path, inventory)
        source["inventory_sha256"] = sha256(path)
        bundle["provenance"]["git_source"] = source
        with self.assertRaisesRegex(ValueError, "reconstruct"):
            verify_git_source(self.root, info, bundle)

    def test_git_transport_does_not_claim_a_downloaded_archive_hash(self):
        info, bundle = self.source()
        info["archive_sha256"] = bundle["provenance"]["archive_sha256"] = "a" * 64
        with self.assertRaisesRegex(ValueError, "HTTP archive"):
            verify_git_source(self.root, info, bundle)

    def test_new_audit_cannot_reuse_cached_proof_after_source_tampering(self):
        build_release(self.root, "supplied")
        self.assertTrue(audit(self.root, scopes=("supplied",))["ready_for_submission"])
        index = read_json(self.root / "data/provenance/git-blob-shards.json")
        path = self.root / next(iter(index["shards"].values()))["path"]
        path.write_bytes(b"changed source")
        with self.assertRaisesRegex(ValueError, "source file hash mismatch|shard hash mismatch"):
            audit(self.root, scopes=("supplied",))

    def test_direct_snapshot_checks_do_not_reuse_a_previous_verification_cache(self):
        from pcom01.release import _snapshot
        from tools.audit_release import load_snapshot
        _snapshot(self.root, self.acquisition, ORIGIN)
        index = read_json(self.root / "data/provenance/git-blob-shards.json")
        path = self.root / next(iter(index["shards"].values()))["path"]
        path.write_bytes(b"changed source")
        with self.assertRaises(ValueError):
            _snapshot(self.root, self.acquisition, ORIGIN)
        with self.assertRaises(ValueError):
            load_snapshot(self.root, self.acquisition, ORIGIN, PACKAGE)

    def test_nested_operations_reuse_immutable_proofs_but_recheck_live_files(self):
        from pcom01.git_evidence import _inventory, verification_session

        @verification_session
        def checked_sequence():
            build_release(self.root, "supplied")
            misses = _inventory.cache_info().misses
            self.assertTrue(audit(self.root, scopes=("supplied",))["ready_for_submission"])
            self.assertEqual(_inventory.cache_info().misses, misses)
            index = read_json(self.root / "data/provenance/git-blob-shards.json")
            path = self.root / next(iter(index["shards"].values()))["path"]
            path.write_bytes(b"changed between nested checks")
            with self.assertRaisesRegex(ValueError, "source file hash mismatch"):
                audit(self.root, scopes=("supplied",))

        checked_sequence()
        self.assertEqual(_inventory.cache_info().currsize, 0)

    def test_removing_snapshot_transport_markers_cannot_bypass_git_proof(self):
        from pcom01.release import _snapshot
        from tools.audit_release import load_snapshot
        info, bundle = self.source()
        del info["source_kind"]
        del bundle["provenance"]["source_kind"]
        self.save_source(info, bundle)
        with self.assertRaisesRegex(ValueError, "transport"):
            _snapshot(self.root, self.acquisition, ORIGIN)
        with self.assertRaisesRegex(ValueError, "transport"):
            load_snapshot(self.root, self.acquisition, ORIGIN, PACKAGE)

    def test_unsealed_collection_cannot_become_ready(self):
        self.acquisition["final_source_binding_sealed"] = False
        save_json(self.root / "data/provenance/release-acquisition.json", self.acquisition)
        report = build_release(self.root, "supplied")
        self.assertFalse(report["ready_for_submission"])
        self.assertEqual(report["source_verified_ghsa_packages"], 0)


if __name__ == "__main__":
    unittest.main()
