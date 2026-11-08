"""Offline tests for release snapshot acquisition and explicit CLI policy.

All HTTP clients are controlled doubles; no network, real source acquisition,
or existing dataset output is touched by these tests.
"""
from contextlib import redirect_stderr, redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pcom01.advisories import HistoricalEvidenceError, utc
from pcom01.io import read_json, save_json, sha256
from pcom01 import pipeline
from tools import acquire_release_sources as acquisition


PACKAGE = "release-acquisition-fixture"
SHA = "a" * 40
ORIGIN = "2026-05-15T12:34:56.789Z"
END = "2026-08-13T12:34:56.789Z"


class ArchiveClient:
    """A deterministic commit lookup and complete, tiny in-memory Git archive."""
    def __init__(self, committed, *, archive_root=None, malformed=False):
        self.committed = committed
        self.archive_root = archive_root or "advisory-database-" + SHA
        self.malformed = malformed
        self.urls = []
        self.events = []

    def json(self, url):
        self.urls.append(url)
        return [{"sha": SHA, "commit": {"committer": {"date": self.committed}},
                 "html_url": "https://github.com/github/advisory-database/commit/" + SHA}], {"url": url}

    def get(self, url, *, destination):
        self.urls.append(url)
        if self.malformed:
            destination.write_bytes(b"not a tar archive")
            return None, {"url": url}
        document = {
            "id": "GHSA-2345-2345-2345", "published": "2026-04-01T00:00:00Z",
            "modified": "2026-04-01T00:00:00Z",
            "database_specific": {"github_reviewed": True, "github_reviewed_at": "2026-04-01T00:00:00Z", "severity": "LOW"},
            "affected": [{"package": {"ecosystem": "npm", "name": PACKAGE}}],
        }
        raw = json.dumps(document).encode()
        with tarfile.open(destination, "w:gz") as archive:
            entry = tarfile.TarInfo(self.archive_root + "/advisories/github-reviewed/2026/04/GHSA-2345-2345-2345/GHSA-2345-2345-2345.json")
            entry.size = len(raw)
            archive.addfile(entry, io.BytesIO(raw))
        return None, {"url": url}


class ReleaseAcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def resolution_entry(self):
        commit = {"sha": SHA, "committed_at": "2026-05-15T12:34:56Z",
                  "html_url": "https://github.com/github/advisory-database/commit/" + SHA}
        response = [{"sha": SHA, "commit": {"committer": {"date": commit["committed_at"]},
                                              "message": "Synthetic complete response with Unicode: \u0622"},
                     "html_url": commit["html_url"], "parents": [{"sha": "f" * 40}]}]
        return {"commit": commit, "response": response, "resolution": {
            "url": acquisition.resolution_url(ORIGIN), "retrieved_via": "GitHub connector",
            "fetched_at": "2026-11-08T18:20:00.000Z",
            "response_sha256": hashlib.sha256(json.dumps(response, sort_keys=True, separators=(",", ":"),
                                                           ensure_ascii=True).encode()).hexdigest()}}

    def write_resolution(self, entry, *, boundary=ORIGIN):
        save_json(self.root / "data/provenance/release-resolutions.json",
                  {"schema_version": 1, "resolutions": {boundary: entry}})

    def test_valid_connector_cache_skips_rest_resolution_and_preserves_evidence(self):
        entry = self.resolution_entry()
        self.write_resolution(entry)
        client = ArchiveClient("2026-05-15T12:34:56Z")
        result = acquisition.snapshot(client, ORIGIN, [PACKAGE], self.root)
        self.assertEqual(client.urls, ["https://codeload.github.com/github/advisory-database/tar.gz/" + SHA])
        self.assertEqual(result["commit"], entry["commit"])
        self.assertEqual(result["resolution"], entry["resolution"])
        self.assertEqual(read_json(self.root / "data/provenance/release-resolutions.json")["resolutions"][ORIGIN], entry)

    def test_missing_cache_boundary_falls_back_to_direct_resolution(self):
        self.write_resolution(self.resolution_entry(), boundary=END)
        client = ArchiveClient("2026-05-15T12:34:56Z")
        acquisition.snapshot(client, ORIGIN, [PACKAGE], self.root)
        self.assertEqual(client.urls[0], acquisition.resolution_url(ORIGIN))

    def test_corrupt_resolution_cache_fails_closed_without_http_fallback(self):
        original = self.resolution_entry()
        edits = (
            lambda entry: entry["response"][0]["commit"].update(message="tampered"),
            lambda entry: entry["commit"].update(sha="b" * 40),
            lambda entry: entry["resolution"].update(url=acquisition.resolution_url("2026-05-15T12:34:56.000Z")),
            lambda entry: entry["resolution"].update(retrieved_via="unverified"),
            lambda entry: entry["resolution"].update(fetched_at="2026-11-08T18:20:00"),
            lambda entry: entry.update(response=[]),
        )
        for index, edit in enumerate(edits):
            with self.subTest(case=index):
                entry = copy.deepcopy(original)
                edit(entry)
                self.write_resolution(entry)
                client = ArchiveClient("2026-05-15T12:34:56Z")
                with self.assertRaises(acquisition.AcquisitionError):
                    acquisition.snapshot(client, ORIGIN, [PACKAGE], self.root)
                self.assertEqual(client.urls, [])

    def test_self_consistent_future_commit_cache_is_still_rejected(self):
        entry = self.resolution_entry()
        entry["commit"]["committed_at"] = ORIGIN
        entry["response"][0]["commit"]["committer"]["date"] = ORIGIN
        entry["resolution"]["response_sha256"] = hashlib.sha256(json.dumps(
            entry["response"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
        self.write_resolution(entry)
        with self.assertRaisesRegex(acquisition.AcquisitionError, "strictly before"):
            acquisition.cached_resolution(self.root, ORIGIN)

    def test_fractional_boundary_includes_same_whole_second_commit(self):
        client = ArchiveClient("2026-05-15T12:34:56Z")
        info = acquisition.snapshot(client, ORIGIN, [PACKAGE], self.root)
        self.assertIn("until=2026-05-15T12:34:56Z&per_page=1", client.urls[0])
        self.assertEqual(info["boundary"], ORIGIN)
        bundle = read_json(self.root / info["bundle_path"])
        self.assertEqual(bundle["provenance"]["reviewed_files_scanned"], 1)
        self.assertEqual(utc(bundle["provenance"]["observed_before"]), utc(ORIGIN))
        self.assertEqual(list((self.root / "data/cache/release-downloads").iterdir()), [])

    def test_exact_second_boundary_requests_previous_second(self):
        boundary = "2026-05-15T12:34:56.000Z"
        client = ArchiveClient("2026-05-15T12:34:55Z")
        acquisition.snapshot(client, boundary, [PACKAGE], self.root)
        self.assertIn("until=2026-05-15T12:34:55Z&per_page=1", client.urls[0])

    def test_commit_at_boundary_is_rejected_before_downloading(self):
        client = ArchiveClient("2026-05-15T12:34:56Z")
        with self.assertRaisesRegex(acquisition.AcquisitionError, "strictly before"):
            acquisition.snapshot(client, "2026-05-15T12:34:56.000Z", [PACKAGE], self.root)
        self.assertEqual(len(client.urls), 1)

    def test_wrong_archive_root_and_malformed_archive_leave_no_retained_bundle(self):
        for kwargs in ({"archive_root": "advisory-database-" + "b" * 40}, {"malformed": True}):
            with self.subTest(kwargs=kwargs):
                client = ArchiveClient("2026-05-15T12:34:56Z", **kwargs)
                with self.assertRaises(HistoricalEvidenceError):
                    acquisition.snapshot(client, ORIGIN, [PACKAGE], self.root)
                self.assertFalse((self.root / "data/raw/release-advisories").exists())
                self.assertEqual(list((self.root / "data/cache/release-downloads").iterdir()), [])

    def test_archive_validation_io_and_response_failures_are_recorded(self):
        planned = {
            "selection_sha256": "a" * 64, "original_acquisition_sha256": "b" * 64,
            "scopes": {"supplied": {"packages": {PACKAGE: {
                "origin": ORIGIN, "outcome_end": END, "supplied_record_count": 1}}}},
        }
        errors = (HistoricalEvidenceError("synthetic invalid archive"),
                  OSError("synthetic local I/O failure"), ValueError("synthetic malformed response"),
                  KeyError("synthetic missing commit field"), TypeError("synthetic null commit"))
        for index, error in enumerate(errors):
            root = self.root / str(index)
            with self.subTest(error=type(error).__name__), \
                    patch("pcom01.release.plan", return_value=planned), \
                    patch.object(acquisition, "selected_packages", return_value=[PACKAGE]), \
                    patch.object(acquisition, "PublicClient", return_value=SimpleNamespace(events=[])), \
                    patch.object(acquisition, "snapshot", side_effect=error):
                result = acquisition.acquire(root, ["supplied"])
            self.assertEqual(result, 2)
            manifest = read_json(root / "data/provenance/release-acquisition.json")
            self.assertFalse(manifest["requested_sources_complete"])
            self.assertEqual(manifest["snapshots"], {})
            self.assertEqual(manifest["missing_requested_boundaries"], [ORIGIN, END])
            self.assertEqual(manifest["failures"][0]["boundary"], ORIGIN)
            self.assertIn("synthetic", manifest["failures"][0]["error"])
            self.assertTrue((root / "data/provenance/release-http-events.json").exists())

    def test_parallel_failure_stops_admission_and_retains_inflight_successes(self):
        packages = [f"fixture-{i}" for i in range(3)]
        planned = {
            "selection_sha256": "a" * 64, "original_acquisition_sha256": "b" * 64,
            "scopes": {"supplied": {"packages": {
                package: {"origin": f"2026-05-{15+i}T12:34:56.789Z",
                          "outcome_end": f"2026-08-{13+i}T12:34:56.789Z",
                          "supplied_record_count": 1}
                for i, package in enumerate(packages)}}},
        }
        started = threading.Barrier(3)
        release_success = threading.Event()
        clients, calls, write_threads = [], [], []
        main_thread = threading.get_ident()

        def client_factory(**kwargs):
            client = SimpleNamespace(events=[])
            clients.append(client)
            return client

        def capture(client, boundary, packages, root):
            calls.append(boundary)
            client.events.append({"boundary": boundary})
            started.wait(timeout=5)
            if boundary == ORIGIN:
                raise acquisition.AcquisitionError("synthetic rate limit")
            if not release_success.wait(timeout=5):
                raise RuntimeError("test did not observe failure ledger write")
            return {"boundary": boundary, "bundle_path": boundary.replace(":", "_") + ".json",
                    "bundle_sha256": "c" * 64}

        def write(path, payload):
            write_threads.append(threading.get_ident())
            result = save_json(path, payload)
            if path.name == "release-acquisition.json" and payload.get("failures"):
                release_success.set()
            return result

        with patch("pcom01.release.plan", return_value=planned), \
                patch.object(acquisition, "selected_packages", return_value=packages), \
                patch.object(acquisition, "PublicClient", side_effect=client_factory), \
                patch.object(acquisition, "snapshot", side_effect=capture), \
                patch.object(acquisition, "ProcessPoolExecutor", acquisition.ThreadPoolExecutor), \
                patch.object(acquisition, "save_json", side_effect=write):
            result = acquisition.acquire(self.root, ["supplied"], workers=3)
        self.assertEqual(result, 2)
        self.assertEqual(len(calls), 3)
        self.assertEqual(len({id(client) for client in clients}), 3)
        self.assertEqual(set(write_threads), {main_thread})
        manifest = read_json(self.root / "data/provenance/release-acquisition.json")
        self.assertEqual(len(manifest["snapshots"]), 2)
        self.assertEqual(len(manifest["failures"]), 1)
        self.assertEqual(len(manifest["missing_requested_boundaries"]), 4)
        events = read_json(self.root / "data/provenance/release-http-events.json")
        self.assertEqual({item["boundary"] for item in events}, set(calls))

    def test_invalid_worker_bound_is_rejected_before_acquisition(self):
        for workers in (0, 5, True, 1.5):
            with self.subTest(workers=workers), self.assertRaisesRegex(ValueError, "workers"):
                acquisition.acquire(self.root, ["supplied"], workers=workers)

    def test_escaped_worker_exception_does_not_discard_other_inflight_capture(self):
        planned = {
            "selection_sha256": "a" * 64, "original_acquisition_sha256": "b" * 64,
            "scopes": {"supplied": {"packages": {
                f"fixture-{i}": {"origin": f"2026-05-{15+i}T12:34:56.789Z",
                                 "outcome_end": f"2026-08-{13+i}T12:34:56.789Z",
                                 "supplied_record_count": 1} for i in range(2)}}},
        }
        started, release_success = threading.Barrier(2), threading.Event()
        calls = []

        def worker(root, boundary, packages):
            calls.append(boundary)
            started.wait(timeout=5)
            if boundary == ORIGIN:
                raise TypeError("synthetic uncaught worker error")
            if not release_success.wait(timeout=5):
                raise RuntimeError("test did not observe failure ledger write")
            return {"boundary": boundary, "bundle_path": "synthetic.json", "bundle_sha256": "c" * 64}, None, [{"boundary": boundary}]

        def write(path, payload):
            save_json(path, payload)
            if path.name == "release-acquisition.json" and payload.get("failures"):
                release_success.set()

        with patch("pcom01.release.plan", return_value=planned), \
                patch.object(acquisition, "selected_packages", return_value=["fixture-0", "fixture-1"]), \
                patch.object(acquisition, "ProcessPoolExecutor", acquisition.ThreadPoolExecutor), \
                patch.object(acquisition, "_fetch_snapshot", side_effect=worker), \
                patch.object(acquisition, "save_json", side_effect=write):
            result = acquisition.acquire(self.root, ["supplied"], workers=2)
        self.assertEqual(result, 2)
        self.assertEqual(len(calls), 2)
        manifest = read_json(self.root / "data/provenance/release-acquisition.json")
        self.assertEqual(len(manifest["snapshots"]), 1)
        self.assertEqual(manifest["failures"][0]["error_type"], "TypeError")
        self.assertEqual(len(manifest["missing_requested_boundaries"]), 3)
        self.assertEqual(read_json(self.root / "data/provenance/release-http-events.json"),
                         [{"boundary": "2026-05-16T12:34:56.789Z"}])

    def test_real_spawn_worker_validates_evidence_before_any_http_request(self):
        entry = self.resolution_entry()
        entry["resolution"]["response_sha256"] = "0" * 64
        self.write_resolution(entry)
        with acquisition.ProcessPoolExecutor(max_workers=1) as pool:
            info, failure, events = pool.submit(acquisition._fetch_snapshot, self.root, ORIGIN, [PACKAGE]).result(timeout=20)
        self.assertIsNone(info)
        self.assertEqual(failure["boundary"], ORIGIN)
        self.assertIn("digest mismatch", failure["error"])
        self.assertEqual(events, [])

    def test_null_rest_commit_shapes_fail_before_archive_download(self):
        for payload in ([None], [{"commit": None}], [{"commit": {"committer": None}}]):
            client = ArchiveClient("2026-05-15T12:34:56Z")
            with self.subTest(payload=payload), patch.object(client, "json", return_value=(payload, {})):
                with self.assertRaises(acquisition.AcquisitionError):
                    acquisition.snapshot(client, ORIGIN, [PACKAGE], self.root)
                self.assertEqual(client.urls, [])

    def test_missing_or_altered_existing_capture_invalidates_complete_manifest(self):
        planned = {
            "selection_sha256": "a" * 64, "original_acquisition_sha256": "b" * 64,
            "scopes": {"supplied": {"packages": {PACKAGE: {
                "origin": ORIGIN, "outcome_end": END, "supplied_record_count": 1}}}},
        }
        for case in ("missing", "altered"):
            root = self.root / case
            source = root / "data/raw/preserved.json"
            save_json(source, {"original": True})
            digest = sha256(source)
            old_bytes = source.read_bytes()
            path = "data/raw/preserved.json" if case == "altered" else "data/raw/absent.json"
            snapshots = {boundary: {"bundle_path": path, "bundle_sha256": digest} for boundary in (ORIGIN, END)}
            manifest_path = root / "data/provenance/release-acquisition.json"
            save_json(manifest_path, {
                "selection_sha256": "a" * 64, "original_acquisition_sha256": "b" * 64,
                "requested_boundaries": [ORIGIN, END], "requested_sources_complete": True,
                "snapshots": snapshots, "failures": [],
            })
            if case == "altered":
                save_json(source, {"changed": True})
                old_bytes = source.read_bytes()
            with self.subTest(case=case), patch("pcom01.release.plan", return_value=planned), \
                    patch.object(acquisition, "selected_packages", return_value=[PACKAGE]), \
                    patch.object(acquisition, "snapshot") as capture:
                result = acquisition.acquire(root, ["supplied"])
            capture.assert_not_called()
            self.assertEqual(result, 2)
            manifest = read_json(manifest_path)
            self.assertFalse(manifest["requested_sources_complete"])
            self.assertEqual(manifest["invalid_recorded_boundaries"], [ORIGIN, END])
            self.assertEqual(manifest["missing_requested_boundaries"], [ORIGIN, END])
            self.assertEqual({item["boundary"] for item in manifest["failures"]}, {ORIGIN, END})
            self.assertEqual(manifest["snapshots"], snapshots)
            self.assertEqual(source.read_bytes(), old_bytes)

    def test_stop_admission_marker_does_not_start_requests_or_mutate_sources(self):
        planned = {
            "selection_sha256": "a" * 64, "original_acquisition_sha256": "b" * 64,
            "scopes": {"supplied": {"packages": {PACKAGE: {
                "origin": ORIGIN, "outcome_end": END, "supplied_record_count": 1}}}},
        }
        marker = self.root / "data/cache/release-downloads/STOP-ADMISSION"
        marker.parent.mkdir(parents=True)
        marker.write_text("synthetic stop request")
        with patch("pcom01.release.plan", return_value=planned), \
                patch.object(acquisition, "selected_packages", return_value=[PACKAGE]), \
                patch.object(acquisition, "snapshot") as capture:
            result = acquisition.acquire(self.root, ["supplied"])
        capture.assert_not_called()
        self.assertEqual(result, 2)
        manifest = read_json(self.root / "data/provenance/release-acquisition.json")
        self.assertTrue(manifest["admission_stop_requested"])
        self.assertFalse(manifest["requested_sources_complete"])
        self.assertEqual(manifest["missing_requested_boundaries"], [ORIGIN, END])
        self.assertEqual(marker.read_text(), "synthetic stop request")

    def test_broader_resume_persists_incomplete_status_before_first_download(self):
        planned = {
            "selection_sha256": "a" * 64, "original_acquisition_sha256": "b" * 64,
            "scopes": {"supplied": {"packages": {PACKAGE: {
                "origin": ORIGIN, "outcome_end": END, "supplied_record_count": 1}}}},
        }
        existing = self.root / "data/raw/existing.json"
        save_json(existing, {"synthetic": "previous subset capture"})
        manifest_path = self.root / "data/provenance/release-acquisition.json"
        save_json(manifest_path, {
            "selection_sha256": "a" * 64, "original_acquisition_sha256": "b" * 64,
            "requested_boundaries": [ORIGIN], "requested_sources_complete": True,
            "snapshots": {ORIGIN: {"bundle_path": "data/raw/existing.json", "bundle_sha256": sha256(existing)}},
            "failures": [],
        })
        observed = []

        def capture(client, boundary, packages, root):
            observed.append(read_json(manifest_path))
            source = root / "data/raw/new.json"
            save_json(source, {"synthetic": "new boundary"})
            return {"boundary": boundary, "bundle_path": "data/raw/new.json", "bundle_sha256": sha256(source)}

        with patch("pcom01.release.plan", return_value=planned), \
                patch.object(acquisition, "selected_packages", return_value=[PACKAGE]), \
                patch.object(acquisition, "PublicClient", return_value=SimpleNamespace(events=[])), \
                patch.object(acquisition, "snapshot", side_effect=capture):
            self.assertEqual(acquisition.acquire(self.root, ["supplied"]), 0)
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0]["requested_sources_complete"])
        self.assertEqual(observed[0]["requested_boundaries"], [ORIGIN, END])
        self.assertEqual(observed[0]["missing_requested_boundaries"], [END])
        self.assertTrue(read_json(manifest_path)["requested_sources_complete"])


class ExplicitPolicyCliTests(unittest.TestCase):
    def assert_parser_rejects(self, arguments, fragment):
        messages = io.StringIO()
        with patch("sys.argv", ["run.py", *arguments]), redirect_stderr(messages):
            with self.assertRaises(SystemExit) as raised:
                pipeline.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertIn(fragment, messages.getvalue())

    def test_legacy_commands_cannot_silently_use_common_cutoff(self):
        for command in ("acquire", "build", "validate", "reproduce"):
            with self.subTest(command=command):
                self.assert_parser_rejects([command], "--legacy-cutoff")

    def test_release_validation_defaults_to_documented_supplied_version_scope(self):
        report = {"ready_for_submission": True}
        checked = {"valid_candidate_derivation": True,
                   "scopes": {"supplied": {"ready_for_submission": True}}}
        with patch("sys.argv", ["run.py", "validate-release"]), \
                patch("pcom01.release.build_release", return_value=report) as build, \
                patch("tools.audit_release.audit", return_value=checked) as audit, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(pipeline.main(), 0)
        build.assert_called_once_with(pipeline.ROOT, "supplied")
        audit.assert_called_once_with(pipeline.ROOT, scopes=("supplied",))

    def test_primary_export_commands_reject_sensitivity_scope(self):
        for command in ("build-corrected", "validate-corrected", "reproduce-corrected"):
            with self.subTest(command=command):
                self.assert_parser_rejects([command, "--scope", "all-precutoff"], "sensitivity analysis only")

    def test_explicit_legacy_build_is_allowed_without_real_dataset_write(self):
        with patch("sys.argv", ["run.py", "build", "--legacy-cutoff"]), patch.object(pipeline, "build") as build:
            self.assertEqual(pipeline.main(), 0)
        build.assert_called_once_with()

    def test_release_validation_requires_both_source_audit_and_builder_readiness(self):
        for builder_ready, audited_ready, derivation_valid in ((False, True, True),
                                                              (True, False, True),
                                                              (True, True, False)):
            with self.subTest(builder_ready=builder_ready, audited_ready=audited_ready,
                              derivation_valid=derivation_valid):
                report = {"ready_for_submission": builder_ready}
                checked = {"valid_candidate_derivation": derivation_valid,
                           "scopes": {"supplied": {"ready_for_submission": audited_ready}}}
                with patch("sys.argv", ["run.py", "validate-release", "--scope", "supplied"]), \
                        patch("pcom01.release.build_release", return_value=report), \
                        patch("tools.audit_release.audit", return_value=checked), redirect_stdout(io.StringIO()):
                    self.assertEqual(pipeline.main(), 2)

    def test_sensitivity_validation_cannot_become_primary_even_when_derivation_passes(self):
        checked = {"valid_candidate_derivation": True,
                   "scopes": {"all-precutoff": {"ready_for_submission": False}}}
        with patch("sys.argv", ["run.py", "validate-release", "--scope", "all-precutoff"]), \
                patch("pcom01.release.build_release", return_value={"ready_for_submission": False}), \
                patch("tools.audit_release.audit", return_value=checked), redirect_stdout(io.StringIO()):
            self.assertEqual(pipeline.main(), 2)


if __name__ == "__main__":
    unittest.main()
