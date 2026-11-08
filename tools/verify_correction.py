"""Verify dataset, source, reproducibility and original-release evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))
from pcom01.io import now, read_json, save_json, sha256

TAG = "initial-training-data"
COMMIT = "7f3606886865302cbcb25a3151a299ea113c2b59"
ANNOTATION = "ef8ff18c9fdc8116de8f2e080e12f15140dc80c0"
DOCUMENTATION_REVISIONS = {
    "reports/independent-review.md", "reports/final-audit.md",
    "reports/final-audit.json", "reports/release-check.json",
}


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-only", action="store_true", help="Skip recorded remote tag verification")
    args = parser.parse_args()
    errors = []
    from pcom01.corrected import verify_corrected
    from tools.audit_release import audit
    corrected = verify_corrected(ROOT)
    audit(ROOT)  # Preserve the combined primary and sensitivity audit report.
    protected = []
    for name in git("ls-tree", "-r", "--name-only", TAG).decode().splitlines():
        if (name.startswith(("data/", "reports/"))
                or name == "schema/course_evidence.json"):
            expected = hashlib.sha256(git("show", TAG + ":" + name)).hexdigest()
            actual = sha256(ROOT / name) if (ROOT / name).exists() else None
            protected.append({"path": name, "initial_sha256": expected,
                              "current_sha256": actual, "unchanged": actual == expected,
                              "owner_authorized_documentation_revision": name in DOCUMENTATION_REVISIONS})
            if actual != expected and name not in DOCUMENTATION_REVISIONS:
                errors.append("Archived evidence changed: " + name)
    local = {"commit": git("rev-parse", TAG + "^{commit}").decode().strip(),
             "annotation": git("rev-parse", TAG).decode().strip(),
             "object_type": git("cat-file", "-t", TAG).decode().strip()}
    if local != {"commit": COMMIT, "annotation": ANNOTATION, "object_type": "tag"}:
        errors.append("Original annotated tag changed")
    if subprocess.run(["git", "-C", str(ROOT), "merge-base", "--is-ancestor", COMMIT, "HEAD"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        errors.append("Current revision is not a descendant of the initial-data version")
    remote = None
    if not args.local_only:
        remote = read_json(ROOT / "reports/correction-remote-preservation.json")
        responses = {item["url"].rsplit("/", 1)[-1]: item["response"] for item in remote["responses"]}
        tag_reference = responses.get(TAG, {}).get("object", {})
        tag_object = responses.get(ANNOTATION, {}).get("object", {})
        if tag_reference.get("sha") != ANNOTATION or tag_object.get("sha") != COMMIT:
            errors.append("Recorded remote initial-data tag differs from the verified local tag")
    checks = {}
    for filename, key in (("correction-tests.json", "successful"),
                          ("correction-source-audit.json", "valid_candidate_derivation"),
                          ("correction-reproducibility-supplied.json", "all_identical"),
                          ("correction-reproducibility-all-precutoff.json", "all_identical"),
                          ("correction-reproducibility-primary.json", "all_identical"),
                          ("correction-legacy-reproducibility.json", "all_identical"),
                          ("correction-legacy-source-audit.json", "valid")):
        path = ROOT / "reports" / filename
        report = read_json(path)
        checks[filename] = {"sha256": sha256(path), "check": key, "passed": report.get(key) is True}
        if report.get(key) is not True:
            errors.append("Verification did not pass: " + filename)
    acquisition = read_json(ROOT / "data/provenance/release-acquisition.json")
    supplements = read_json(ROOT / "data/provenance/release-manifests.json")
    supplemental_hash = sha256(ROOT / "data/provenance/release-manifests.json")
    if (supplements.get("complete") is not True
            or supplements.get("original_acquisition_sha256") != sha256(ROOT / "data/provenance/acquisition.json")):
        errors.append("Supplemental manifest inventory incomplete or source binding changed")
    supplemental_versions = []
    for package, versions in supplements["manifests"].items():
        for version, item in versions.items():
            supplemental_versions.append(package + "@" + version)
            if sha256(ROOT / item["path"]) != item["stored_sha256"]:
                errors.append("Supplemental source digest mismatch: " + package + "@" + version)
    resolutions = read_json(ROOT / "data/provenance/release-resolutions.json")["resolutions"]
    for boundary, info in acquisition["snapshots"].items():
        if info["commit"] != resolutions[boundary]["commit"]:
            errors.append("Independent connector/collector commit mismatch: " + boundary)
        if sha256(ROOT / info["bundle_path"]) != info["bundle_sha256"]:
            errors.append("Retained snapshot digest mismatch: " + boundary)
    scopes = {}
    for scope in ("supplied", "all-precutoff"):
        folder = ROOT / "data/corrections" / scope
        report = read_json(folder / "report.json")
        state = read_json(folder / "build-status.json")
        if state.get("complete") is not True:
            errors.append("Candidate build incomplete: " + scope)
        if report["release_acquisition_sha256"] != sha256(ROOT / "data/provenance/release-acquisition.json"):
            errors.append("Candidate build source binding stale: " + scope)
        if report.get("supplemental_source_sha256") != supplemental_hash:
            errors.append("Supplemental source binding stale: " + scope)
        for name, expected in state.get("artifact_sha256", {}).items():
            if sha256(folder / name) != expected:
                errors.append("Candidate artifact changed: " + scope + "/" + name)
        if report["ready_for_submission"] is not (scope == "supplied"):
            errors.append("Derivation readiness disagrees with primary policy: " + scope)
        if report["publication_permitted"] is not False:
            errors.append("Derivation improperly grants publication")
        scopes[scope] = {key: report[key] for key in ("candidate_records", "represented_packages",
                        "structurally_valid_candidates", "source_verified_ghsa_packages",
                        "candidate_sha256", "ready_for_submission")}
    result = {"checked_at": now(), "branch": git("branch", "--show-current").decode().strip(),
              "verification_passed": not errors, "errors": errors,
              "ready_for_submission": not errors and corrected["ready_for_submission"],
              "remote_ref_check_performed": not args.local_only,
              "corrected_export": {"manifest_path": "data/corrected/manifest.json",
                                   "manifest_sha256": sha256(ROOT / "data/corrected/manifest.json"),
                                   "dataset_sha256": corrected["dataset_sha256"],
                                   "records": corrected["records"], "packages": corrected["packages"]},
              "original_tag": local, "protected_original_files": protected,
              "remote_evidence_checked_at": remote["checked_at"] if remote else None, "checks": checks,
              "scopes": scopes, "acquired_snapshot_count": len(acquisition["snapshots"]),
              "requested_snapshot_count": len(acquisition["requested_boundaries"]),
              "requested_sources_complete": acquisition["requested_sources_complete"],
              "supplemental_source_sha256": supplemental_hash,
              "recovered_version_manifests": sorted(supplemental_versions),
              "scope": "Retained sources and artifacts; historical service synchronization and mutable registry metadata are not independently established."}
    save_json(ROOT / "reports/correction-audit.json", result)
    print(json.dumps({key: result[key] for key in ("verification_passed", "errors", "ready_for_submission",
                                                   "acquired_snapshot_count", "requested_snapshot_count", "scopes")}, indent=2))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
