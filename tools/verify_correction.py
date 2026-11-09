"""Verify dataset, source, reproducibility and original-release evidence."""
from __future__ import annotations

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
COMMIT = "ad0dd1f0762ef29ddfedd14d2e3ef639f4e93c67"
ANNOTATION = "92ce3f99bd52f8e9e4fbef95e5571569d3962d71"
INITIAL_TREE = "9d8cac9348430d773b02cf1e1cf6894933ee5495"
DOCUMENTATION_REVISIONS = {
    "reports/independent-review.md", "reports/final-audit.md",
    "reports/final-audit.json", "reports/release-check.json",
}


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def main():
    errors = []
    from pcom01.dataset_export import verify_corrected
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
    if git("rev-parse", TAG + "^{tree}").decode().strip() != INITIAL_TREE:
        errors.append("Initial snapshot file tree changed")
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
              "corrected_export": {"manifest_path": "data/corrected/manifest.json",
                                   "manifest_sha256": sha256(ROOT / "data/corrected/manifest.json"),
                                   "dataset_sha256": corrected["dataset_sha256"],
                                   "records": corrected["records"], "packages": corrected["packages"]},
              "original_tag": local, "protected_original_files": protected,
              "checks": checks,
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
