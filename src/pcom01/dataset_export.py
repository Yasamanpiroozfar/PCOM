"""Export and verify the source-audited primary release-origin dataset."""
from pathlib import Path

from .io import read_json, save_json, sha256
from .release import build_release


INITIAL_COMMIT = "ad0dd1f0762ef29ddfedd14d2e3ef639f4e93c67"


def build_corrected(root, output=None, *, original_submission=None, minimum_packages=1):
    if type(minimum_packages) is not int or minimum_packages < 1:
        raise ValueError("minimum_packages must be a positive integer")
    root = Path(root)
    destination = Path(output) if output is not None else root / "data/corrected"
    for protected in (root / "data/processed", root / "data/corrections",
                      root / "data/raw", root / "data/provenance", root / "schema"):
        if destination.resolve() == protected.resolve() or protected.resolve() in destination.resolve().parents:
            raise ValueError("Corrected export cannot overwrite sources or archival derivations")
    destination.mkdir(parents=True, exist_ok=True)
    save_json(destination / "manifest.json", {
        "complete": False, "scope": "supplied", "ready_for_submission": False,
        "publication_permitted": False,
        "reason": "Build started; any previous export is stale until all checks pass.",
    })
    report = build_release(root, "supplied")
    if not report.get("ready_for_submission"):
        raise ValueError("Primary source/anchor/schema checks failed; corrected export withheld")
    from tools.audit_release import audit
    audited = audit(root, scopes=("supplied",))
    if not (audited.get("valid_candidate_derivation")
            and audited.get("ready_for_submission")
            and audited["scopes"]["supplied"].get("ready_for_submission")):
        raise ValueError("Independent source audit failed; corrected export withheld")
    if report["represented_packages"] < minimum_packages:
        raise ValueError(f"At least {minimum_packages} verified packages are required; "
                         f"found {report['represented_packages']}")
    source = root / "data/corrections/supplied"
    mapping = {"training-records.jsonl": "candidate-records.jsonl",
               "training-records.csv": "candidate-records.csv",
               **{name: name for name in ("row-metadata.json", "package-decisions.json",
                   "exclusions.json", "advisory-evidence.json", "validation.json", "report.json")}}
    for name, source_name in mapping.items():
        target = destination / name
        temporary = target.with_suffix(target.suffix + ".part")
        temporary.write_bytes((source / source_name).read_bytes())
        temporary.replace(target)
    save_json(destination / "source-audit.json", audited)
    manifest = {
        "complete": True, "role": "primary_corrected", "scope": "supplied",
        "measurement_policy": "origin-known-fixed-calendar",
        "ready_for_submission": True, "publication_permitted": False,
        "readiness_meaning": "Source-audited local dataset under the documented supplied-version interpretation; no claim of personal instructor approval or permission to publish.",
        "records": report["candidate_records"], "packages": report["represented_packages"],
        "schema_columns": report["schema_columns"],
        "dataset_sha256": sha256(destination / "training-records.jsonl"),
        "artifact_sha256": {name: sha256(destination / name) for name in (*mapping, "source-audit.json")},
        "derivation_artifact_map": mapping,
        "source_sha256": {"data/provenance/acquisition.json": report["original_acquisition_sha256"],
                          "data/provenance/release-acquisition.json": report["release_acquisition_sha256"],
                          "schema/record_schema.json": report["schema_contract_sha256"],
                          "data/corrections/supplied/build-status.json": sha256(source / "build-status.json")},
        "original_submission": dict(original_submission) if original_submission is not None else
                               {"path": "data/processed", "tag": "initial-training-data",
                                "commit": INITIAL_COMMIT},
        "successor_tag_proposal": "release-origin-training-v2",
        "limitations": report["limitations"],
    }
    if minimum_packages > 1:
        manifest["minimum_verified_packages"] = minimum_packages
    supplemental = root / "data/provenance/release-manifests.json"
    if supplemental.exists():
        if report.get("supplemental_source_sha256") != sha256(supplemental):
            raise ValueError("Supplemental manifest binding changed during export")
        manifest["source_sha256"]["data/provenance/release-manifests.json"] = sha256(supplemental)
    save_json(destination / "manifest.json", manifest)
    return manifest


def verify_corrected(root, output=None, *, original_submission=None, minimum_packages=1):
    """Verify export hashes, source bindings and independently recounted values."""
    root = Path(root)
    destination = Path(output) if output is not None else root / "data/corrected"
    manifest = read_json(destination / "manifest.json")
    if not (manifest.get("complete") is True and manifest.get("ready_for_submission") is True
            and manifest.get("publication_permitted") is False and manifest.get("scope") == "supplied"):
        raise ValueError("Corrected export is incomplete or has invalid policy status")
    if type(minimum_packages) is not int or minimum_packages < 1:
        raise ValueError("minimum_packages must be a positive integer")
    if (type(manifest.get("packages")) is not int or manifest["packages"] < minimum_packages
            or minimum_packages > 1 and manifest.get("minimum_verified_packages") != minimum_packages):
        raise ValueError(f"At least {minimum_packages} verified packages are required")
    if original_submission is not None and manifest.get("original_submission") != original_submission:
        raise ValueError("Original submission reference does not match this dataset root")
    artifacts = {"training-records.jsonl", "training-records.csv", "row-metadata.json",
                 "package-decisions.json", "exclusions.json", "advisory-evidence.json",
                 "validation.json", "report.json", "source-audit.json"}
    if set(manifest.get("artifact_sha256", {})) != artifacts:
        raise ValueError("Corrected export artifact inventory is incomplete")
    sources = {"data/provenance/acquisition.json", "data/provenance/release-acquisition.json",
               "schema/record_schema.json", "data/corrections/supplied/build-status.json"}
    if (root / "data/provenance/release-manifests.json").exists():
        sources.add("data/provenance/release-manifests.json")
    if set(manifest.get("source_sha256", {})) != sources:
        raise ValueError("Corrected export source inventory is incomplete")
    for name, expected in manifest["artifact_sha256"].items():
        if sha256(destination / name) != expected:
            raise ValueError("Corrected export artifact changed: " + name)
    for name, expected in manifest["source_sha256"].items():
        if sha256(root / name) != expected:
            raise ValueError("Corrected export source changed: " + name)
    if manifest["dataset_sha256"] != sha256(destination / "training-records.jsonl"):
        raise ValueError("Corrected dataset hash mismatch")
    from tools.audit_release import audit
    checked = audit(root, scopes=("supplied",))
    if not (checked.get("valid_candidate_derivation") and checked.get("ready_for_submission")):
        raise ValueError("Current independent source audit failed")
    if read_json(destination / "source-audit.json") != checked:
        raise ValueError("Corrected export audit is stale")
    expected_map = {"training-records.jsonl": "candidate-records.jsonl",
                    "training-records.csv": "candidate-records.csv",
                    **{name: name for name in artifacts - {"training-records.jsonl", "training-records.csv", "source-audit.json"}}}
    if manifest.get("derivation_artifact_map") != expected_map:
        raise ValueError("Corrected derivation mapping mismatch")
    for name, original in expected_map.items():
        if (destination / name).read_bytes() != (root / "data/corrections/supplied" / original).read_bytes():
            raise ValueError("Corrected export differs from source-audited derivation: " + name)
    report = read_json(destination / "report.json")
    if any(manifest.get(key) != report[source_key] for key, source_key in
           (("records", "candidate_records"), ("packages", "represented_packages"), ("schema_columns", "schema_columns"))):
        raise ValueError("Corrected manifest counts disagree with audited derivation")
    return manifest
