"""Build and reproduce the expanded cohort independently of the initial datasets."""
from pathlib import Path
import json

from .dataset_export import INITIAL_COMMIT, build_corrected, verify_corrected
from .features import audit_features, build_features
from .git_evidence import verification_session
from .io import read_json, save_json, sha256

MINIMUM_PACKAGES = 300


def dataset_root(repository_root):
    repository = Path(repository_root).resolve()
    root = repository / "datasets/training"
    if repository not in root.resolve().parents:
        raise ValueError("Expanded dataset root must remain inside the repository")
    return root


def original_submission():
    return {"path": "../../data/processed", "tag": "initial-training-data",
            "commit": INITIAL_COMMIT}


def _check_schema(repository, root):
    expected = repository / "schema/record_schema.json"
    actual = root / "schema/record_schema.json"
    if not actual.is_file() or actual.read_bytes() != expected.read_bytes():
        raise ValueError("Expanded cohort must use the unchanged official schema contract")


def _cohort_evidence(repository, root):
    from tools.acquire_expanded_npm import verify_candidates
    path = root / "config/candidates.json"
    candidates = verify_candidates(root, read_json(path), repository=repository)
    selection = read_json(root / "config/packages.json")
    acquisition = read_json(root / "data/provenance/acquisition.json")
    digest = sha256(path)
    if (selection.get("candidate_sha256") != digest
            or acquisition.get("candidate_inventory_sha256") != digest
            or acquisition.get("selection_sha256") != sha256(root / "config/packages.json")):
        raise ValueError("Expanded candidate/source bindings disagree")
    candidate_names = {item["name"] for item in candidates["packages"]}
    names = [item["name"] for item in selection["packages"]]
    if len(names) != len(set(names)) or not set(names) <= candidate_names or set(names) != set(acquisition["packages"]):
        raise ValueError("Expanded selection differs from the documented source cohort")
    return {"candidate_packages": len(candidate_names), "selected_packages": len(names),
            "candidate_inventory_sha256": digest, "search_responses_verified": len(candidates["requests"])}


def _original_subset(repository, expanded_file):
    folder = repository / "data/corrected"
    manifest = read_json(folder / "manifest.json")
    original = folder / "training-records.jsonl"
    if sha256(original) != manifest["dataset_sha256"]:
        raise ValueError("Original cohort dataset hash mismatch")
    rows = [json.loads(line) for line in original.read_text(encoding="utf-8").splitlines()]
    expected = {row["purl"]: row for row in rows}
    if len(expected) != len(rows) or len(rows) != manifest["records"]:
        raise ValueError("Original cohort record identities disagree")
    seen = set()
    with expanded_file.open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            key = row["purl"]
            if key in expected:
                if key in seen or row != expected[key]:
                    raise ValueError("Expanded cohort changed an original record: " + key)
                seen.add(key)
    if seen != set(expected):
        raise ValueError("Expanded cohort omits original records")
    return {"records_checked": len(rows), "all_identical": True,
            "dataset_sha256": manifest["dataset_sha256"]}


def _finish(repository, root, core, features, manifest, *, rebuild):
    current = core.resolve() == (root / "data/corrected").resolve()
    if current:
        save_json(repository / "reports/expanded-integrity.json", {"valid": False})
    cohort = _cohort_evidence(repository, root)
    preserved = _original_subset(repository, core / "training-records.jsonl")
    if rebuild:
        feature_manifest = build_features(root, output=features)
        checked = feature_manifest["audit"]
    else:
        checked = audit_features(root, output=features)
        if not checked.get("valid"):
            raise ValueError("Expanded feature audit failed: " + str(checked.get("errors")))
        feature_manifest = read_json(features / "manifest.json")
    if feature_manifest["records"] != manifest["records"] or feature_manifest["packages"] != manifest["packages"]:
        raise ValueError("Additional features do not cover the official dataset")
    result = {"valid": True, "cohort": cohort, "original_cohort": preserved,
              "records": manifest["records"], "packages": manifest["packages"],
              "official_columns": manifest["schema_columns"],
              "dataset_sha256": manifest["dataset_sha256"],
              "optional_numeric_features": feature_manifest["numeric_features"],
              "feature_manifest_sha256": sha256(features / "manifest.json"),
              "feature_audit": checked}
    if current:
        save_json(repository / "reports/expanded-integrity.json", result)
    return result


@verification_session
def build_expanded(repository_root, output=None):
    repository = Path(repository_root).resolve()
    root = dataset_root(repository)
    _check_schema(repository, root)
    destination = Path(output) if output is not None else root / "data/corrected"
    allowed = (root / "data/corrected").resolve()
    replay = (repository / "reports/replay/expanded").resolve()
    if destination.resolve() not in (allowed, replay):
        raise ValueError("Expanded export must use its cohort directory or isolated replay directory")
    manifest = build_corrected(root, output=destination, original_submission=original_submission(),
                               minimum_packages=MINIMUM_PACKAGES)
    features = root / "data/features" if destination.resolve() == allowed else repository / "reports/replay/expanded-features"
    _finish(repository, root, destination, features, manifest, rebuild=True)
    return manifest


@verification_session
def verify_expanded(repository_root):
    repository = Path(repository_root).resolve()
    root = dataset_root(repository)
    _check_schema(repository, root)
    manifest = verify_corrected(root, original_submission=original_submission(),
                                minimum_packages=MINIMUM_PACKAGES)
    _finish(repository, root, root / "data/corrected", root / "data/features", manifest, rebuild=False)
    return manifest


@verification_session
def reproduce_expanded(repository_root):
    repository = Path(repository_root).resolve()
    original = dataset_root(repository) / "data/corrected"
    verify_expanded(repository)
    replay = repository / "reports/replay/expanded"
    build_expanded(repository, output=replay)
    original_names = {p.name for p in original.iterdir() if p.is_file()}
    replay_names = {p.name for p in replay.iterdir() if p.is_file()}
    compared = {
        name: {"original_sha256": sha256(original / name),
               "replayed_sha256": sha256(replay / name),
               "identical": (original / name).read_bytes() == (replay / name).read_bytes()}
        for name in sorted(original_names & replay_names)
    }
    feature_original = dataset_root(repository) / "data/features"
    feature_replay = repository / "reports/replay/expanded-features"
    feature_names = {p.name for p in feature_original.iterdir() if p.is_file()}
    feature_replay_names = {p.name for p in feature_replay.iterdir() if p.is_file()}
    for name in sorted(feature_names & feature_replay_names):
        compared["features/" + name] = {
            "original_sha256": sha256(feature_original / name),
            "replayed_sha256": sha256(feature_replay / name),
            "identical": (feature_original / name).read_bytes() == (feature_replay / name).read_bytes()}
    file_sets_equal = original_names == replay_names and feature_names == feature_replay_names and bool(feature_names)
    report = {"dataset_root": "datasets/training", "minimum_verified_packages": MINIMUM_PACKAGES,
              "file_sets_equal": file_sets_equal,
              "all_identical": bool(compared) and file_sets_equal
                               and all(item["identical"] for item in compared.values()),
              "files": compared, "publication_permitted": False}
    save_json(repository / "reports/expanded-reproducibility.json", report)
    return report
