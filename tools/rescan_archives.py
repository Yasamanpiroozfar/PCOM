"""Rebuild compact replay bundles from already recorded, hash-checked archives.

No network access and no changes to source archives. Useful after parser fixes.
The acquisition manifest's stored bundle hashes are updated; rebuild the dataset.
"""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcom01.advisories import load_snapshot_archive
from pcom01.io import read_json, save_json, sha256
from pcom01.pipeline import selected_packages


def main():
    path = ROOT / "data/provenance/acquisition.json"
    manifest = read_json(path)
    for label, info in manifest["snapshots"].items():
        archive = ROOT / "data/cache" / (info["commit"]["sha"] + ".tar.gz")
        if sha256(archive) != info["archive_sha256"]:
            raise ValueError(f"Archive digest mismatch: {label}")
        snapshot = load_snapshot_archive(archive, selected_packages(ROOT), info["boundary"],
                                         info["commit"]["sha"], info["commit"]["committed_at"])
        bundle = ROOT / info["bundle_path"]
        save_json(bundle, {"provenance": snapshot.provenance(), "records": snapshot.raw_records()})
        info["bundle_sha256"] = sha256(bundle)
        print(f"{label}: {snapshot.reviewed_files_scanned} reviewed records scanned; {len(snapshot.advisories)} selected retained; {len(snapshot.warnings)} warnings; {len(snapshot.issues)} packages blocked", flush=True)
    save_json(path, manifest)


if __name__ == "__main__":
    main()
