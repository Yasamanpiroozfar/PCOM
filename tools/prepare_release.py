"""Inspect the dedicated local submission; does not publish, commit, or tag."""
from __future__ import annotations
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcom01.io import save_json, now

ORIGINALS = {
    "PCOM Homework [Public].pdf": "3a6a6b1679090ef83678016fb5c33ac8284b0a246519c4c1765677815b47f5e7",
    "PCOM Class Worklog [Public].pdf": "46e489fd04004966fbb8302836206cf080a5e3b20f0ef47b627a1e6314cd6b18",
    "PCOM-01 Record Schema [Public].xlsx": "243a32bcd9e9b6d23cbde133a790f8e81ef518ece6e1e408adbb39815f033413",
    "PCOM Organization [Public].xlsx": "923c27780695afe414069d36e441cd0e906bd9b4d670073b2c577cf864e1d4ed",
    "PCOM_Exercise_2_Submission.zip": "437758f42cfb7fd9e24baa9614993ce0ede410f93c6ff6c9dde678808e998b99",
}


def release_files():
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        if not path.is_file() or any(part in {".git", "__pycache__", ".venv"} for part in relative.parts):
            continue
        if relative.parts[:2] in {("data", "cache"), ("reports", "replay")} or path.suffix == ".part":
            continue
        yield path


def main():
    # Canonical LF is required so hashes survive Windows/Linux Git checkouts.
    for path in release_files():
        if path.suffix in {".py", ".json", ".jsonl", ".csv", ".txt", ".md", ".toml", ".yml"} or path.name in {".gitattributes", ".gitignore"}:
            raw = path.read_bytes()
            normalized = raw.replace(b"\r\n", b"\n")
            if normalized != raw:
                path.write_bytes(normalized)
    patterns = {
        "github_token": rb"gh[pousr]_[A-Za-z0-9]{36,255}",
        "github_fine_grained_token": rb"github_pat_[A-Za-z0-9_]{70,255}",
        "npm_token": rb"npm_[A-Za-z0-9]{36}",
        "aws_access_key": rb"(?:AKIA|ASIA)[A-Z0-9]{16}",
        "private_key": rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    }
    findings, oversized, copied_originals, scanned = [], [], [], 0
    for path in release_files():
        relative = path.relative_to(ROOT).as_posix()
        if path.name in ORIGINALS:
            copied_originals.append(relative)
        if path.stat().st_size > 50 * 1024 * 1024:
            oversized.append(relative)
        raw = path.read_bytes()
        if path.suffix == ".gz":
            raw = gzip.decompress(raw)
        scanned += 1
        for kind, expression in patterns.items():
            matches = list(re.finditer(expression, raw))
            if matches:
                # Never copy a suspected secret into a report or terminal.
                findings.append({"path": relative, "kind": kind, "count": len(matches)})
    originals = {}
    for name, expected in ORIGINALS.items():
        path = ROOT.parent / name
        actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None
        originals[name] = {"expected_sha256": expected, "actual_sha256": actual,
                           "unchanged": actual == expected if actual else None}
    report = {"executed_at": now(), "files_scanned": scanned,
              "credential_pattern_findings": findings, "files_over_50_mib": oversized,
              "original_course_files_copied_into_repository": copied_originals,
              "original_file_integrity": originals,
              "local_checks_pass": not findings and not oversized and not copied_originals and all(v["unchanged"] is not False for v in originals.values()),
              "limitations": "Pattern scan plus explicit file inventory review is not proof that every conceivable secret format is absent.",
              "publication": {"github_owner_verified": "Yasamanpiroozfar", "proposed_repository": "PCOM-01",
                              "visibility": "awaiting owner approval", "published": False, "submission_tag_created": False, "form_submitted": False}}
    save_json(ROOT / "reports/release-check.json", report)
    inventory = ROOT / "reports/file-inventory.txt"
    inventory.touch(exist_ok=True)
    inventory.write_text("\n".join(path.relative_to(ROOT).as_posix() for path in release_files()) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, indent=2))
    return 0 if report["local_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
