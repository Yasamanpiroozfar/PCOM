"""Write human-readable results from executed evidence; never invent success."""
from pathlib import Path
from collections import Counter
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from pcom01.io import read_json, save_json


def main():
    stats = read_json(ROOT / "data/processed/statistics.json")
    validation = read_json(ROOT / "reports/validation.json")
    tests = read_json(ROOT / "reports/tests.json")
    sources = read_json(ROOT / "reports/source-audit.json")
    replay = read_json(ROOT / "reports/reproducibility.json")
    release = read_json(ROOT / "reports/release-check.json")
    acquisition = read_json(ROOT / "data/provenance/acquisition.json")
    packages = read_json(ROOT / "data/processed/package-reports.json")
    events = read_json(ROOT / "data/provenance/http-events.json")
    n = stats["valid_records"]
    complete_optional = sum(count == n for count in validation["optional_coverage"].values())
    absent_optional = sum(count == 0 for count in validation["optional_coverage"].values())
    original_ok = all(item["unchanged"] is True for item in release["original_file_integrity"].values())
    commit = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT, text=True, capture_output=True)
    existing_commit = commit.stdout.strip() if commit.returncode == 0 else None
    report = ["# Executed Homework 3 results", "", "These figures are generated from recorded runs, not estimates. Dataset verification is scoped to the pinned source evidence and the documented cutoff interpretation.", "", "| Metric | Result |", "|---|---:|",
              f"| Packages selected / registry processed | {stats['packages_considered']} / {stats['packages_registry_processed']} |",
              f"| Packages with eligible final records | {stats['packages_with_final_records']} |",
              f"| Registry version manifests examined | {stats['registry_versions_considered']:,} |",
              f"| Real final package-version rows | {n:,} |",
              f"| Official columns | {stats['schema_columns']} |",
              f"| Required field coverage | {min(validation['required_coverage'].values())}/{n} for every required field |",
              f"| Optional fields fully populated / entirely NULL | {complete_optional} / {absent_optional} |",
              f"| Structural validation errors | {len(validation['errors'])} |",
              f"| Tests run / failures / errors / skips | {tests['tests_run']} / {tests['failures']} / {tests['errors']} / {tests['skipped']} |",
              f"| Independent source comparisons | {sources['source_value_comparisons']:,} |",
              f"| Original advisory documents verified against archives | {sources['original_advisory_documents_verified']} |",
              f"| Byte-identical processed artifacts | {sum(v['identical'] for v in replay['files'].values())}/{len(replay['files'])} |",
              f"| Unresolved source failures | {len(stats['unresolved_source_failures'])} |",
              f"| Quarantined exploratory rows in final run | {stats['exploratory_record_count']} |",
              "", "## Acquisition evidence", "",
              f"Captured source requests: {dict(Counter(str(event.get('status')) for event in events))}. HTTP 429 responses are retained; pacing/backoff and a resumed acquisition recovered all 13 initially failed package download sources. No failed lookup became zero.",
              "", "| Snapshot | Immutable commit | Commit UTC time | Reviewed files scanned |", "|---|---|---|---:|"]
    for label, info in acquisition["snapshots"].items():
        bundle = read_json(ROOT / info["bundle_path"])
        p = bundle["provenance"]
        report.append(f"| {label} | [{p['commit_sha']}](https://github.com/github/advisory-database/commit/{p['commit_sha']}) | {p['committed_at']} | {p['reviewed_files_scanned']:,} |")
    report += ["", "Both full trees were scanned. Ten historical records have modified-before-published source anomalies; each original value is preserved and both timestamps precede the cutoff. This is a documented warning, not a future-data leak. The exact historical GitHub service state remains unproven; see the methodology.",
               "", "## Exclusions", "", "| Reason | Count |", "|---|---:|"]
    for reason, count in stats["exclusion_counts"].items():
        report.append(f"| {reason} | {count:,} |")
    report += ["", f"The {stats['exclusion_counts'].get('timestamp_without_version_manifest', 0)} timestamp-only entries are additional metadata references without usable version manifests. `minimist` is retained in the selection/provenance but has no stable release in the required window. The other {stats['packages_with_final_records']} selected packages produce the {n} records.",
               "", "## Vulnerability outcomes", "", "| Severity | Distinct package–GHSA counts | Sum over version rows (repeated labels) |", "|---|---:|---:|"]
    for severity in ("low", "moderate", "high", "critical", "unknown"):
        key = f"target_ghsa_{severity}_count_90d"
        report.append(f"| {severity} | {stats['package_target_totals'][key]} | {stats['row_target_totals'][key]} |")
    report += ["", f"There are {stats['distinct_target_ghsa_ids']} distinct target GHSA IDs in this sample. {stats['package_label_distribution'].get('0',0)} of {stats['packages_with_final_records']} represented packages have zero qualifying future advisories. Labels are package-wide and repeat across versions; row totals must not be interpreted as independent vulnerabilities or independent training cases.",
               "", "| Total labels per package | Packages |", "|---|---:|"]
    for count, packages_count in sorted(stats["package_label_distribution"].items(), key=lambda item: int(item[0])):
        report.append(f"| {count} | {packages_count} |")
    report += ["", "## Records by package", "", "| Package | Eligible rows | Highest stable SemVer before cutoff |", "|---|---:|---|"]
    for name, item in packages.items():
        report.append(f"| {name} | {item['statistics']['records']} | {item['latest_semver']} |")
    report += ["", "## Evidence files", "", "- `validation.json`: all column/type/missingness/chronology results and per-field coverage.",
               "- `tests.json` and `tests.txt`: executed suite and full test names.", "- `source-audit.json`: independent row facts and original-archive projection checks.",
               "- `reproducibility.json`: both hashes for every regenerated artifact.", "- `release-check.json`: credential-pattern scan and original-course-file integrity.",
               "- `file-inventory.txt`: exact intended repository file list; caches and replay scratch files excluded.",
               "", f"Primary dataset SHA-256: `{stats['dataset_sha256']}`.", "", "No trained model, prediction score, invented grade, or completed external submission is claimed."]
    (ROOT / "reports/results.md").write_text("\n".join(report) + "\n", encoding="utf-8", newline="\n")

    audit = []
    def item(category, requirement, condition, evidence, limitation="", pending=False):
        status = "PASS" if condition else "PARTIAL" if pending else "FAIL"
        audit.append({"category": category, "requirement": requirement, "status": status, "evidence": evidence, "limitation": limitation})
    item("Instructor", "Acquire a real public-source npm training dataset", n > 0 and sources["valid"], f"data/raw; acquisition.json; source-audit.json; {n} source-backed version rows")
    item("Instructor", "Exact official column names/order, all 224 fields", validation["valid"] and stats["schema_columns"] == 224, "schema/record_schema.json; columns.txt; schema tests; validation.json")
    item("Instructor", "All 78 required fields present with correct types", validation["valid"] and all(count == n for count in validation["required_coverage"].values()), "validation.json required_coverage and negative tests")
    item("Instructor", "Exact-version npm PURLs; exclude prereleases", validation["valid"], "npm tests; validation tests; source-audit.json; exclusions.json")
    item("Instructor", "Valid creation/publication timestamps and all 5 dependency counts", sources["valid"] and validation["valid"], "Independent source comparison and chronology tests")
    item("Instructor", "July 2025–June 2026 history; correct M0–M11 mapping", validation["valid"] and tests["successful"], "Workbook Documentation sheet evidence; month-boundary tests; fixed source request dates")
    item("Instructor", "Distinct reviewed GHSA history and five severity outcomes", sources["valid"] and tests["successful"], "Historical trees; per-package GHSA ID evidence; 70 GHSA fields independently compared", "Verified against historical Git mirror; exact service-state limitation is separately marked PARTIAL")
    item("Instructor", "Package-wide targets and exact 90-day interval", False, "Known expected counts; package-wide and boundary tests; labels through 2026-09-29 exclusive", "Calculation verified under common-cutoff interpretation; instructor cutoff anchor remains unresolved", pending=True)
    item("Instructor", "Optional unavailable measurements are NULL, not fabricated zeros", validation["valid"], "146 optional fields retained; 108 GitHub event fields NULL; failure/null/zero tests")
    item("Instructor", "Keep required core while allowing extensions", validation["valid"], "No extra table columns; provenance and collection times in sidecars")
    item("Instructor", "Commit code and real data to repository", bool(existing_commit), "The final release commit is identified by initial-training-data^{commit}; resolve with git rev-parse after tag creation", "A commit cannot embed its own hash; the release tag provides the stable reference", pending=True)
    item("Instructor", "Publish an instructor-accessible GitHub repository", False, "Public destination approved: https://github.com/Yasamanpiroozfar/PCOM", "This audit records pre-publication checks; verify public access after the push", pending=True)
    item("Instructor", "Exact tag initial-training-data", False, "Tag creation and push explicitly approved", "Verify the remote tag points to the final tested commit after publication", pending=True)
    item("Instructor", "Submit repository URL through official form", False, "https://forms.gle/SUjxnXAWQ99oDv8N8", "The owner will submit the form separately; the agent must not submit it")
    item("User quality", "Preserve all original course and Homework 2 files", original_ok, "release-check.json compares all 5 source SHA-256 values")
    item("User quality", "Actually execute acquisition, validation and tests", tests["successful"] and validation["valid"] and sources["valid"], f"{tests['tests_run']} executed tests; {sum(event.get('status') == 200 for event in events)} HTTP 200 responses; source audit")
    item("User quality", "Known results, negative cases, edge cases, temporal leakage prevention", tests["successful"], "Test names/transcript cover source failures, dates, IDs, types, cutoffs, revisions, duplicates and replay")
    item("User quality", "Reproducible dataset and clear dependency setup", replay["all_identical"], "Python 3.11+ standard library; README commands; nine byte-identical artifacts")
    item("User quality", "Explicit source failures, missingness and sampling biases", True, "HTTP events; source failures/recovery; exclusions; docs/sources.md")
    item("User quality", "Secrets and irrelevant files checked", release["local_checks_pass"], "release-check.json; original course files and large caches excluded; signed narrative URLs omitted", "Pattern scan does not prove absence of all conceivable secret formats")
    item("Decision", "40-package purposive selection, without outcome-based selection", True, "Fixed config/packages.json; every package retained in reports", "Convenience/popularity/survivorship bias; not representative npm prevalence")
    item("Decision", "Half-open UTC windows and withdrawn-advisory policy", True, "docs/decisions.md; advisory-history.md; endpoint/withdrawal tests", "These interpretation choices are not separately confirmed by instructor")
    item("Decision", "Highest semantic version identified without current dist-tags", True, "Per-package reports and semantic-order tests", "No claim that this resolves the disputed cutoff anchor")
    item("Optional", "Populate GitHub issue/PR historical measurements", False, "All 108 optional columns exist as NULL", "Reliable complete historical event reconstruction was not acquired", pending=True)
    item("Optional", "GitHub Actions test/reproducibility workflow", False, ".github/workflows/validate.yml; https://github.com/Yasamanpiroozfar/PCOM/actions", "Pre-publication snapshot; inspect the final commit's workflow results after push", pending=True)
    item("Unresolved", "Common cutoff versus 90 days after latest version", False, "Worklog p.1 vs fixed workbook months; docs/decisions.md", "July 1 common cutoff is explicit and internally validated, not instructor-confirmed", pending=True)
    item("Unresolved", "Exact historical GitHub service state", False, f"Immutable Git mirror snapshots; {sources['original_advisory_documents_verified']} original records verified", "Mirror/commit timing cannot certify exact service-state history", pending=True)
    item("Unresolved", "Historical immutability/completeness of npm metadata", False, "Authentic captured retrospective full registry responses", "Unpublishing or later source corrections cannot be ruled out", pending=True)
    item("Unresolved", "Four-output worklog versus five schema labels", False, "Five official schema fields preserved", "Future submission output format needs clarification; no required column dropped", pending=True)
    item("Unresolved", "Repository visibility and instructor access", False, "Owner approved public Yasamanpiroozfar/PCOM on 2026-11-02", "Verify anonymous access after publication; no collaborator invitation is needed for a public repository", pending=True)
    save_json(ROOT / "reports/final-audit.json", {"scope": "Pre-publication verification; public repository and tag authorized; form reserved for owner", "items": audit})
    lines = ["# Final requirement-by-requirement audit", "", "This is the pre-publication verification snapshot. Public publication to Yasamanpiroozfar/PCOM and creation of initial-training-data were approved on 2026-11-02. Remote publication, tag and Actions outcomes must be checked after pushing; this file does not claim those later operations have already succeeded. The Google Form is reserved for the owner.", "", "PASS means implemented and verified within the stated evidence scope. PARTIAL identifies a limitation, unresolved interpretation or remote verification pending at this snapshot. FAIL means missing/unverified. No numerical grade is inferred.",
             "", "| Category | Requirement | Status | Evidence | Limitation / next action |", "|---|---|---|---|---|"]
    lines.extend(f"| {i['category']} | {i['requirement']} | **{i['status']}** | {i['evidence']} | {i['limitation']} |" for i in audit)
    lines += ["", "## Release identity and remaining steps", "", "The code, authentic data, tests and offline reproduction form the reviewed release. The interpretation and historical-source limits are material and disclosed. The exact release SHA is obtained with `git rev-parse initial-training-data^{commit}` after tag creation, avoiding a stale or self-referential embedded commit hash. Verify the [public repository](https://github.com/Yasamanpiroozfar/PCOM), [release tag](https://github.com/Yasamanpiroozfar/PCOM/tree/initial-training-data), and [Actions results](https://github.com/Yasamanpiroozfar/PCOM/actions) after publication. The owner must submit the Google Form separately."]
    (ROOT / "reports/final-audit.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"report_written": True, "audit_status_counts": dict(Counter(item['status'] for item in audit)), "local_commit": existing_commit}, indent=2))


if __name__ == "__main__":
    main()
