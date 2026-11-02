# Final requirement-by-requirement audit

This is the pre-publication verification snapshot. Public publication to Yasamanpiroozfar/PCOM and creation of initial-training-data were approved on 2026-11-02. Remote publication, tag and Actions outcomes must be checked after pushing; this file does not claim those later operations have already succeeded. The Google Form is reserved for the owner.

PASS means implemented and verified within the stated evidence scope. PARTIAL identifies a limitation, unresolved interpretation or remote verification pending at this snapshot. FAIL means missing/unverified. No numerical grade is inferred.

| Category | Requirement | Status | Evidence | Limitation / next action |
|---|---|---|---|---|
| Instructor | Acquire a real public-source npm training dataset | **PASS** | data/raw; acquisition.json; source-audit.json; 990 source-backed version rows |  |
| Instructor | Exact official column names/order, all 224 fields | **PASS** | schema/record_schema.json; columns.txt; schema tests; validation.json |  |
| Instructor | All 78 required fields present with correct types | **PASS** | validation.json required_coverage and negative tests |  |
| Instructor | Exact-version npm PURLs; exclude prereleases | **PASS** | npm tests; validation tests; source-audit.json; exclusions.json |  |
| Instructor | Valid creation/publication timestamps and all 5 dependency counts | **PASS** | Independent source comparison and chronology tests |  |
| Instructor | July 2025–June 2026 history; correct M0–M11 mapping | **PASS** | Workbook Documentation sheet evidence; month-boundary tests; fixed source request dates |  |
| Instructor | Distinct reviewed GHSA history and five severity outcomes | **PASS** | Historical trees; per-package GHSA ID evidence; 70 GHSA fields independently compared | Verified against historical Git mirror; exact service-state limitation is separately marked PARTIAL |
| Instructor | Package-wide targets and exact 90-day interval | **PARTIAL** | Known expected counts; package-wide and boundary tests; labels through 2026-09-29 exclusive | Calculation verified under common-cutoff interpretation; instructor cutoff anchor remains unresolved |
| Instructor | Optional unavailable measurements are NULL, not fabricated zeros | **PASS** | 146 optional fields retained; 108 GitHub event fields NULL; failure/null/zero tests |  |
| Instructor | Keep required core while allowing extensions | **PASS** | No extra table columns; provenance and collection times in sidecars |  |
| Instructor | Commit code and real data to repository | **PASS** | The final release commit is identified by initial-training-data^{commit}; resolve with git rev-parse after tag creation | A commit cannot embed its own hash; the release tag provides the stable reference |
| Instructor | Publish an instructor-accessible GitHub repository | **PARTIAL** | Public destination approved: https://github.com/Yasamanpiroozfar/PCOM | This audit records pre-publication checks; verify public access after the push |
| Instructor | Exact tag initial-training-data | **PARTIAL** | Tag creation and push explicitly approved | Verify the remote tag points to the final tested commit after publication |
| Instructor | Submit repository URL through official form | **FAIL** | https://forms.gle/SUjxnXAWQ99oDv8N8 | The owner will submit the form separately; the agent must not submit it |
| User quality | Preserve all original course and Homework 2 files | **PASS** | release-check.json compares all 5 source SHA-256 values |  |
| User quality | Actually execute acquisition, validation and tests | **PASS** | 110 executed tests; 84 HTTP 200 responses; source audit |  |
| User quality | Known results, negative cases, edge cases, temporal leakage prevention | **PASS** | Test names/transcript cover source failures, dates, IDs, types, cutoffs, revisions, duplicates and replay |  |
| User quality | Reproducible dataset and clear dependency setup | **PASS** | Python 3.11+ standard library; README commands; nine byte-identical artifacts |  |
| User quality | Explicit source failures, missingness and sampling biases | **PASS** | HTTP events; source failures/recovery; exclusions; docs/sources.md |  |
| User quality | Secrets and irrelevant files checked | **PASS** | release-check.json; original course files and large caches excluded; signed narrative URLs omitted | Pattern scan does not prove absence of all conceivable secret formats |
| Decision | 40-package purposive selection, without outcome-based selection | **PASS** | Fixed config/packages.json; every package retained in reports | Convenience/popularity/survivorship bias; not representative npm prevalence |
| Decision | Half-open UTC windows and withdrawn-advisory policy | **PASS** | docs/decisions.md; advisory-history.md; endpoint/withdrawal tests | These interpretation choices are not separately confirmed by instructor |
| Decision | Highest semantic version identified without current dist-tags | **PASS** | Per-package reports and semantic-order tests | No claim that this resolves the disputed cutoff anchor |
| Optional | Populate GitHub issue/PR historical measurements | **PARTIAL** | All 108 optional columns exist as NULL | Reliable complete historical event reconstruction was not acquired |
| Optional | GitHub Actions test/reproducibility workflow | **PARTIAL** | .github/workflows/validate.yml; https://github.com/Yasamanpiroozfar/PCOM/actions | Pre-publication snapshot; inspect the final commit's workflow results after push |
| Unresolved | Common cutoff versus 90 days after latest version | **PARTIAL** | Worklog p.1 vs fixed workbook months; docs/decisions.md | July 1 common cutoff is explicit and internally validated, not instructor-confirmed |
| Unresolved | Exact historical GitHub service state | **PARTIAL** | Immutable Git mirror snapshots; 614 original records verified | Mirror/commit timing cannot certify exact service-state history |
| Unresolved | Historical immutability/completeness of npm metadata | **PARTIAL** | Authentic captured retrospective full registry responses | Unpublishing or later source corrections cannot be ruled out |
| Unresolved | Four-output worklog versus five schema labels | **PARTIAL** | Five official schema fields preserved | Future submission output format needs clarification; no required column dropped |
| Unresolved | Repository visibility and instructor access | **PARTIAL** | Owner approved public Yasamanpiroozfar/PCOM on 2026-11-02 | Verify anonymous access after publication; no collaborator invitation is needed for a public repository |

## Release identity and remaining steps

The code, authentic data, tests and offline reproduction form the reviewed release. The interpretation and historical-source limits are material and disclosed. The exact release SHA is obtained with `git rev-parse initial-training-data^{commit}` after tag creation, avoiding a stale or self-referential embedded commit hash. Verify the [public repository](https://github.com/Yasamanpiroozfar/PCOM), [release tag](https://github.com/Yasamanpiroozfar/PCOM/tree/initial-training-data), and [Actions results](https://github.com/Yasamanpiroozfar/PCOM/actions) after publication. The owner must submit the Google Form separately.
