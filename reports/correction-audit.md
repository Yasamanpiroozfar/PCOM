# Homework 3 dataset validation

The primary export contains **989 records from 39 packages in 224 columns**.
It uses the highest supplied stable SemVer release as each package's origin,
fixed M0 June 2026-M11 July 2025 inputs observed by that origin, and 90-day targets.
The [method](../docs/correction-contract.md) records the measurement definitions.

## Verification

| Check | Result |
|---|---|
| Tests | 197 passed; zero failures, errors or skips |
| Historical GHSA coverage | 80 boundary snapshots from 78 distinct Git trees |
| Primary source audit | 221,536 field comparisons; zero disagreements |
| Sensitivity source audit | 221,088 comparisons; zero disagreements |
| Combined source audit | 442,624 comparisons; zero disagreements |
| Primary reproduction | All ten export files byte-identical |
| Detailed reproduction | All nine derivation files per scope byte-identical |
| Original data | 990 records and source captures preserved; nine processed files reproduce byte-identically |
| Original source audit | 99,990 comparisons and 614 full advisory documents verified |

Evidence: [tests](correction-tests.json), [source audit](correction-source-audit.json),
[primary replay](correction-reproducibility-primary.json),
[supplied replay](correction-reproducibility-supplied.json),
[sensitivity replay](correction-reproducibility-all-precutoff.json), and
[GitHub Actions](https://github.com/Yasamanpiroozfar/PCOM/actions).

Primary JSONL SHA-256:
`ca796670ce7a4953e9e82feb46c356a678334826ac98cbc7246a246b28909462`.
The [manifest](../data/corrected/manifest.json) binds export files to their sources.

## Sensitivity analysis
The all-precutoff sensitivity view contains 987 records from 38 packages.
It selects yargs 18.0.0 instead of supplied-version anchor 17.7.3 and excludes
both later supplied yargs records. All five training targets remain, including
unknown severity; the course requires four severity outputs for prediction.

## Source limits

npm captures and recovered mirror metadata are retrospective. Historical GHSA
snapshots preserve reviewed Git mirror state, with synchronization and earlier
unreviewed/deleted-ID limitations. Cohort selection is retrospective; optional
unacquired issue/PR measurements remain NULL. Full-month eventual totals are
not substituted for observations available at the release origin.
