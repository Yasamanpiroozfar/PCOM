# PCOM-01 Homework 3: npm vulnerability training data

The dataset contains **989 version records from 39 packages**, using
all **224 official schema columns**. Each package's forecast starts at the release
of its highest stable semantic version among the supplied July 2025-June 2026
records and covers the following 90 days.

## Dataset and evidence

| File | Contents |
|---|---|
| [Training JSONL](data/corrected/training-records.jsonl) | Typed primary dataset |
| [Training CSV](data/corrected/training-records.csv) | Same records in official column order |
| [Export manifest](data/corrected/manifest.json) | File hashes, sources and validation bindings |
| [Method](docs/correction-contract.md) | Course requirements and measurement definitions |
| [Validation](reports/correction-audit.md) | Tests, independent source checks and reproduction |

## Method

- Select the highest stable SemVer **within the supplied records**, rather than
  the most recently published version. Its publication timestamp is origin `T`.
- Keep the fixed calendar: **M0 = June 2026 through M11 = July 2025**. Features
  use observations available by `T`; months are not shifted to rolling offsets.
- Count package-wide GHSA IDs from the historical reviewed snapshot at `T`,
  using publication before `T` and severity at `T`. Monthly counts group those
  IDs by their fixed publication month. Future buckets represent zero known IDs,
  not zero eventual advisories; unavailable source evidence remains missing.
- Sum download observations only for UTC days ending by `T`, retaining the
  observed-day coverage. Exclude version manifests published after `T`.
- Derive targets from a separate historical snapshot at `T + 90 days`, counting
  qualifying new IDs published in **[T, T + 90 days)**, with severity at the end.
- Retain all five training targets, including unknown severity. The course
  requires four prediction outputs: low, moderate, high and critical counts.

## Reproduction

Requires Python 3.11+ and its standard library. Run from the repository directory:

```text
python -B run.py test
python -B run.py build-corrected
python -B run.py validate-corrected
python -B run.py reproduce-corrected
```

The build independently audits the derivation before export. Validation recounts
source evidence and checks exported bytes; reproduction compares all ten export
artifacts. Detailed derivation checks use `validate-release` and
`reproduce-release`, both defaulting to the supplied-version policy.

A broader all-precutoff SemVer scope is retained as sensitivity analysis:

```text
python -B run.py build-release --scope all-precutoff
python -B run.py reproduce-release --scope all-precutoff
```

This produces 987 records from 38 packages. For yargs, the primary anchor is
17.7.3 (June 19, 2026); the broader scope selects 18.0.0 (May 27, 2025), before
both supplied yargs records. Full dates and windows are in the method document.

## Verification and source limits

**197 tests pass.** Independent audits compare **221,536 primary fields** and
**442,624 fields across both scopes**, with zero disagreements. All ten primary
export files and nine derivation files per scope reproduce byte for byte.
The historical sources cover 80 boundary snapshots from 78 distinct Git trees.

Retained source responses and hashes support exact reproduction. npm metadata
and downloads are retrospective captures, not immutable release-time exports.
The three recovered manifests are attributed to a public npm mirror; timestamps
come from the original npm captures. GHSA trees preserve Git mirror state, subject
to synchronization delay. The new-ID guard covers earlier reviewed IDs, not every
historical unreviewed, malware or deleted entry. Cohort selection is retrospective.
Optional unacquired issue/PR fields remain NULL; evaluation should group by package.

## Releases

[GitHub Actions](https://github.com/Yasamanpiroozfar/PCOM/actions) records validation
and reproduction runs. The annotated
[`initial-training-data`](https://github.com/Yasamanpiroozfar/PCOM/tree/initial-training-data)
tag identifies the initial submission. Its data and source captures remain
available separately from the current export.
