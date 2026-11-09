# PCOM-01 — Homework 3: Updated npm Vulnerability Training Dataset

This README documents the **updated Homework 3 dataset on the `main` branch** (November 9, 2026). The update preserves the official record schema and provides the corrected release-based prediction windows.

**14,840 version records from 685 verified packages**, in the
**224-column official record schema**, plus 20 separately defined numeric features.
Each package's forecast origin is the release of its highest stable semantic
version in the July 2025-June 2026 input window; targets cover the following 90 days.

| File | Contents |
|---|---|
| [Training JSONL](datasets/training/data/corrected/training-records.jsonl) | Typed version records |
| [Training CSV](datasets/training/data/corrected/training-records.csv) | Same records in official column order |
| [Manifest](datasets/training/data/corrected/manifest.json) | Counts, hashes and source bindings |
| [Additional features](datasets/training/data/features/features.csv) | 20 numeric features; join on `purl` |
| [Feature definitions](datasets/training/data/features/feature-spec.json) | Units, windows and missing-value rules |
| [Method](docs/correction-contract.md) | Course requirements, selection and measurement definitions |
| [Validation](reports/correction-audit.md) | Source audit, tests and reproduction evidence |

## Method

- Select the highest stable SemVer within the supplied records. Its publication
  timestamp is origin `T`; records published after `T` are excluded.
- Keep **M0 = June 2026 through M11 = July 2025**. Measurements use observations
  available by `T` within those fixed months, with explicit download-day coverage.
- Count package-wide GHSA IDs using reviewed historical Git snapshots. Inputs
  use severity at `T`; targets count new IDs published in **[T, T + 90 days)**
  with severity at the outcome boundary.
- Retain all five schema targets, including unknown severity. The prediction
  task specifies four outputs: low, moderate, high and critical.
- Keep the 20 additional release, download and advisory features separate from
  the official schema. No outcome information is used to derive them.

The frozen candidate pool contains 1,214 packages from 20 public npm searches
and the retained reference sample. Admission uses release and source completeness,
without selecting on vulnerability outcomes. Original responses, Git object
proofs and source hashes are retained for offline verification.

## Reproduction

Python 3.11+ and its standard library are sufficient. From the repository root:

```text
python -B run.py test
python -B run.py validate-expanded
python -B run.py reproduce-expanded
```

`build-expanded` regenerates the export from retained sources. Reproduction
validates the committed dataset, independently rebuilds it, and compares all
14 core and feature files byte for byte. No package code is installed or executed.

## Source limits

The cohort and npm metadata/download captures are retrospective. Historical GHSA
trees establish reviewed Git mirror state, subject to synchronization delay.
The new-ID guard covers earlier reviewed IDs, not every unreviewed or deleted
entry. Optional unacquired issue/PR fields remain NULL. Multiple version rows
share package-level outcomes; evaluation should split by package.

[GitHub Actions](https://github.com/Yasamanpiroozfar/PCOM/actions) runs the checks.
The annotated [`initial-training-data`](https://github.com/Yasamanpiroozfar/PCOM/tree/initial-training-data)
tag retains the initial submission files.
