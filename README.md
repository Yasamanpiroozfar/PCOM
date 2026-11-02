# PCOM-01 Homework 3 — Initial npm training data

A reproducible acquisition and validation project for FAU Erlangen–Nürnberg's
PCOM-01 Prediction Competition. The submission follows the supplied official
224-column record schema: 78 required fields and 146 nullable fields. It uses
real npm metadata, recorded npm daily download observations, and historical
GitHub-reviewed GHSA snapshots. Synthetic records exist only in automated tests.

**Status:** local submission candidate; publication, the `initial-training-data`
tag, and Google Form submission require the owner's explicit approval. See
[`reports/final-audit.md`](reports/final-audit.md) for the final requirement audit
and [`reports/results.md`](reports/results.md) for executed results. No grade is
claimed or guaranteed.

## Quick reproduction

Requirements: Python **3.11 or newer**, with its standard library. No npm install,
package execution, API credentials, or third-party Python packages are needed.
Run these commands from this project's directory:

```text
python -B run.py test
python -B run.py build
python -B run.py validate
python -B run.py reproduce
```

`build` verifies hashes of the committed source captures and rebuilds all processed
artifacts. `reproduce` builds separately in `reports/replay/` and compares every
processed file byte for byte. Tests report both their transcript and machine-readable
outcome under `reports/`. Some Windows sandboxes deny temporary-directory access;
that is an execution-environment failure, not a passing test. Run in a normal
terminal if necessary.

To acquire public sources in a **fresh checkout**:

```text
python -B run.py acquire
python -B run.py build
python -B run.py validate
python -B run.py test
python -B run.py reproduce
```

The committed captures are reused after hash verification. To independently
re-download sources, make a separate copy/checkout and run
`python -B run.py acquire --refresh` there. Do not overwrite your archived release.
The fixed historical dates remain unchanged. Live npm metadata/download responses
can change; reacquisition is not a promise of byte-identical upstream responses.
Exact reproduction uses the committed, hashed captures. GitHub archives are
identified by immutable commit SHAs; the acquisition manifest records their hashes.
The large full archives are local cache files and are intentionally not committed.

GitHub's public API normally works without a token. If rate-limited, wait for the
reported reset or set `GITHUB_TOKEN` in your environment. Never place it in a file,
command argument, source URL, or Git commit. The client uses bounded retries,
explicit failure reporting, npm download pacing, and validated pagination.

## Experimental contract and its limits

- History: **2025-07-01 inclusive to 2026-07-01 exclusive**, UTC.
- `M0` is June 2026; `M11` is July 2025, exactly as the workbook specifies.
- Working prediction cutoff: **2026-07-01T00:00:00.000Z**.
- Outcomes: **2026-07-01 inclusive to 2026-09-29 exclusive**, exactly 90 days.
- All five outcome fields, including unknown severity, are preserved.
- Every row identifies one exact stable npm version published in the history
  window. Package-wide measurements and labels repeat across its versions.

The common cutoff is an **explicit interpretation**, not a confirmed instructor
clarification. The worklog also says 90 days after the highest-semantic-version
release, which cannot silently replace the fixed monthly schema. The per-package
reports identify that highest stable version without using today's `dist-tags`.
Read [`docs/decisions.md`](docs/decisions.md) before using the dataset.

**Do not randomly split version rows into train/test sets.** Multiple versions of
one package share the same target and many features. Split/group by package, and
use additional time windows for temporal evaluation. This one-cutoff initial
dataset is neither a representative npm survey nor evidence of model performance.

## Data and provenance

| Location | Purpose |
|---|---|
| `config/packages.json` | Frozen 40-package selection by software role; no outcome-based selection |
| `schema/record_schema.json` | Ordered contract, source cells, constraints, and workbook SHA-256 |
| `schema/columns.txt` | Exact 224 column names in submission order |
| `data/raw/registry/*.json.gz` | Full recorded npm registry documents |
| `data/raw/downloads/*.json.gz` | Recorded daily download responses |
| `data/raw/advisories-*.json.gz` | Historical OSV measurement fields, original-document hashes, and complete-scan inventories |
| `data/provenance/acquisition.json` | URLs, acquisition times, cutoffs, commit identifiers, source hashes |
| `data/provenance/http-events.json` | Actual successes, retries, and failures, without credentials |
| `data/processed/training.jsonl` | Primary typed dataset; JSON `null` means missing |
| `data/processed/training.csv` | Same ordered dataset; empty cell means missing, `0` means zero |
| `data/processed/advisory-evidence.json` | Exact GHSA IDs behind each severity/time bucket |
| `data/processed/package-reports.json` | Per-package version selection, warnings, and highest SemVer |
| `data/processed/exclusions.json` | Every recorded exclusion and its reason |
| `data/processed/exploratory.json` | Quarantined partial records, never mixed into final training data |
| `data/processed/statistics.json` | Coverage and label distributions at both row and package levels |
| `reports/` | Actual validation, tests, reproducibility evidence, and final audit |

Optional GitHub issue/pull-request histories are left NULL where a complete
historical reconstruction has not been acquired. Current counters are not used
as historical measurements. No missing measurement is converted to zero.
Historical download totals are sums over reported days only, without extrapolation;
their observed-day counts distinguish complete and partial coverage.

## Methodology and source documentation

- [Decisions, uncertainty, and requirement priority](docs/decisions.md)
- [npm metadata and dependency methodology](docs/npm-methodology.md)
- [Historical advisory reconstruction](docs/advisory-history.md)
- [Data sources and sampling limitations](docs/sources.md)
- [Final requirement audit](reports/final-audit.md)

Course source files and the previous Homework 2 submission are preserved outside
this dedicated project and excluded from its repository. To regenerate the
schema contract when those original files are available in the parent folder:

```text
python -B tools/extract_course_contract.py
```

This reads the workbooks as ZIP/XML without saving or modifying them. The exact
source hashes and worksheet evidence are recorded under `schema/`.

## Submission steps

After reviewing the final audit, approve the intended GitHub owner/repository and
visibility. Publish the reviewed commit and create the exact annotated tag
`initial-training-data` only after approval. Verify that both remote commit and
tag resolve to the reviewed version, and that the instructor can access it.
Then submit the repository URL through the official
[Homework 3 Google Form](https://forms.gle/SUjxnXAWQ99oDv8N8).
Neither a prepared repository nor a successful push proves that the form was submitted.

Implementation and review were prepared with AI assistance. The recorded data,
source provenance, and executed tests are provided for independent verification;
the student should be able to explain the methodological choices and limitations.
