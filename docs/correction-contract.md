# Homework 3 dataset method

The primary policy selects the highest stable SemVer among the supplied
July 2025-June 2026 records, then derives inputs at that release and outcomes
for the following 90 days. The source files inspected on November 8, 2026,
exact quotations, workbook cells and SHA-256 hashes are recorded in
[source evidence](../schema/correction-evidence.json).

## Course requirements

The Class Worklog, page 1, defines the input as:

> One record for each package version
>
> Excluding prerelease versions
>
> Over the previous 12 months (July 2025 to June 2026)

It specifies the output and horizon:

> Count of vulnerabilities for CVSS score low, moderate, high, critical
>
> Expected time frame is 90 days after the latest package version
>
> Latest = highest semantic version (not timestamp)

The Homework PDF, pages 1-2, requires the PCOM-01 record schema, a training
dataset from public sources, code and data committed to the repository, and the
`initial-training-data` tag. It also states:

> You can (should!) keep updating the data after this

The workbook expands to 224 columns: 78 required and 146 nullable.

| Workbook location | Measurement definition |
|---|---|
| Documentation!B2:B5 | M0 = June 2026 through M11 = July 2025 |
| Schema!H18 | Sum available daily download observations; no extrapolation |
| Schema!H21 | Count observed UTC days, including reported zero-download days |
| Schema!H56:H60 | Lifetime GHSA IDs published before prediction; severity at prediction |
| Schema!H62, H65, H68, H71, H74 | GHSA IDs by fixed publication month; severity at prediction |
| Schema!H78:H82 | New package-wide GHSA IDs during the following 90 days; severity at outcome end |

Five training target columns include unknown severity. The Worklog's four
prediction outputs are a separate requirement; unknown is retained in training
without redistribution.

The supplied November 2 forum screenshot permits choosing package-wide or
version-specific GHSA counting. This implementation uses package-wide counts
for features and targets, consistent with the workbook's descriptions.

## Version selection and time boundaries

The primary candidate set is the supplied fixed-window input. The Worklog's
latest-version rule follows that input description, supporting this scope.
SemVer precedence is numeric; prereleases are excluded and build metadata does
not increase precedence. Unknown timestamps and unresolved ties fail selection.

Origin `T` is the selected release's publication timestamp. July 1, 2026 is
the supplied cohort's exclusive upper date limit.

The broader all-precutoff stable-release universe is a sensitivity analysis.
The scopes select different anchors for yargs:

| Scope | Version | Origin, UTC | Outcome end, UTC |
|---|---|---|---|
| Primary: supplied | 17.7.3 | 2026-06-19T02:08:41.275Z | 2026-09-17T02:08:41.275Z |
| All-precutoff sensitivity | 18.0.0 | 2025-05-27T14:27:19.495Z | 2025-08-25T14:27:19.495Z |

In the sensitivity view, both supplied yargs versions, 16.2.2 and 17.7.3, occur
after the origin and are excluded. Selecting a maximum from the completed input
window is retrospective cohort selection, not a prospectively known cohort.

## Input and outcome measurements

Monthly identities remain fixed. Complete eventual monthly totals would include
future information for earlier origins; origin-known observations within those
calendar buckets avoid that leakage. Partial downloads are explicitly supported
by H18/H21, while GHSA fields use the historical state at prediction.

- GHSA inputs count distinct qualifying IDs from the verified origin reviewed
  snapshot, published before `T`, with severity at `T`. Monthly features partition
  those IDs by fixed publication month. A future bucket's zero means no qualifying
  origin-known IDs; missing historical evidence is not converted to zero.
- Downloads include only valid observed UTC days whose end is at or before `T`.
  Coverage counts accompany totals; an intraday release day is excluded.
- Stable-release activity and version manifests are limited to publication at
  or before `T`, including the selected anchor at `T`.
- Targets use a separate reviewed snapshot before the outcome boundary. Count
  qualifying new package-wide IDs published in `[T, T + 90 days)`, classified
  using severity at the window end and that snapshot's qualification state.
  Deduplicate per package and exclude IDs already in the origin reviewed corpus
  even if later publication-date revisions place them inside the target window.

The half-open target interval is the implementation's explicit boundary convention.

## Sources and coverage

The npm captures contain timestamps but omit manifests for `axios@0.30.4`,
`axios@1.14.1` and `chalk@5.6.1`. Retained public npm mirror responses supply these
manifests after direct npm lookup failures. Timestamps remain sourced from the
captures. The [inventory](../data/provenance/release-manifests.json)
records source responses and hashes.

The reconstructed cohort has 993 records. Four later manifests are excluded:
`express@4.22.1`, `express@4.22.2`, `undici@6.27.0` and `undici@7.28.0`.
The primary export has **989 records / 39 packages / 224 columns**; sensitivity
has **987 records / 38 packages**. All 80 requested historical boundaries were
captured from 78 distinct Git trees.

## Evidence limits

npm responses are retrospective and may contain later metadata corrections or
omit removed releases. Mirror recovery does not establish release-time metadata
immutability. GHSA trees establish recorded Git mirror state, subject to mirror
lag; the earlier-ID guard does not reconstruct every prior unreviewed, malware
or deleted entry. Optional unacquired issue/PR histories remain NULL.

Online course-document revisions could not be verified. The inspected PDFs,
workbook and supplied screenshots are identified by hashes in the evidence file.
The implemented scope and boundary conventions are documented interpretations.

[Executed verification](../reports/correction-audit.md) covers tests, independent
source recounts and reproduction.
