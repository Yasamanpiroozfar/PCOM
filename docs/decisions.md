# Interpretation register

Authority order: official Record Schema; current Homework 3 instructions; latest
Class Worklog decisions; course schedule; older introductory proposals. This
register distinguishes requirements from implementation choices. It does not
claim instructor approval of unresolved choices.

| Item | Evidence | Interpretation implemented | Remaining uncertainty |
|---|---|---|---|
| Ecosystem | Homework PDF p.1; worklog p.1 | npm exclusively | None |
| Record contract | Schema C5:H82 | All 224 fields, 78 required, 146 nullable, ordered as workbook; expand ellipses | None about field names/order |
| History | Documentation B2/B3/B5; worklog p.1 | July 2025–June 2026, complete UTC calendar months, M0 newest | None about month identity |
| Cutoff | Schema says "at prediction" without a timestamp column | Common cutoff July 1, 2026 at 00:00 UTC, immediately after all required input months | Worklog's literal latest-release anchor remains unconfirmed |
| Latest version | Worklog p.1: highest semantic version, not latest timestamp | Compute highest stable SemVer published before cutoff from all registry timestamps; report ties/unavailable evidence | Does not redefine the cutoff; records remain all eligible versions |
| Outcomes | Schema H78:H82 | [cutoff, cutoff + 90 days), ending September 29 at 00:00 UTC; package-wide distinct new GHSA IDs | Endpoint inclusion is an explicit half-open-interval choice |
| Five vs four outputs | Schema C78:C82 vs worklog p.1 | Preserve all five labels including unknown; do not silently drop it | Future prediction-format instructions may request a four-vector |
| Collection time | Worklog October 26 metadata notes | Per-source fetched_at in sidecar manifest, not an extra official column | Schema has no dedicated collection/prediction timestamp field |
| Qualifying advisories | Schema H56:H82: GitHub-reviewed/npm | Complete historical reviewed tree, explicit reviewed flag, npm mapping, not withdrawn as of boundary | Exact GitHub web/API state and mirror synchronization are not proven |
| New advisories | Schema H78:H82 says distinct new GHSA IDs | Publication within outcome window; an ID already present in historical reviewed corpus cannot become new merely by date revision | Later reclassification/mapping is separate from new publication |
| Unavailable values | Workbook constraints | Required unknowns quarantine rows; optional unknowns are NULL; never missing-to-zero | Coverage limitations remain visible |
| Older 18-month proposal | Worklog pp.7–8 vs current p.1 | Do not use 18 months or a one-month outcome | Superseded concept is not silently combined with current task |
| Inconsistent example | Schema F6/F7 | Do not use creation-after-publication example as data | Report source example defect; validate real chronological consistency |

## Defensible scope of the historical claim

The advisory features use only records from a full Git tree whose selected commit
precedes the input cutoff. The label tree precedes the outcome end. Later severity,
review status, mapping, and publication revisions cannot alter the historical
feature tree. The exact public GitHub service state at those instants is not
observable from Git timestamps alone: delayed mirroring or rewritten history can
matter. The dataset is verified **against the recorded historical Git mirror**, not
certified as an exact historical export of every GitHub service.

npm version records and day-specific downloads are authentic retrospective source
responses collected on the acquisition dates. The registry is not an archived
as-of-cutoff database. Later unpublishing, corrections, or metadata mutations may
affect coverage. No present-day dist-tag, issue total, download total outside the
specified dates, or future vulnerability outcome is used as an input feature.

The instructor's literal latest-release interpretation would require a revised
experimental cutoff policy and refreshed advisory snapshots, potentially different
per package. That interpretation has not been declared satisfied by the common
cutoff implementation. It is marked PARTIAL in the audit.

## Missingness and excluded data

No GHSA lookup failure is represented as a verified zero. Zero counts require a
complete reviewed-corpus scan covering the selected package. Optional API failure
leaves NULL values with a source failure record. Zero observed download days means
known coverage of zero days, and the corresponding download total is NULL.
Issues discovered in selected required advisory records quarantine the affected
package unless the source evidence justifies a documented treatment of that issue.

The final table's repeated package-wide labels are not independent samples.
Any later model evaluation must group versions of the same package together.
