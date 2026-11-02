# Historical advisory methodology

## Contract and explicit interpretation

The supplied `PCOM-01 Record Schema [Public].xlsx`, `Schema!C56:H82`, requires
GitHub-reviewed GHSA counts. Historical lifetime and monthly features use severity
at prediction; five outcome labels use severity at the end of a 90-day window.
The matching unit is the npm package, across **any affected version**, and the
counting unit is a distinct GHSA ID. CVE aliases are not the counting unit.

This implementation sets the prediction boundary to **2026-07-01T00:00:00Z**,
immediately after the prescribed historical months. This is a documented project
interpretation, not an instructor-confirmed resolution of the worklog's
latest-version publication anchor. All historical inputs precede this boundary.
M0 is June 2026; M11 is July 2025. Each calendar-month interval includes its first
instant and excludes the start of the next month. The outcome interval is
**[2026-07-01T00:00:00Z, 2026-09-29T00:00:00Z)**, exactly 90 UTC days. Choosing
half-open intervals avoids overlapping adjacent windows; endpoint inclusion is
not specified by the instructor.

All five schema severity columns, including unknown, are retained. The worklog's
four-output wording does not remove a required schema column. Qualification is
interpreted as an explicitly GitHub-reviewed GHSA present in the historical
reviewed tree, naming the exact npm package, and not withdrawn by the applicable
boundary. Whether withdrawn advisories should instead remain in course labels
requires instructor clarification; this implementation excludes them and records
the rule.

## Why current API responses do not establish historical features

GitHub's repository is a mirror of its advisory service. Records can be amended;
the qualitative severity, reviewed flag and **last** review timestamp are
GitHub-specific OSV extensions, whose format is not guaranteed stable. A current
record filtered only by publication date can therefore leak later edits into old
features. We retain exact source versions and validate their structure rather
than assume current metadata was historically available. The upstream database
is CC-BY-4.0; retained records are attributed to GitHub Advisory Database.
[Source: official repository documentation](https://github.com/github/advisory-database/blob/main/README.md).

The OSV format distinguishes publication, modification and withdrawal timestamps,
affected package names and version ranges. They represent different facts: an
update or review is not a new publication. The pipeline uses the snapshot's
`published` timestamp to assign time buckets and excludes withdrawals according
to the same snapshot. Qualitative severity is taken from the GHSA category;
missing or unrecognized values go to unknown, with no guessed CVSS conversion.
[Source: OSV specification](https://ossf.github.io/osv-schema/).

## Acquisition and provenance

For each boundary the acquisition layer resolves a commit on the official
repository's main history strictly before that boundary. The commit API exposes
an `until` filter, immutable SHA, commit date and signature-verification metadata.
The acquisition manifest preserves selected response fields, its body hash, and selected SHA; the pipeline
then downloads the entire repository archive addressed by that SHA.
[Source: GitHub commit API](https://docs.github.com/en/rest/commits/commits#list-commits).

The parser verifies the archive root against the full commit SHA, streams all
`advisories/github-reviewed/**/*.json` files without extracting paths, hashes the
archive and records the reviewed-file count. It checks IDs, duplicate conflicts,
package mappings, timestamps and reviewed flags. Any malformed mapping prevents
claiming corpus completeness. A selected package's unresolvable advisory blocks
its counts; it is not silently omitted or turned into zero. A zero means no
qualifying matching advisory was found in that complete reviewed-tree scan.

The committed replay bundle retains original count-relevant advisory fields, their paths,
archive hash, commit identity and date, scanned-file count, selected package list,
and full corpus GHSA ID inventory. The caller verifies bundle hashes before
replay. The full ID inventory prevents an already known GHSA whose publication
date is later changed from being misclassified as a new future ID. The large
archives can be downloaded again by immutable SHA rather than committed.

Narrative, references and credits are omitted from the committed replay projection:
one upstream advisory's narrative contains expired signed attachment URLs, which
are irrelevant to the course measurements and should not be redistributed as
credential-like strings. No measurement, timestamp, severity or package mapping is
altered. Each original complete JSON document has a recorded SHA-256 over its
canonical representation (sorted keys, compact separators, ensure_ascii=True),
and its immutable source path and archive hash permit independent retrieval.

For history, only the input snapshot is consulted. For outcomes, only the outcome
snapshot supplies severity, affected-package mapping, review state and withdrawal
state. Outcome changes never modify historical features. Each output count has
an accompanying exact GHSA membership list. Multiple affected entries for one
package count once. Distinct GHSA IDs sharing a CVE still count separately, as the
course schema demands.

## Limits of the historical claim

This reconstructs **observable historical Git mirror state**, not a certified
transaction log of GitHub's advisory service. Mirror delays can make the most
recent commit lag the requested instant; the manifest reports that gap. Commit
timestamps and upstream main history are trusted evidence, not an independent
proof of when every byte became publicly accessible. Delayed imports or later
backdated corrections are absent from an earlier tree even if their current
publication date is old. No current metadata is backfilled to disguise this.

The absence of an advisory in the complete tree establishes a database count,
not that a package had no vulnerabilities in the world. Advisory coverage,
curation, severity and package mappings can be incomplete. Selected npm metadata
has its own provenance limits, documented separately. These limits must be
disclosed when calling rows historically verified: verification is against the
pinned observable sources and this stated policy, not a guarantee of exact
historical service state or instructor agreement with the cutoff.

## Validation

`tests/test_advisories.py` uses explicitly synthetic unit fixtures separate from
the collected dataset. It checks known counts, all severity categories, month
boundaries, exact 90-day endpoints, distinct IDs, duplicate mappings and CVE
aliases, later severity/mapping/withdrawal changes, missing publication,
future timestamps, invalid reviewed status, wrong snapshot commits, unscanned
packages, archive corruption indicators, and deterministic bundle replay.
Actual execution results are recorded by the project's run report; this document
alone is not a claim that tests or acquisition succeeded.

## Observed upstream timestamp anomalies

The actual historical trees contain ten selected GHSA records whose `modified`
time precedes their `published` time. For example, GHSA-xw5p-hw6r-2j98 has
modified 2020-08-03 and published 2020-08-05. GHSA-9gr3-7897-pp7m has modified 2021-08-31
and published 2021-09-01. Both dates are years before the input cutoff, and each
record is present in the immutable pre-cutoff tree. The OSV specification defines
these fields separately and does not impose a cross-field ordering constraint.
Therefore this condition is retained as a source-quality warning with original
values, rather than excluding valid historical evidence. No timestamp is repaired
or fabricated. Future-dated fields and missing required evidence still block the
package. Rejected raw records are retained separately in the replay bundle for audit.
