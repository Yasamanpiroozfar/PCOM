# Sources, sampling, and redistribution

## Public sources

1. Full npm metadata: `https://registry.npmjs.org/{percent-encoded-package}` with
   `Accept: application/json`. [Registry metadata documentation](https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md).
   Successful full documents establish declared dependency maps; absent maps mean
   no declarations, whereas null/malformed maps are rejected.
2. Per-day downloads: `https://api.npmjs.org/downloads/range/2025-07-01:2026-06-30/{package}`.
   [Official download-count documentation](https://github.com/npm/registry/blob/main/docs/download-counts.md).
   Observed zero-download days are retained; absent days are not estimated.
3. GitHub-reviewed advisories: complete commit-pinned archives from
   [github/advisory-database](https://github.com/github/advisory-database).
   [OSV format](https://ossf.github.io/osv-schema/) provides published/modified,
   affected packages/ranges, and GitHub's database-specific review/severity fields.
4. [GitHub commits API](https://docs.github.com/en/rest/commits/commits) resolves the
   latest commit strictly before each boundary using `until` and `per_page=1`.
   Retained API response fields and the response-body hash are in the acquisition manifest.
5. [GitHub global advisories API](https://docs.github.com/en/rest/security-advisories/global-advisories)
   documents the mutable service view. A live query filtered by publication date
   is not a replacement for historical snapshots.
6. [npm package.json documentation](https://docs.npmjs.com/cli/configuring-npm/package-json/)
   defines dependency maps and bundle declarations.
7. [Package URL specification](https://github.com/package-url/purl-spec) and
   [SemVer2.0](https://semver.org/spec/v2.0.0.html) define identity/version handling.

URLs and UTC collection timestamps of every actual request are recorded in
`data/provenance/http-events.json`; hashes distinguish stored normalized JSON from
the HTTP response bytes. Full archives are scanned without extracting paths or
executing package content. No package is installed or imported.

## Selection

`config/packages.json` freezes forty well-known packages chosen by software role:
server/UI frameworks, build/language tools, HTTP clients, validators, command-line
tools, test frameworks, quality tools, networking, archives, parsers, and utilities.
Scoped and unscoped names and contrasting release activity are included.
No future advisory count was queried to select these packages, and the sample is
not expanded or filtered to manufacture positive labels. Every exclusion is reported.

This is purposive convenience sampling. It favors maintained, visible projects,
uses present-day familiarity rather than an independently archived historical
sampling frame, and excludes much of the long tail. These introduce popularity,
survivorship, and ecosystem-role biases. Forty packages are forty package groups,
regardless of how many version rows they produce. Do not generalize prevalence
or predictive accuracy to all npm packages from this sample.

## Historical optional measurements

The 9 GitHub issue/PR monthly families (108 columns) require reliable event histories
and month-end reconstruction, including pre-window open items. They are not filled
with current counters. They remain NULL in this release rather than assuming
incomplete event APIs establish historical zeros. This does not remove any column.

Current npm metadata may omit unpublished versions. Stable-release counts describe
the valid timestamped releases visible in the captured metadata, including
timestamp-only entries. They are not asserted to prove coverage of deleted history.
Optional package size/file counts come from returned version distribution metadata.

## Rights and attribution

GitHub publishes the Advisory Database under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
The retained advisory fields and derived counts are attributed to GitHub Advisory
Database. The projection omits narrative, reference and credit fields; the original
documents and their upstream references remain retrievable using the pinned source
paths. These changes and the aggregation method are described in the methodology. Its source
license is available at [repository LICENSE](https://github.com/github/advisory-database/blob/main/LICENSE.md).
npm responses contain public registry metadata and may include upstream package
license/author fields. No blanket new license is imposed on those third-party
materials. Original course PDFs/XLSX files and Homework 2 are not redistributed in
this repository. Verify institutional submission/access requirements before publication.
