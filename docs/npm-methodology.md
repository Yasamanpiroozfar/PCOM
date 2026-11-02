# npm metadata and version methodology

The source is npm's full public metadata endpoint,
`https://registry.npmjs.org/{escaped-package-name}`, requested using
`Accept: application/json`. We retain the returned source separately from the
transformed records. No package code, installation hook, or submitted SQL is
executed. API/network failures are not interpreted as empty packages.

## Course-field interpretation

The authoritative workbook `Schema!C5:H16` requires an exact npm PURL, npm
`time.created`, the exact version's `time[version]`, four separate dependency-map
key counts, and the bundling declaration count. Optional `dist.unpackedSize`
and `dist.fileCount` are copied only when valid nonnegative signed-64-bit
integers. Absent/invalid optional values remain null; invalid values are also
reported. Distinct dependency maps are counted independently: optional
dependencies are **not** subtracted from ordinary dependencies, and optional
peer dependencies remain included in the peer count.

In a successfully retrieved **full** version manifest, an absent dependency
map denotes no declared dependencies of that kind; its count is zero. A map
explicitly set to null, a non-object value, or an inconsistent manifest identity
excludes the record with a reason. The full-response requirement prevents
mistaking omitted abbreviated metadata for absent declarations.

`bundleDependencies` and its alias `bundledDependencies` count distinct listed
names. Boolean false denotes no bundled declarations; true denotes the union
of ordinary and optional direct runtime dependencies. Two conflicting aliases
cause exclusion instead of silent precedence. This counts the declaration,
not dependency files discovered inside the tarball. The official schema does
not specify alias-conflict behavior; conservative exclusion is an implementation
decision. Normal npm publication usually supplies a normalized array.

## Time, versions, and PURLs

The documented implementation cutoff is **2026-07-01T00:00:00.000Z** and the
input window is **[2025-07-01T00:00:00.000Z, cutoff)**. It aligns the twelve
specified calendar months: M0 June 2026 through M11 July 2025. This fixed
cutoff is an explicit project interpretation, not a claim that the instructor
resolved the conflict with the worklog's latest-version forecast wording.

Each returned row identifies a real stable exact version published within that
window. The parser accepts strict SemVer 2.0, excludes prereleases, and reports
legacy/noncanonical version identifiers. It does not silently strip a `v`,
coerce leading zeros, or invent missing dates. UTC timestamps are formatted with
exactly three fractional digits. Input timestamps with finer precision are
truncated to milliseconds for the output representation; eligibility comparisons
use their original parsed precision. Raw source values remain in the snapshot.

Highest semantic version is calculated from all timestamped stable versions
known in the returned metadata whose publication precedes the cutoff, including
versions older than the input window. Current `dist-tags.latest`, current
package-level repository information, and latest publication time do not select
the historical version. Build metadata does not change SemVer precedence;
equal-precedence candidates are all reported, with a lexical choice solely for
deterministic reporting. `latest_semver_in_records` tells whether that candidate
actually has a valid row in the input window.
`latest_semver_verified_for_returned_metadata` is false if any stable version
has an invalid/missing timestamp: in that case the reported candidate is only
the highest among the successfully timestamped versions, and is not a verified
highest historical version.

PURLs preserve the exact version, encode the scope's `@` as `%40`, and encode
build-metadata `+` as `%2B`. For example, the **illustrative** identifier
`pkg:npm/%40scope/package@1.2.3%2Bbuild.1` denotes a scoped exact version. Test
fixtures are synthetic and are not acquired training records.

## Monthly stable-release counts

The monthly count covers distinct stable version names with publication times
in each calendar month, including maintenance releases. A timestamped release
whose version manifest is no longer present still contributes to release count,
but no metadata row is fabricated for it. If a stable version has a missing or
inconsistent publication timestamp, all monthly stable-release measurements for
that package are null because their completeness cannot be established. A
valid observed empty month is zero. The count refers to versions represented
in the retrieved registry metadata; it is not proof that npm retained every
unpublished historical version.

## Historical limitations

An npm packument retrieved today is not an archived June 2026 snapshot.
Publication times and exact-version manifests let us identify retrospective
version records, but cannot prove every field was immutable or present in
exactly this form at the historical cutoff. Unpublished versions may be absent;
registry normalization or metadata corrections can also change what is visible.
We do not use mutable current package-level fields as historical features.
The provenance and final audit must retain this limitation; a contemporary
collection cannot be described as a fully observed historical npm census.

Independent tarball-integrity checks, if supplied by the acquisition layer,
support authenticity of the downloaded artifact but do not establish when a
registry manifest's metadata was first publicly available. They also must not
silently overwrite the workbook's specified registry fields.

## Primary documentation

- [npm full/abbreviated metadata format and field definitions](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md)
- [npm package.json dependency and bundling declarations](https://docs.npmjs.com/cli/configuring-npm/package-json/)
- [SemVer 2.0 rules, prereleases and build precedence](https://semver.org/spec/v2.0.0.html)
- [npm metadata normalization source](https://github.com/npm/normalize-package-data/blob/main/lib/fixer.js)

Course evidence was read directly from the original workbook. The course
worklog's latest-semantic-version rule is preserved as metadata and remains
distinguished from the fixed dataset-cutoff interpretation.
