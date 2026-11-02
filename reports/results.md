# Executed Homework 3 results

These figures are generated from recorded runs, not estimates. Dataset verification is scoped to the pinned source evidence and the documented cutoff interpretation.

| Metric | Result |
|---|---:|
| Packages selected / registry processed | 40 / 40 |
| Packages with eligible final records | 39 |
| Registry version manifests examined | 24,229 |
| Real final package-version rows | 990 |
| Official columns | 224 |
| Required field coverage | 990/990 for every required field |
| Optional fields fully populated / entirely NULL | 38 / 108 |
| Structural validation errors | 0 |
| Tests run / failures / errors / skips | 108 / 0 / 0 / 0 |
| Independent source comparisons | 99,990 |
| Original advisory documents verified against archives | 614 |
| Byte-identical processed artifacts | 9/9 |
| Unresolved source failures | 0 |
| Quarantined exploratory rows in final run | 0 |

## Acquisition evidence

Captured source requests: {'200': 84, '429': 72}. HTTP 429 responses are retained; pacing/backoff and a resumed acquisition recovered all 13 initially failed package download sources. No failed lookup became zero.

| Snapshot | Immutable commit | Commit UTC time | Reviewed files scanned |
|---|---|---|---:|
| history | [396e25aa0b5b10bdd44627834d156df57294adfd](https://github.com/github/advisory-database/commit/396e25aa0b5b10bdd44627834d156df57294adfd) | 2026-06-30T22:29:28Z | 32,595 |
| outcome | [4886121ecccc6041f8d20eca6cd9013786f5dae4](https://github.com/github/advisory-database/commit/4886121ecccc6041f8d20eca6cd9013786f5dae4) | 2026-09-28T21:58:48Z | 35,994 |

Both full trees were scanned. Ten historical records have modified-before-published source anomalies; each original value is preserved and both timestamps precede the cutoff. This is a documented warning, not a future-data leak. The exact historical GitHub service state remains unproven; see the methodology.

## Exclusions

| Reason | Count |
|---|---:|
| at_or_after_cutoff | 333 |
| before_history | 9,364 |
| no_stable_version_in_history | 1 |
| prerelease | 13,542 |
| timestamp_without_version_manifest | 22 |

The 22 timestamp-only entries are additional metadata references without usable version manifests. `minimist` is retained in the selection/provenance but has no stable release in the required window. The other 39 selected packages produce the 990 records.

## Vulnerability outcomes

| Severity | Distinct package–GHSA counts | Sum over version rows (repeated labels) |
|---|---:|---:|
| low | 2 | 22 |
| moderate | 27 | 1159 |
| high | 12 | 583 |
| critical | 3 | 185 |
| unknown | 0 | 0 |

There are 44 distinct target GHSA IDs in this sample. 29 of 39 represented packages have zero qualifying future advisories. Labels are package-wide and repeat across versions; row totals must not be interpreted as independent vulnerabilities or independent training cases.

| Total labels per package | Packages |
|---|---:|
| 0 | 29 |
| 1 | 1 |
| 2 | 4 |
| 3 | 1 |
| 5 | 1 |
| 6 | 1 |
| 10 | 1 |
| 11 | 1 |

## Records by package

| Package | Eligible rows | Highest stable SemVer before cutoff |
|---|---:|---|
| express | 5 | 5.2.1 |
| fastify | 16 | 5.9.0 |
| koa | 11 | 3.2.1 |
| @hapi/hapi | 9 | 21.4.9 |
| @nestjs/core | 27 | 11.1.27 |
| react | 23 | 19.2.7 |
| vue | 22 | 3.5.39 |
| svelte | 152 | 5.56.4 |
| next | 82 | 16.2.9 |
| @angular/core | 93 | 22.0.4 |
| vite | 62 | 8.1.2 |
| webpack | 27 | 5.108.3 |
| rollup | 52 | 4.62.2 |
| esbuild | 17 | 0.28.1 |
| @babel/core | 10 | 8.0.1 |
| typescript | 4 | 6.0.3 |
| lodash | 3 | 4.18.1 |
| axios | 27 | 1.18.1 |
| undici | 48 | 8.5.0 |
| got | 18 | 15.0.7 |
| zod | 54 | 4.4.3 |
| joi | 11 | 18.2.3 |
| ajv | 4 | 8.20.0 |
| commander | 4 | 15.0.0 |
| yargs | 2 | 18.0.0 |
| chalk | 3 | 5.6.2 |
| jest | 11 | 30.4.2 |
| vitest | 31 | 4.1.9 |
| mocha | 5 | 11.7.6 |
| eslint | 26 | 10.6.0 |
| prettier | 16 | 3.9.4 |
| ws | 7 | 8.21.0 |
| socket.io | 2 | 4.8.3 |
| tar | 21 | 7.5.19 |
| semver | 8 | 7.8.5 |
| minimist | 0 | 1.2.8 |
| qs | 34 | 6.15.3 |
| yaml | 6 | 2.9.0 |
| marked | 22 | 18.0.5 |
| nanoid | 15 | 5.1.16 |

## Evidence files

- `validation.json`: all column/type/missingness/chronology results and per-field coverage.
- `tests.json` and `tests.txt`: executed suite and full test names.
- `source-audit.json`: independent row facts and original-archive projection checks.
- `reproducibility.json`: both hashes for every regenerated artifact.
- `release-check.json`: credential-pattern scan and original-course-file integrity.
- `file-inventory.txt`: exact intended repository file list; caches and replay scratch files excluded.

Primary dataset SHA-256: `3023382cabd7dec3e9a6a8091afd447850c31721974056fe579fc7f0ed4ac21b`.

No trained model, prediction score, invented grade, or completed external submission is claimed.
