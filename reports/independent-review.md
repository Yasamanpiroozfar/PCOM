# Requirements and engineering review

Review date: 2026-11-02. Scope: source/design review with separately recorded final execution evidence.

## Scope and evidence

The review covered the official schema workbook and organization workbook, including all three worksheets; the acquisition, storage, npm transformation, downloads, advisory-history, schema-validation, and pipeline modules; the package-selection configuration; and the npm/advisory methodology documents. The schema was directly re-extracted as 224 ordered columns: 78 required and 146 optional. The original schema SHA-256 was `243a32bcd9e9b6d23cbde133a790f8e81ef518ece6e1e408adbb39815f033413`.

The initial 15 schema/validation tests passed, and five offline integration tests used explicitly synthetic sources. An attempted standalone integration execution was blocked by Windows temporary-directory access restrictions; it was not a successful test run. The separately recorded final run reports **110 tests passed**, a structurally valid dataset of **990 records from 39 of 40 selected packages**, **99,990 source comparisons**, **614 retained advisory originals verified**, and **nine byte-identical replay artifacts**. Those final execution results are separate evidence; this review did not repeat the complete final run or inspect every final generated row.

This report records source/design findings and distinguishes them from the separately recorded final execution results. It does not constitute a second complete execution of the final release.

## Findings addressed during development

1. **All-quarantined builds lost diagnostics.** The reviewed pipeline originally rejected an empty final dataset before saving the exclusions and exploratory records. Final run documentation reports this as fixed and states that failed-build status also prevents stale outputs from being validated as a new successful build.
2. **Commit-response preservation wording exceeded the stored evidence.** The early methodology claimed the complete resolution response was preserved, while the reviewed code retained selected commit metadata and a response hash. Final documentation reports that the provenance/documentation mismatch has been corrected.
3. **Package versions are correlated observations.** Multiple version rows share the same package-wide history and future labels. Random row-level train/test splitting would leak package identity and overstate sample independence. Final documentation includes a grouped-package-split warning. Package-level label totals must remain separate from row-level totals.
4. **Source chronologies can differ from simplistic validation assumptions.** An advisory's modification timestamp preceding its publication timestamp initially quarantined records. The documented resolution replaces that unsupported blanket rejection with a warning while preserving raw evidence and boundary checks. A separate reinspection of that final change was outside this review's scope.

## Remaining material limitations and decisions

| Item | Assessment |
|---|---|
| Fixed prediction cutoff | **Unresolved instructor interpretation.** July 1, 2026 aligns the schema's July 2025–June 2026 history. It is not the same as independently anchoring every package's 90-day prediction to its highest-semantic-version publication timestamp. The implementation must retain this distinction and its supporting source hierarchy. |
| Five target columns versus four-output worklog | **Contract-preserving decision.** Keeping unknown severity follows the higher-priority explicit schema. This does not prove the instructor intended a five-element model prediction interface. |
| npm historical state | **Partial historical evidence.** Current full registry metadata supplies authentic version records and publication timestamps but does not prove every value was available or identical at the historical cutoff. Removed versions and subsequent corrections can affect retrospective coverage. Do not describe the dataset as a contemporaneously archived npm census. |
| GHSA historical state | **Qualified historical reconstruction.** Pinned reviewed-repository trees are materially stronger than filtering today's advisories by publication date. They remain a reconstruction of the public Git mirror, subject to mirror lag and upstream commit-time trust, rather than a certified advisory-service transaction history. |
| Advisory qualification and target boundaries | **Documented implementation decisions.** Withdrawal handling, unknown/unrecognized severity, half-open boundaries, and genuinely new IDs must remain explicit. These are not all fully specified by the instructor. |
| Sampling | **Purposive, not representative.** The selected software-role sample is reproducible and was not selected using future outcomes. It remains biased toward recognizable, surviving packages and does not support population-wide npm claims. |
| Optional GitHub activity | **Permitted missingness, reduced feature breadth.** The recorded final output has all 108 GitHub lifecycle columns set to NULL. The schema allows this, but these fields have not been acquired; their presence as columns must not be presented as successful measurement. |
| Statistical independence | **Rows are not independent packages.** The recorded final output has 990 version rows but 39 represented packages. Future evaluation should group by package and consider temporal validation rather than treating 990 as 990 independent prediction cases. |
| External submission | **Pending authorization and verification.** A local commit is not a published repository, the exact `initial-training-data` tag, or a confirmed form submission. These must remain pending until authorized operations actually succeed. |

## Critical conclusion

No additional blocking code defect was identified in the reviewed modules beyond the issues reported above. The reported final results support a substantial, reproducible initial dataset under the documented source and cutoff interpretation. They do **not** eliminate the material historical-evidence and instructor-interpretation limitations.

A defensible final audit should mark explicit structural/core-field and executed-test requirements according to their concrete evidence, while marking strict historical availability and unresolved cutoff semantics **PARTIAL**, not unconditionally PASS. Optional unavailable measurements should be distinguished from required-field failures. Publication must preserve these qualifications and must not claim instructor confirmation, a numerical grade, or completed external submission.
