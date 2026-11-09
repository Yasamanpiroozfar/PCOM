# Homework 3 dataset validation

The primary export contains **14,840 records from 685 packages**, with
all **224 official columns** and **20 additional numeric input features** in a
separate file. The [method](../docs/correction-contract.md) defines the release
origin, fixed calendar measurements and 90-day outcomes.

| Check | Result |
|---|---|
| Tests | 250 passed; zero failures, errors or skips |
| Candidate sources | 1,214 distinct names; 20 retained public npm search responses |
| Verified packages | 685 with complete required source evidence |
| Historical GHSA coverage | 1,370 boundaries; 826 commits; 529 reviewed subtrees |
| Original Git objects | 44,336 advisory blob versions retained and verified |
| Official field audit | 3,324,160 comparisons; zero disagreements |
| Additional feature audit | 326,480 comparisons; zero disagreements |
| Required missing values / duplicate PURLs | 0 / 0 |
| Offline reproduction | All 14 core and feature files byte-identical |
| Reference cohort | All 989 release-based records retained identically |
| Initial submission | Exact tagged file tree and original data preserved |

Evidence: [integrity](expanded-integrity.json), [source audit](../datasets/training/data/corrected/source-audit.json),
[reproduction](expanded-reproducibility.json), [tests](correction-tests.json),
[dataset summary](expanded-summary.json), and
[GitHub Actions](https://github.com/Yasamanpiroozfar/PCOM/actions).

Primary JSONL SHA-256:
`19c486852aa9052e895adfe93dbc1a721816527d3ac48b86f12d12f1ff6fccec`.
The [manifest](../datasets/training/data/corrected/manifest.json) binds each export to its sources.

There are 28 packages with at least one qualifying 90-day outcome.
These are package-level labels shared by each package's version records;
evaluation should split by package to avoid overlap.

npm captures and cohort selection are retrospective. Historical GHSA evidence
reflects reviewed Git mirror state, with synchronization and prior unreviewed or
deleted-ID limitations. Unacquired optional issue/PR measurements remain NULL.
Full eventual monthly totals are not substituted for observations available at
the release origin.
