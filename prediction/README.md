# PCOM-01 – Homework 5

Forecast the number of new GitHub-reviewed npm vulnerability advisories in the 90 days after the release of the highest stable semantic version in the input. The initial predictor is an L2-regularized Poisson regression model (alpha = 0.1), with one model per severity. The previous Homework 4 proposal remains the starting point.

## Run a prediction

From the repository root, with Python 3.11 or later:

```sh
python prediction/predict.py input.csv result.csv --fractional
python -m unittest discover -s prediction -v
```

The input is a CSV containing version records for exactly one package. The output is a CSV header followed by one row of five nonnegative floating-point predictions in the official Prediction Goal order when `--fractional` is used (low, moderate, high, critical, unknown). The prediction uses the supplied history and does not contact external services or read the target columns. The input is expected to contain stable versions only. The highest semantic version is selected, not the most recently published version.

The manual competition form requests five floating-point values, including unknown severity. Use `--fractional` for the competition to retain the model's unrounded expected counts. The predictor defaults to five rounded integer counts when that flag is omitted; `--four-severities` is available for compatibility with the four-value Worklog description, but is not needed for this round. The integer target labels in the training schema represent observed counts; they do not require the submitted predictions to be rounded.

`model.json` contains the fitted coefficients and the preprocessing parameters. Inference uses only the Python standard library. The unknown-severity model returns zero because the training partition contains no positive examples for that target.

## Training and model comparison

The existing corrected Homework 3 data has 14,840 version records from 685 packages. Use the highest stable version per package; a package's version rows share the package-level 90-day outcome. The split is deterministic, stratified by whether any of the four known-severity targets is positive, and uses 480 training, 102 validation and 103 previously inspected test packages. Preprocessing is fitted on training only. The official input features are sufficient at prediction time; no additional sidecar features are required.

```sh
python -m pip install -r prediction/requirements.txt
python prediction/train.py datasets/training/data/corrected/training-records.csv
python prediction/compare_models.py datasets/training/data/corrected/training-records.csv
python prediction/compare_models.py datasets/training/data/corrected/training-records.csv --features full --report prediction/full_feature_comparison.json
```

`train.py` fits the 15-feature Poisson model and selects alpha by rounded validation RMSE. The committed model was fitted to the same objective using Newton optimization; scikit-learn can produce slightly different coefficients. `evaluation.json` retains the original experiment, including the previously observed holdout results.

The compact comparison uses seven features: lifetime advisory count, lifetime high/critical count, advisory count in M0–M2, stable releases, direct dependency count, log daily downloads and log package age. The two latter features are rounded to two decimal places to keep the experiment's input representation reproducible. Missing values are imputed using training medians. The five count features receive a log1p transform. The full comparison option uses the original 15 features for all candidates and is intended for a subsequent run against the complete CSV.

The comparison trains actual XGBoost models with `count:poisson`, a regularized Poisson baseline and two hurdle-style predictors (logistic occurrence model multiplied by the mean severity count conditional on occurrence). The compact experiment uses the same feature inputs and split for each method. Zero and training-mean baselines are included. The compact results are in `model_comparison.json`. RMSE is the provisional selection criterion; it is not assumed to be the official competition score.

### Validation results

| Method | Feature count | Integer MAE | Integer RMSE |
|---|---:|---:|---:|
| Zero | — | 0.036765 | 0.467052 |
| Poisson (alpha 0.01) | 7 | 0.034314 | 0.242536 |
| XGBoost Poisson (best tested integer RMSE) | 7 | 0.046569 | 0.405235 |
| Hurdle (any occurrence, C=0.1) | 7 | 0.041667 | 0.386665 |
| Initial Poisson (alpha 0.1; previous experiment) | 15 | 0.026961 | 0.204124 |

These scores average over the four known severities, for comparison with the original evaluation; the new comparison report also includes five-column integer scores. Unknown counts are zero in all three partitions. Only four validation packages have a positive known-severity outcome, so the ranking is uncertain. The original 15-feature Poisson's rounded test RMSE (0.203131) was worse than the zero baseline (0.130347). That test has already been inspected and is not a fresh holdout for further model selection. Keep the initial predictor for this submission provisionally and use new, independent packages or a later temporal holdout for future evaluation.

## Files

- `predict.py`, `model.json`: submission predictor and trained model.
- `train.py`, `evaluation.json`: original model training and evaluation.
- `compare_models.py`, `model_comparison.json`, `comparison_metadata.json`: compact comparison and reproducibility details; full-feature comparison can be run locally.
- `example_input.csv`, `example_output.csv`, `test_predict.py`: real-package example and inference tests. Future target cells in the example are blank.

## Submission

Run the tests and check the actual competition input. Commit the submission predictor, trained model, relevant training and evaluation code and reports, tests, examples, and documentation; create the `pcom-entry-1` tag on the selected submission commit. Do not include temporary prediction outputs or incomplete historical data and caches. The first round is manual: run the predictor on the instructor-provided CSV with `--fractional` and enter the five predicted values in the course form. The VM and `/health` and `/predict` service are Homework 6 requirements, not this submission.

Data expansion is a separate next step. This revision does not add new packages or historical windows. Additional training data should use completed 90-day outcomes, preserve the same package-level advisory definitions and avoid using post-origin observations as predictors.
