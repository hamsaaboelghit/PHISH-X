# PHISH-X — Dataset & Evaluation Protocol

## 1. Objective and target labels

PHISH-X classifies URL strings into two classes:

- `0` — Phishing
- `1` — Legitimate

The project uses Logistic Regression trained with hand-implemented numerical optimization. The primary evaluation protocol is a fixed Group Split by Host.

## 2. Dataset and feature contract

The project uses the supplied LegitPhish dataset. The preprocessing and feature-specification documents record the cleaning decisions and legacy feature definitions.

The extractor calculates the legacy URL feature set, while the current classifier consumes exactly five features, in this order:

1. `url_length`
2. `number_of_digits`
3. `url_entropy`
4. `dot_count`
5. `path_length`

The target mapping and feature order are part of the model artifact contract. Do not change feature definitions or order without retraining and updating the artifact/version contract.

**Historical count note:** older audit notes record 100,872 cleaned rows, while the checked-in `split_metadata.json` used by the current training run records 100,862 rows across the two group partitions. The current model run uses the committed split manifests (81,525 train + 19,337 test). Do not combine historical row/class totals with the current split counts as if they were one synchronized snapshot; reconcile the dataset CSV and manifests before publishing a single overall cleaned-row total.

## 3. Dataset quality and bias

Prior audits identified important dataset shortcuts and collection effects:

- An IP-only rule achieved approximately 85.55% accuracy on the historical dataset snapshot.
- Strict parsed-host analysis found a strong association between IP-literal hosts and the phishing class.
- The legacy `has_ip_address` feature is a regex over the entire URL string, not a strict test of whether the parsed destination host is an IP; 22 observed rows explain the difference between the two counts.
- `tld_popularity` also has a strong relationship with the target and requires caution.
- Some legacy features are collection artefacts or naive lexical proxies rather than robust security properties.

These observations mean a high score on this dataset is not proof of broad real-world generalization. The detailed evidence and limitations are in:

- [URL Security & Feature Specification](URL_SECURITY_AND_FEATURE_SPECIFICATION.md)
- [Security Dataset Audit](SECURITY_DATASET_AUDIT.md)
- [Security evidence JSON](security_dataset_evidence.json)

## 4. Split strategies

The checked-in `split_metadata.json` records:

| Strategy | Train records | Test records | Shared hosts |
|---|---:|---:|---:|
| Random stratified | 80,689 | 20,173 | 4,805 |
| Group Split by Host | 81,525 | 19,337 | 0 |

Both use a requested test size of 20% and random state 42. The random split is retained for comparison only. Group Split by Host is the primary evaluation because every host is assigned to one partition only.

The model training CLI reads the raw feature columns from the committed group manifests. The training scaler is fitted only on Group Train and is reused unchanged for Group Test and production inference.

## 5. Numerical training and evaluation

The production model is a hand-implemented Logistic Regression classifier. It uses:

- Manual population-variance standardization.
- Stable sigmoid probability calculation.
- Binary Cross-Entropy with L2 regularization.
- Explicit analytical gradient and Hessian.
- Batch Gradient Descent for numerical comparison.
- Damped Newton-Raphson with backtracking line search.
- Hand-implemented Gaussian Elimination with Partial Pivoting to solve the Newton system.

No scikit-learn estimator or optimizer is used to fit the Logistic Regression model. Scikit-learn remains a utility dependency for dataset splitting and compatibility/testing tasks.

Run training from the repository root:

```powershell
python src/phishx/models/train.py
```

This generates a local Joblib artifact and `training_metrics.json` under `data/processed/model_artifacts/`.

## 6. Current reported held-out results

The project team's local run on 13 November 2026 evaluated 19,337 Group Test samples:

| Metric | Phishing | Legitimate |
|---|---:|---:|
| Precision | 98.91% | 96.82% |
| Recall | 97.90% | 98.34% |
| F1-score | 98.41% | 97.57% |

Overall accuracy: **98.08%**.

Confusion matrix, with actual classes as rows and predicted classes as columns:

| Actual | Predicted Phishing | Predicted Legitimate |
|---|---:|---:|
| Phishing | 11,481 | 246 |
| Legitimate | 126 | 7,484 |

Training used Newton-Raphson with L2 = 0.001. The reported regularized loss decreased from 0.693147 to 0.061183 over 10 iterations.

These values are a reported local run on the supplied fixed split, not a live benchmark or a guarantee for future phishing campaigns. See [Final Project Report](FINAL_PROJECT_REPORT.md) for full interpretation.

## 7. Reproducibility and validation

The split manifests and metadata are stored in `data/processed/splits/`. The loader validates:

- Required files and columns.
- Non-empty URLs and unique URLs within each source.
- No URL overlap between Group Train and Group Test.
- Manifest host values against hosts extracted from URLs.
- Manifest labels against the cleaned dataset.
- No shared hosts between Group Train and Group Test.
- Numeric and finite model features.

The full test suite is run with:

```powershell
python -m pytest -q
```

The latest team-reported local run: **319 passed, 1 skipped, 190 subtests passed**.

## 8. Interpretation

Phishing recall is security-critical because it measures how many phishing samples are correctly caught. Precision matters because false phishing alerts can disrupt legitimate users. Both class-specific metric sets must be reported; a single precision/recall pair is ambiguous when the positive label is Legitimate (1).

The model score, additive feature contributions, and structural security advisories are three different outputs:

- Model probabilities are produced by Logistic Regression.
- Feature contributions explain the model logit in standardized feature space.
- Security advisories are deterministic structural checks and do not change model probabilities.

A positive feature contribution moves the model logit toward Legitimate; it does not prove that the raw feature is protective. A warning is not proof of phishing, and no warning is not proof of safety.
