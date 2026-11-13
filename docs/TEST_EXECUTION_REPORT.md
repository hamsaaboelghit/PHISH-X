# PHISH-X — Test Execution & Verification Report

**Report date:** 13 November 2026  
**Repository branch:** `main`  
**Scope:** Current numerical model, inference pipeline, URL security analysis, Streamlit integration, and evaluation dashboard.

> This report supersedes the historical task-by-task notes previously stored in this file. Older task/branch snapshots are not current test evidence.

## 1. Local full-suite result

The project team ran the following command locally after integrating the numerical training pipeline, class-specific evaluation metrics, and Model Evaluation page:

```powershell
python -m pytest -q
```

Reported terminal summary:

```text
319 passed, 1 skipped, 190 subtests passed
```

No failing tests were reported in this run.

The test suite includes coverage for:

- URL parser and security-signal behaviour.
- Feature extraction and full-dataset feature parity.
- Artifact validation and URL inference.
- Manual Logistic Regression, sigmoid, loss, gradient, Hessian, and Newton solver.
- Gaussian Elimination with Partial Pivoting.
- Numerical standardization and training/inference scaling parity.
- Finite-difference checks for analytical derivatives.
- Hessian symmetry/positive-semidefinite properties.
- Rank-deficient feature cases and optimizer comparisons.
- Streamlit source/integration contracts.

One test is reported as skipped. This report does not infer the skip reason from the aggregate summary; inspect the pytest output or test marker if the instructor asks about that specific skip.

## 2. Training CLI verification

The team ran:

```powershell
python src/phishx/models/train.py
```

The command completed and printed:

- `PHISH-X NUMERICAL TRAINING COMPLETED`
- Artifact path: `data/processed/model_artifacts/phishx_newton_model.joblib`
- Metrics path: `data/processed/model_artifacts/training_metrics.json`

Reported training/evaluation values:

| Item | Result |
|---|---:|
| Optimizer | Newton-Raphson Logistic Regression |
| L2 | 0.001 |
| Iterations | 10 |
| Initial loss | 0.6931471806 |
| Final loss | 0.0611826891 |
| Group Test samples | 19,337 |
| Accuracy | 98.0762% |
| Phishing precision | 98.9144% |
| Phishing recall | 97.9023% |
| Phishing F1 | 98.4058% |
| Legitimate precision | 96.8176% |
| Legitimate recall | 98.3443% |
| Legitimate F1 | 97.5750% |

Confusion matrix:

- True phishing predicted phishing: 11,481
- True phishing predicted legitimate: 246
- True legitimate predicted phishing: 126
- True legitimate predicted legitimate: 7,484

These are the team's reported local run values, not a promise of future or external performance.

## 3. Artifact-backed inference smoke test

The team loaded the generated artifact through the public inference API:

```python
from phishx.inference import load_model_artifact, predict_url

artifact = load_model_artifact(
    "data/processed/model_artifacts/phishx_newton_model.joblib"
)
result = predict_url("https://example.com/login", artifact)
print(result.as_dict())
```

Previously reported examples included:

- `https://example.com/login` → Legitimate, phishing probability approximately 0.1857.
- `http://192.168.1.10/account/verify` → Phishing, phishing probability approximately 0.9995; the independent structural layer also reports a low-severity direct-IP advisory.
- `https://secure-login.example` → a model output was produced, but `.example` is a reserved example domain and must not be represented as a live-site validation.

These are smoke-test examples, not a statistically representative test set.

## 4. Streamlit runtime verification

The team ran Streamlit's `AppTest` against `app/main.py`, selected the **Model Evaluation** page, and inspected exceptions and rendered metrics.

Reported output:

```text
EXCEPTIONS: []
METRICS: [
  'Test samples',
  'Accuracy',
  'Decision threshold',
  'Training iterations',
  'Phishing Precision',
  'Phishing Recall',
  'Phishing F1-score',
  'Legitimate Precision',
  'Legitimate Recall',
  'Legitimate F1-score',
  'Dataset split',
  'Feature specification',
  'Model optimizer',
  'Regularization (L2)'
]
```

This confirms that the page executed in the Streamlit test harness and rendered the expected metric labels. It is not a claim of manual visual inspection in a browser.

The run emitted a bare-mode `ScriptRunContext` warning and deprecation warnings for `use_container_width`; these did not produce AppTest exceptions. The current `main` implementation has since migrated all 14 affected calls to Streamlit's `width="stretch"` argument. The local AppTest result above predates that cleanup, so the updated UI argument should be included in the next local smoke test.

## 5. GitHub Actions status

The latest push to `main` triggered the repository's URL feature test workflow. At the time this report was prepared, that push workflow was still in progress. The Core Inference and URL feature workflows associated with the immediately preceding documentation PR head had completed successfully.

Always inspect the Actions page for the final status of the latest `main` commit before claiming that the newest remote CI run passed:

https://github.com/hamsaaboelghit/PHISH-X/actions

## 6. Reproduction commands

From the repository root:

```powershell
python -m pytest -q
python src/phishx/models/train.py
streamlit run app/main.py
```

The training command requires the approved dataset and split manifests at the paths documented in the README. The generated Joblib artifact and JSON metrics report are local outputs and are not committed to the repository.

## 7. Verification boundaries

- A passing test suite verifies covered code paths; it does not prove that every possible URL is safe or correctly classified.
- The reported model metrics are tied to the supplied dataset and Group Split by Host.
- AppTest confirms execution and expected UI elements, not visual quality across every browser, screen size, or interaction.
- Structural security findings are deterministic advisories, not calibrated probabilities.
- Joblib artifacts must be loaded only from trusted sources.
