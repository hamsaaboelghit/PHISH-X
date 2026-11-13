# PHISH-X — Phishing URL Detection & Explanation

**PHISH-X (Phishing X-Ray)** is an explainable security-analysis workbench that classifies a URL as **Phishing** or **Legitimate**, shows the model's probabilities and feature contributions, and reports independent URL-structure security advisories.

The project is also a numerical-computations implementation: Logistic Regression is trained with optimization methods implemented directly from their equations, rather than a built-in machine-learning estimator or optimizer.

## What the system does

- Extracts URL features locally from the supplied string; it does not visit the URL or make DNS/HTTP requests.
- Predicts the class and reports phishing/legitimate probabilities.
- Explains the model score through additive feature contributions in log-odds space.
- Runs a separate structural security assessment. These advisories are not silently mixed into the model's feature vector.
- Provides a Streamlit workbench with URL Investigation, Optimization Lab, Dataset Intelligence, and Model Evaluation views.

## Model contract

The current model uses five numerical inputs, in this exact order:

1. `url_length`
2. `number_of_digits`
3. `url_entropy`
4. `dot_count`
5. `path_length`

The label mapping is fixed: **0 = Phishing**, **1 = Legitimate**. The model uses the legacy feature specification `1.0-legacy`; feature extraction must remain consistent with the dataset used for training.

The feature extractor can calculate a broader 16-feature dataset representation, but only the five features above are currently passed to this Logistic Regression model. See [URL Security & Feature Specification](docs/URL_SECURITY_AND_FEATURE_SPECIFICATION.md) for all feature definitions, parser behaviour, warnings, dataset caveats, and known limitations.

## Numerical methods implemented

### 1. Numerical standardization

The scaler is implemented directly and fitted on Group Train only. For feature (j):

```text
mean_j     = (1 / n) * sum(x_ij)
variance_j = (1 / n) * sum((x_ij - mean_j)^2)
scale_j    = sqrt(variance_j)
z_ij       = (x_ij - mean_j) / scale_j
```

A constant feature uses scale 1 to avoid division by zero. The fitted training statistics are stored in the model artifact and reused unchanged for test data and inference.

### 2. Logistic Regression and Binary Cross-Entropy

For input vector (x), weights (w), and bias (b):

```text
z = w^T x + b
p = sigmoid(z) = 1 / (1 + exp(-z))
```

The training objective is Binary Cross-Entropy with L2 regularization on weights (the bias is not regularized):

```text
J(w,b) = -(1/m) * sum[y log(p) + (1-y) log(1-p)]
         + (lambda / (2m)) * sum(w_j^2)
```

### 3. Batch Gradient Descent

The analytical gradients are implemented explicitly:

```text
dw = X^T (p - y) / m + (lambda / m) * w
db = sum(p - y) / m
```

Parameters are updated using the selected learning rate:

```text
w = w - learning_rate * dw
b = b - learning_rate * db
```

### 4. Newton-Raphson optimization

The implementation calculates the Logistic Regression Hessian, adds numerical damping, and solves the Newton linear system:

```text
theta_next = theta - step_size * direction
(H + damping * I) * direction = gradient
```

The Hessian is formed using (p_i(1-p_i)), the augmented feature matrix (including the bias column), and the L2 term on feature weights only. A backtracking line search accepts a step only when it decreases the regularized loss.

The linear system is solved by a hand-implemented **Gaussian Elimination with Partial Pivoting**, including forward elimination and back substitution. The model does not delegate this solve to `numpy.linalg.solve` or `numpy.linalg.pinv`.

### 5. Optimization comparison

The Optimization Lab runs the implemented Batch Gradient Descent and Newton-Raphson methods on the same deterministic, class-balanced training sample and compares measured loss, iterations, runtime, and convergence history.

Implementation: `src/phishx/models/logistic_regression.py` and `src/phishx/data/preprocessing.py`.

**Scope clarification:** `docs/tld_popularity_ablation.json` is a historical, separate 16-feature audit experiment built with scikit-learn Logistic Regression. It is not the deployed five-feature PHISH-X model and is not the source of the performance metrics reported for the current application.

## Training and evaluation design

- Uses the pre-generated **Group Split by Host** manifests.
- Validates URLs, host manifests, label consistency, feature values, uniqueness, and train/test host separation.
- Fits preprocessing statistics on Group Train only; Group Test is transformed once using the saved training scaler.
- Trains the manual Newton Logistic Regression implementation.
- Evaluates on the held-out Group Test set and reports accuracy, confusion matrix, and precision/recall/F1 separately for Phishing and Legitimate.
- Saves the inference artifact and a JSON evaluation report under `data/processed/model_artifacts/`.

Class-specific metrics matter: a single positive-class precision/recall pair can be misleading when the positive label is Legitimate. The Model Evaluation page therefore labels both classes explicitly.

## Repository data required

The training loader expects these files:

- `data/processed/cleaned_dataset.csv`
- `data/processed/splits/group_train.csv`
- `data/processed/splits/group_test.csv`

The raw feature source used by the project is documented in the feature specification. Dataset files and generated model artifacts may not be present in every clone; obtain the approved project dataset separately if they are not included.

## Setup

Use Python 3.10–3.13 (the GitHub Actions test matrix covers these versions).

From the repository root:

```bash
python -m venv .venv
```

Activate the environment, then install dependencies:

**Windows PowerShell**
```powershell
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

**macOS / Linux**
```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Train the model

From the repository root, after placing the required dataset files in the paths above:

```bash
python src/phishx/models/train.py
```

This generates:

- `data/processed/model_artifacts/phishx_newton_model.joblib`
- `data/processed/model_artifacts/training_metrics.json`

The serialized Joblib artifact uses pickle internally. Only load an artifact from a trusted source.

## Run the Streamlit workbench

After training has generated the model artifact:

```bash
streamlit run app/main.py
```

The **Model Evaluation** page reads the generated `training_metrics.json`. If the report is missing or does not contain class-specific metrics, regenerate it by running the training command.

## Run tests

From the repository root:

```bash
python -m pytest -q
```

The project also runs automated checks in GitHub Actions across Python 3.10–3.13.

## Explainability: how to read contributions

The contribution view decomposes the model's logit:

```text
logit = bias + sum(feature_contribution_j)
feature_contribution_j = scaled_feature_j * weight_j
```

A positive contribution moves the logit toward **Legitimate (class 1)**; a negative contribution moves it toward **Phishing (class 0)**. These are additive contributions to the model score, not causal claims about why a URL is safe or malicious. Because contributions use standardized feature values, a positive contribution does not necessarily mean the raw feature value is inherently protective.

## Important limitations

- This is a dataset-trained classifier, not a guarantee that every URL will be classified correctly.
- Reported metrics describe the held-out Group Split by Host and may not generalize to future campaigns or changing attacker behaviour.
- URL parsing and several feature definitions intentionally preserve the dataset's legacy contract; known weaknesses are documented in the feature specification.
- The model uses five lexical URL features. It does not query domain reputation, WHOIS, DNS, certificate transparency, or blocklists.
- Structural security advisories are a separate analysis channel and should be interpreted alongside, not as a replacement for, the model result.
- HTTPS alone is not proof that a site is legitimate. A suspicious-looking feature or advisory is not by itself proof of phishing.

## Project structure

```text
app/                         Streamlit workbench
src/phishx/features/         URL parsing and feature extraction
src/phishx/models/            Manual Logistic Regression and training
src/phishx/data/              Numerical scaling and dataset loading
src/phishx/inference.py       Artifact-backed prediction pipeline
src/phishx/explainability/    Additive logit contributions
src/phishx/security_assessment.py
tests/                        Automated unit and integration-contract tests
docs/                         Detailed feature and security specification
```

## Further documentation

- [Project Proposal Summary](docs/PROJECT_PROPOSAL.md)
- [Final Project Report](docs/FINAL_PROJECT_REPORT.md)
- [Presentation, Live Demo & Viva Guide](docs/DEMO_AND_VIVA_GUIDE.md)
- [Dataset & Evaluation Protocol](docs/DATASET_AND_EVALUATION_PROTOCOL.md)
- [Dataset Audit Summary](dataset_audit.md)
- [Detailed Security Dataset Audit](docs/SECURITY_DATASET_AUDIT.md)
- [URL Security & Feature Specification](docs/URL_SECURITY_AND_FEATURE_SPECIFICATION.md)
- [Artifact-backed Inference](docs/ARTIFACT_BACKED_INFERENCE.md)
- [Test Execution Report](docs/TEST_EXECUTION_REPORT.md)
- [Source code](src/phishx/)
- [Automated tests](tests/)
