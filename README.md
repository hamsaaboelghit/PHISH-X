# PHISH-X — Phishing URL Detection & Explanation

**PHISH-X (Phishing X-Ray)** is an explainable cybersecurity workbench for investigating suspicious URLs. It predicts whether a submitted URL is **Phishing** or **Legitimate**, displays both class probabilities, explains the model score through feature contributions, and provides a separate structural security assessment.

PHISH-X combines three complementary layers:

1. **Machine Learning:** a manually implemented Logistic Regression classifier.
2. **Numerical Computations:** standardization, Batch Gradient Descent, Newton-Raphson optimization, Hessian construction, and Gaussian Elimination with Partial Pivoting.
3. **Cybersecurity Analysis:** independent URL-structure advisories that add context without silently changing the ML prediction.

> **Privacy and scope:** URL analysis is performed locally on the supplied string. PHISH-X does not open the submitted URL, send HTTP requests, perform DNS lookups, or check live domain reputation.

## At a glance

- **Application:** Streamlit analyst workbench.
- **Classifier:** artifact-backed Logistic Regression trained with the project's manual Newton-Raphson implementation.
- **Model inputs:** five numerical URL features.
- **Explainability:** additive feature contributions in log-odds space.
- **Security layer:** independent structural checks with severity-labelled findings.
- **Evaluation:** held-out Group Split by Host.
- **Optimization comparison:** manual Batch Gradient Descent vs. Newton-Raphson.

## Workbench modules

| Module | Purpose |
|---|---|
| **Overview** | Project and dataset intelligence at a glance. |
| **Dataset Intelligence** | Dataset composition, quality checks, and analytical readiness. |
| **Model Evaluation** | Held-out evaluation metrics and class-specific performance. |
| **Optimization Lab** | Compare Gradient Descent and Newton-Raphson convergence and runtime. |
| **URL Investigation** | Analyze a URL, inspect its prediction, probabilities, features, and explanation. |
| **Threat Simulation Lab** | Compare controlled lexical and structural URL variations. |
| **Confidence & Uncertainty** | Inspect probability balance, decision margin, and threshold sensitivity. |

Threat simulations are controlled offline perturbations. They are not live attacks or a complete adversarial-robustness benchmark.

## How URL investigation works

For a submitted URL, the inference pipeline:

1. Extracts the model's five features using the production feature extractor.
2. Applies the standardization parameters saved from Group Train.
3. Loads the trained coefficients and calculates the Legitimate-class probability.
4. Derives the Phishing probability as `1 - P(Legitimate)`.
5. Explains the model logit through additive feature contributions.
6. Runs a separate structural URL assessment and returns any findings.

The security assessment is an independent advisory channel. It does **not** alter the model feature vector, class prediction, threshold, or probabilities.

### Model input contract

The deployed model currently uses exactly these five features, in this order:

1. `url_length`
2. `number_of_digits`
3. `url_entropy`
4. `dot_count`
5. `path_length`

The label mapping is fixed:

- `0 = Phishing`
- `1 = Legitimate`

The active feature specification is `1.0-legacy`. The extractor supports a broader 16-feature dataset representation, but only the five features above are passed to the deployed Logistic Regression model. Do not add or reorder model features without versioning the feature contract, regenerating the dataset as needed, and retraining the model.

See [URL Security & Feature Specification](docs/URL_SECURITY_AND_FEATURE_SPECIFICATION.md) for definitions, parser behaviour, warnings, dataset caveats, and known limitations.

## Explainable predictions

PHISH-X decomposes the model logit as:

```text
logit = bias + sum(feature_contribution_j)
feature_contribution_j = scaled_feature_j * weight_j
```

- A **positive** contribution moves the score toward **Legitimate (class 1)**.
- A **negative** contribution moves the score toward **Phishing (class 0)**.

These are contributions to the model score, not causal explanations. A positive contribution does not prove that a raw URL characteristic is safe or protective.

## Independent URL security assessment

Alongside the ML result, PHISH-X inspects URL structure and can report findings such as:

| Finding | Typical severity | What it indicates |
|---|---:|---|
| Misleading user-info | High | Text before `@` may imitate a trusted domain while the actual destination is different. |
| Repeated URL scheme | High | A repeated scheme prefix appears in the URL. |
| Non-HTTP(S) URI scheme | Medium | The input is not a standard web URL covered by the model's training domain. |
| Incomplete structural inspection | Medium | Strict security-oriented parsing could not fully inspect the input. |
| User-info present | Medium | The URL authority contains user-info before the actual host. |
| Invalid port | Medium | The port could not be parsed as valid. |
| Internationalized or punycode hostname | Medium | The hostname may contain visually confusable characters and deserves review. |
| Embedded URL | Medium | The path or query contains another URL. |
| Obfuscated IP destination | Medium | The hostname appears to encode an IPv4 address in a non-standard form. |
| Direct IP destination | Low | The URL targets an IP address rather than a hostname. |

A result of `no_structural_flags` means these implemented checks did not identify a finding; it is **not** a guarantee that the URL is safe. A `warning` status means one or more structural findings were raised. The ML result remains separately visible.

## Numerical methods implemented

The model and optimization routines are implemented directly in the project source code. PHISH-X does not rely on a built-in Logistic Regression estimator or library optimizer to fit the deployed model.

### 1. Numerical standardization

The scaler is fitted on Group Train only. For each feature:

```text
mean_j     = (1 / n) * sum(x_ij)
variance_j = (1 / n) * sum((x_ij - mean_j)^2)
scale_j    = sqrt(variance_j)
z_ij       = (x_ij - mean_j) / scale_j
```

A constant feature uses scale 1 to avoid division by zero. The fitted training statistics are stored in the model artifact and reused unchanged for Group Test and inference.

### 2. Logistic Regression and Binary Cross-Entropy

For input vector (x), weights (w), and bias (b):

```text
z = w^T x + b
p = sigmoid(z) = 1 / (1 + exp(-z))
```

The objective is Binary Cross-Entropy with L2 regularization on weights only:

```text
J(w,b) = -(1/m) * sum[y log(p) + (1-y) log(1-p)]
         + (lambda / (2m)) * sum(w_j^2)
```

### 3. Batch Gradient Descent

The analytical gradients are implemented explicitly:

```text
dw = X^T (p - y) / m + (lambda / m) * w
db = sum(p - y) / m

w = w - learning_rate * dw
b = b - learning_rate * db
```

### 4. Newton-Raphson optimization

The implementation constructs the Logistic Regression Hessian, applies numerical damping, and solves the Newton system:

```text
theta_next = theta - step_size * direction
(H + damping * I) * direction = gradient
```

The Hessian uses `p_i(1-p_i)`, the augmented feature matrix (including the bias column), and L2 regularization on feature weights only. A backtracking line search accepts a step only when it decreases the regularized loss.

### 5. Gaussian Elimination with Partial Pivoting

The Newton linear system is solved by a hand-implemented Gaussian Elimination routine with partial pivoting, forward elimination, and back substitution. The implementation does not delegate this solve to `numpy.linalg.solve` or `numpy.linalg.pinv`.

### 6. Optimization comparison

The Optimization Lab runs the implemented Batch Gradient Descent and Newton-Raphson methods on the same deterministic, class-balanced training sample and compares measured loss, iterations, runtime, and convergence history.

Implementation: `src/phishx/models/logistic_regression.py` and `src/phishx/data/preprocessing.py`.

**Scope clarification:** `docs/tld_popularity_ablation.json` is a separate historical 16-feature audit experiment using scikit-learn Logistic Regression. It is not the deployed five-feature PHISH-X model and is not the source of the current application's performance metrics.

## Training and evaluation design

- Uses the pre-generated **Group Split by Host** manifests.
- Validates URLs, host manifests, label consistency, feature values, uniqueness, and train/test host separation.
- Fits preprocessing statistics on Group Train only.
- Transforms the held-out Group Test set using the saved training scaler.
- Trains the manual Newton Logistic Regression implementation.
- Evaluates accuracy, confusion matrix, and precision/recall/F1 separately for Phishing and Legitimate.
- Saves the inference artifact and a JSON evaluation report under `data/processed/model_artifacts/`.

The Group Split by Host is used to reduce host overlap between training and testing. Metrics describe this held-out dataset split; they are not a guarantee of future performance.

### Recorded held-out evaluation

The current project evaluation records:

| Metric | Result |
|---|---:|
| Accuracy | 98.08% |
| Phishing precision | 98.91% |
| Phishing recall | 97.90% |
| Phishing F1-score | 98.41% |
| Legitimate precision | 96.82% |
| Legitimate recall | 98.34% |
| Legitimate F1-score | 97.57% |

Held-out Group Test size: **19,337 URLs**.

These are recorded results for the current Group Split by Host. Interpret them in the context of the dataset, feature contract, and limitations described below; they should not be treated as a guarantee of real-world detection performance.

## Repository data required

The training loader expects:

- `data/processed/cleaned_dataset.csv`
- `data/processed/splits/group_train.csv`
- `data/processed/splits/group_test.csv`

Dataset files and generated model artifacts may not be present in every clone. Obtain the approved project dataset separately if any required files are missing.

## Setup

Use Python **3.10–3.13** (the GitHub Actions test matrix covers these versions).

From the repository root, create a virtual environment:

```bash
python -m venv .venv
```

Activate it and install dependencies.

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

After placing the required dataset files in the paths listed above, run:

```bash
python src/phishx/models/train.py
```

This generates:

- `data/processed/model_artifacts/phishx_newton_model.joblib`
- `data/processed/model_artifacts/training_metrics.json`

The serialized Joblib artifact uses pickle internally. Only load an artifact from a trusted source.

## Run the Streamlit workbench

After the model artifact has been generated:

```bash
streamlit run app/main.py
```

The **Model Evaluation** page reads the generated `training_metrics.json`. If the report is missing or does not contain class-specific metrics, regenerate it by running the training command.

## Verify artifact-backed inference

From the repository root, with the virtual environment activated and the model artifact present, run:

```bash
python -c "import sys; sys.path.insert(0, 'src'); from phishx.inference import load_model_artifact, predict_url; model = load_model_artifact('data/processed/model_artifacts/phishx_newton_model.joblib'); result = predict_url('https://example.com/login', model); print(result.prediction, result.phishing_probability, result.legitimate_probability)"
```

This check loads and validates the saved artifact, extracts the model inputs, applies the saved scaler, generates a prediction, and returns the independent security assessment. The example URL is an input string only; PHISH-X does not visit it.

## Run tests

From the repository root:

```bash
python -m pytest tests -q
```

GitHub Actions also runs the automated test suite across Python 3.10–3.13. See [Test Execution Report](docs/TEST_EXECUTION_REPORT.md) for the recorded validation details.

## Important limitations and safe interpretation

- PHISH-X is a dataset-trained classifier, not a guarantee that every URL will be classified correctly.
- Reported metrics describe the held-out Group Split by Host and may not generalize to future campaigns or changing attacker behaviour.
- The deployed model uses five lexical URL features. The broader extractor and structural checks do not mean all extracted signals are model inputs.
- The feature specification intentionally preserves parts of the dataset's legacy contract; known weaknesses and parser edge cases are documented in the feature specification.
- The model does not query domain reputation, WHOIS, DNS, certificate transparency, shortener services, or blocklists.
- Security advisories are a separate analysis channel and are not a replacement for the ML result.
- `no_structural_flags` is not a safety certification.
- HTTPS alone is not proof that a site is legitimate.
- A suspicious-looking feature or advisory is not, by itself, proof of phishing.
- Threat Simulation Lab perturbations are controlled synthetic examples, not a full adversarial-robustness evaluation.

## Project structure

```text
app/                              Streamlit workbench
src/phishx/features/              URL parsing, features, and security signals
src/phishx/models/                Manual Logistic Regression and training
src/phishx/data/                  Dataset loading and numerical preprocessing
src/phishx/inference.py            Artifact-backed prediction pipeline
src/phishx/security_assessment.py  Independent structural security findings
src/phishx/explainability/         Additive logit contributions
tests/                             Automated unit and integration-contract tests
docs/                              Project, dataset, security, and evaluation docs
```

## Project Team

PHISH-X is developed by a six-member team:

| Team member | Responsibility |
|---|---|
| Hamsa Aboelghit | AI / Team Lead |
| Noruhan Ali | AI |
| Eyad Mohamed | Security |
| Roaa Elgarf | AI |
| Shawky Ahmed | Security |
| Amina Sabry | AI |

See [Project Team](docs/TEAM.md) for the team overview.

## Further documentation

- [Project Proposal Summary](docs/PROJECT_PROPOSAL.md)
- [Final Project Report](docs/FINAL_PROJECT_REPORT.md)
- [Final Submission Report](docs/FINAL_SUBMISSION_REPORT.md)
- [Presentation, Live Demo & Viva Guide](docs/DEMO_AND_VIVA_GUIDE.md)
- [Dataset & Evaluation Protocol](docs/DATASET_AND_EVALUATION_PROTOCOL.md)
- [Dataset Validation Report](docs/DATASET_VALIDATION_REPORT.md)
- [Dataset Audit Summary](dataset_audit.md)
- [Detailed Security Dataset Audit](docs/SECURITY_DATASET_AUDIT.md)
- [URL Security & Feature Specification](docs/URL_SECURITY_AND_FEATURE_SPECIFICATION.md)
- [Artifact-backed Inference](docs/ARTIFACT_BACKED_INFERENCE.md)
- [Test Execution Report](docs/TEST_EXECUTION_REPORT.md)
- [Source code](src/phishx/)
- [Automated tests](tests/)
