# PHISH-X — Final Project Report

**Project:** PHISH-X (Phishing X-Ray)  
**Description:** Explainable phishing URL classification with an independent structural security assessment  
**Course context:** MATH301 — Numerical Computations  
**Implementation:** Python, NumPy, Pandas, Streamlit  
**Report status:** Prepared from the current `main` implementation and the locally executed training/test results reported by the project team on 13 November 2026.

---

## Abstract

PHISH-X is a software-only security workbench that classifies a submitted URL as Phishing or Legitimate. Its central numerical-computations contribution is a Logistic Regression model whose standardization, objective, analytical gradient, Hessian, Gradient Descent optimizer, Newton-Raphson optimizer, and linear-system solver are implemented directly from their mathematical definitions. The trained model is evaluated on a fixed Group Split by Host so that URLs from a host in the training partition do not also appear in the test partition.

The system also explains each model score through additive feature contributions in log-odds space and reports structural URL advisories through a separate rule-based assessment. The advisory layer does not alter the trained model's prediction or probabilities. In the reported held-out test run, the model achieved 98.08% accuracy, with 97.90% phishing recall and 98.91% phishing precision. These results describe this dataset and split; they are not a guarantee of performance on future phishing campaigns.

## 1. Problem statement and objectives

Phishing URLs can imitate legitimate services through deceptive hostnames, URL structure, and other lexical patterns. A useful analyst tool should not only output a class label; it should expose the model score, explain which input features moved that score, and surface structural signals that deserve manual review.

PHISH-X aims to:

1. Classify a URL as **Phishing (0)** or **Legitimate (1)**.
2. Implement and demonstrate numerical optimization rather than relying on a built-in Logistic Regression estimator or optimizer.
3. Compare Batch Gradient Descent with Newton-Raphson on the same objective.
4. Explain predictions using additive feature contributions.
5. Keep deterministic structural security findings separate from statistical model probabilities.
6. Evaluate on a host-separated test partition and document dataset limitations.

## 2. System architecture

The application follows this pipeline:

```text
URL entered by analyst
        |
        v
Input validation and legacy feature extraction
        |
        +------------------------------+
        |                              |
        v                              v
Five model features              Strict URL signals
        |                              |
        v                              v
Saved numerical scaler           Rule-based assessment
        |                              |
        v                              |
Manual Logistic Regression             |
        |                              |
        +---------------+--------------+
                        |
                        v
       Prediction + probabilities + explanations
                        |
                        v
              Streamlit analyst workbench
```

The prediction path is local. PHISH-X does not visit submitted URLs, perform DNS lookups, send HTTP requests to destinations, or query external reputation services. Structural findings are advisory and never overwrite the classifier's output.

### Main workbench views

- **URL Investigation:** accepts a URL and presents the prediction, class probabilities, feature contributions, numerical score breakdown, extraction warnings, actual parsed host, and separate structural findings.
- **Optimization Lab:** runs the hand-implemented Batch Gradient Descent and Newton-Raphson methods on the same deterministic, class-balanced sample and compares loss, iterations, runtime, and convergence histories.
- **Dataset Intelligence:** exposes dataset and feature information available in the application.
- **Model Evaluation:** displays held-out sample count, accuracy, threshold, training iterations, class-specific precision/recall/F1, confusion matrix, and evaluation configuration.

## 3. Dataset and evaluation protocol

The project uses the supplied LegitPhish URL dataset. The target mapping is fixed:

- `0` = Phishing
- `1` = Legitimate

The project retains the provided Group Split by Host manifests. The checked-in split metadata records:

| Partition | Records |
|---|---:|
| Group Train | 81,525 |
| Group Test | 19,337 |
| Shared hosts | 0 |

The training command loads raw features from Group Train and Group Test. The numerical scaler is fitted only on Group Train; the same saved training statistics are applied once to Group Test and later to individual URLs. This prevents test-data statistics from leaking into training preprocessing.

A random stratified split is retained as a comparison artifact, but Group Split by Host is the primary evaluation because a host cannot occur in both partitions. The reported test metrics are from one fixed held-out group split, not k-fold cross-validation and not an external live-phishing benchmark.

**Dataset caution:** earlier audit notes and the current split metadata contain different historical record totals. The training/evaluation figures in this report therefore use the exact current split metadata and the 19,337-sample test report generated by the training command. The project should not claim a single total-cleaned-record count without reconciling the historical dataset audit and the current CSV/split manifests.

## 4. Model input contract

The feature extractor reproduces the dataset's legacy feature definitions. The current Logistic Regression model consumes exactly these five features, in this order:

1. `url_length`
2. `number_of_digits`
3. `url_entropy`
4. `dot_count`
5. `path_length`

The extractor calculates a broader set of legacy URL features, but the remaining features are not silently passed to the model. The model artifact stores the exact feature order and feature-specification version. This contract is checked during inference.

## 5. Numerical methods

### 5.1 Numerical standardization

For feature column (j), using (n) training samples:

\[
mu_j = \frac{1}{n}\sum_{i=1}^{n}x_{ij}
\]

\[
\sigma_j^2 = \frac{1}{n}\sum_{i=1}^{n}(x_{ij}-\mu_j)^2
\qquad
s_j=\sqrt{\sigma_j^2}
\]

\[
z_{ij}=\frac{x_{ij}-\mu_j}{s_j}
\]

The implementation uses population variance. If a feature is constant, its scale is set to 1 to avoid division by zero. The fitted means and scales are stored in the model artifact and reused for test-time inference.

### 5.2 Logistic Regression

For a feature vector (x), weights (w), and bias (b):

\[
z=w^Tx+b
\]

\[
p=\sigma(z)=\frac{1}{1+e^{-z}}
\]

The sigmoid implementation uses separate positive/negative branches for numerical stability.

### 5.3 Binary Cross-Entropy with L2 regularization

For (m) training examples:

\[
J(w,b)=-\frac{1}{m}\sum_{i=1}^{m}
\left[y_i\log(p_i)+(1-y_i)\log(1-p_i)\right]
+\frac{\lambda}{2m}\sum_{j=1}^{d}w_j^2
\]

The bias is not regularized. Probabilities are clipped only for safe logarithm evaluation.

### 5.4 Analytical gradient and Batch Gradient Descent

Let (X) be the standardized design matrix and (p) the vector of predicted probabilities:

\[
\nabla_w J=\frac{X^T(p-y)}{m}+\frac{\lambda}{m}w
\]

\[
\frac{\partial J}{\partial b}=\frac{1}{m}\sum_{i=1}^{m}(p_i-y_i)
\]

The batch updates are:

\[
w_{t+1}=w_t-\alpha\nabla_wJ
\qquad
b_{t+1}=b_t-\alpha\frac{\partial J}{\partial b}
\]

The learning rate, iteration limit, and stopping tolerances are explicit parameters. The Optimization Lab measures the loss history rather than presenting a hard-coded comparison.

### 5.5 Hessian and Newton-Raphson

For augmented feature matrix (\tilde X), including a bias column, and diagonal matrix (R) with entries (p_i(1-p_i)), the Hessian has the form:

\[
H=\frac{1}{m}\tilde X^TR\tilde X+\frac{\lambda}{m}P
\]

where (P) applies L2 regularization to feature weights but not the bias.

At each iteration the damped Newton direction (d) is obtained from:

\[
(H+\eta I)d=\nabla J
\]

and the parameters are updated by:

\[
\theta_{t+1}=\theta_t-\gamma d
\]

Damping helps stabilize ill-conditioned systems. A backtracking line search accepts a step only when it reduces the regularized objective. The implementation also checks finite values and stopping tolerances.

### 5.6 Gaussian Elimination with Partial Pivoting

The Newton linear system is solved with a hand-implemented Gaussian Elimination routine:

1. Select the largest-magnitude pivot in the current column.
2. Swap rows when necessary (partial pivoting).
3. Eliminate entries below the pivot.
4. Use back substitution to obtain the solution.

The production Newton path does not delegate this solve to `numpy.linalg.solve` or `numpy.linalg.pinv`. NumPy is used for array storage and vectorized arithmetic; the central optimization and linear-system algorithms are explicit project implementations.

### 5.7 Numerical verification

The test suite includes finite-difference checks of analytical derivatives, Hessian symmetry/positive-semidefinite checks, linear-solver tests, rank-deficient feature cases, and comparisons of the two optimization methods on a shared regularized objective.

## 6. Training procedure

From the repository root, run:

```bash
python src/phishx/models/train.py
```

The script:

1. Loads the raw Group Train and Group Test feature matrices.
2. Fits the manual scaler on Group Train only.
3. Trains Logistic Regression using the implemented Newton-Raphson method.
4. Evaluates the saved artifact on Group Test using the same fitted scaler.
5. Writes the trusted local Joblib model artifact and a JSON metrics report under `data/processed/model_artifacts/`.

The Joblib artifact is generated locally and is intentionally not committed. Joblib uses pickle internally, so only load artifacts from trusted sources.

## 7. Reported training and test results

The project team's local training run on 13 November 2026 reported:

| Training item | Result |
|---|---:|
| Optimizer | Newton-Raphson Logistic Regression |
| L2 coefficient | 0.001 |
| Newton iterations | 10 |
| Initial regularized loss | 0.693147 |
| Final regularized loss | 0.061183 |
| Test samples | 19,337 |
| Decision threshold | 0.5 |

### Overall and class-specific metrics

| Metric | Phishing | Legitimate |
|---|---:|---:|
| Precision | 98.91% | 96.82% |
| Recall | 97.90% | 98.34% |
| F1-score | 98.41% | 97.57% |

Overall accuracy: **98.08%**.

### Confusion matrix

The positive class in the stored binary report is Legitimate (label 1). To avoid ambiguity, the counts are explained by actual class:

| Actual class | Predicted Phishing | Predicted Legitimate |
|---|---:|---:|
| Phishing | 11,481 | 246 |
| Legitimate | 126 | 7,484 |

Thus, 246 phishing URLs were classified as legitimate in this held-out split, while 126 legitimate URLs were classified as phishing. For a security detector, phishing recall is particularly important because it measures the proportion of phishing samples correctly caught.

### Loss convergence

The reported Newton loss decreased from 0.693147 to 0.061183 over 10 accepted iterations. The saved JSON report contains the complete loss history and class-specific metrics.

## 8. Explainability

For standardized model input (z_j), feature weight (w_j), and bias (b):

\[
c_j=w_jz_j
\qquad
\text{logit}=b+\sum_jc_j
\qquad
p(\text{Legitimate})=\sigma(\text{logit})
\]

- A positive contribution increases the logit and moves the prediction toward Legitimate (class 1).
- A negative contribution decreases the logit and moves the prediction toward Phishing (class 0).

Contributions are additive log-odds contributions, not individual probabilities and not causal explanations. Because inputs are standardized, a positive contribution does not mean that a raw feature is inherently safe or protective.

## 9. Independent structural security assessment

A separate deterministic rule-based layer reports structural findings such as misleading user-info, user-info presence, invalid ports, internationalized/punycode hostnames, repeated schemes, embedded URLs, and direct or obfuscated IP destinations.

The layer reports a severity label and actual parsed destination host when available. These findings are advisories, not calibrated probabilities and not proof that a URL is malicious. Crucially, they do not modify the ML class label, threshold, or probabilities.

## 10. Limitations and responsible interpretation

1. The reported metrics describe the supplied dataset and one fixed host-separated test split. They do not guarantee performance on unseen future campaigns.
2. The dataset contains measurable collection and feature biases. A previously documented IP-only baseline achieved high performance, demonstrating why accuracy alone is insufficient.
3. The model uses five lexical URL features; it does not use domain reputation, WHOIS, DNS, certificate transparency, blocklists, page content, or browser behaviour.
4. The legacy feature definitions are preserved for dataset compatibility. Some names are imperfect proxies for their apparent meaning; the feature specification documents these quirks.
5. Structural rules can produce false positives and false negatives. A direct IP can be legitimate, HTTPS does not prove legitimacy, and the absence of a finding does not prove safety.
6. The system is an analyst aid, not an autonomous blocking authority. High-impact decisions require independent investigation.

## 11. Testing and verification

The project team reported this local full-suite result after the current model, evaluation, and UI changes:

```text
319 passed, 1 skipped, 190 subtests passed
```

The team also ran the training CLI and confirmed that it generated the Joblib artifact and `training_metrics.json`. Streamlit's `AppTest` was run against the **Model Evaluation** page and returned:

- `EXCEPTIONS: []`
- All 14 expected metric/configuration labels were present.

This is an automated Streamlit runtime test, not a claim of manual visual inspection in a browser. The latest GitHub Actions push workflow was still running when this report was prepared; consult the repository Actions page for its final result.

## 12. Reproduction and launch

Install dependencies:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run tests:

```powershell
python -m pytest -q
```

Train the model and create local artifacts:

```powershell
python src/phishx/models/train.py
```

Launch the workbench:

```powershell
streamlit run app/main.py
```

For a fresh clone, ensure the approved dataset and split CSVs are present at the paths documented in the README. Generate the model artifact before using URL Investigation or Model Evaluation.

## 13. Conclusion

PHISH-X combines a manually implemented numerical Logistic Regression pipeline with a practical URL-analysis interface. Its strongest course contribution is not merely using a library model: it explicitly computes the objective, gradient, Hessian, Newton direction, and Gaussian-elimination solution, while also implementing and comparing Batch Gradient Descent. The project adds transparent logit contributions and a separate structural advisory channel to make predictions easier to inspect. Its reported results are strong on the supplied host-separated test split, but the dataset limitations and the distinction between model probability and structural warning must remain explicit in any demonstration or submission.
