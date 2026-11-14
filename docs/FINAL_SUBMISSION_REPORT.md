# PHISH-X — Final Project Report

**Project:** PHISH-X (Phishing X-Ray)  
**Course:** MATH 301 — Numerical Computations  
**Submission date:** 14 November 2026  
**Repository:** https://github.com/hamsaaboelghit/PHISH-X

---

## Abstract

PHISH-X is a software-only, explainable phishing-URL analysis workbench. It combines a manually implemented Logistic Regression training pipeline with numerical optimization, URL feature analysis, additive model-score explanations, and an independent structural security assessment. The application is delivered through a Streamlit interface intended to support analyst investigation and educational demonstration.

The system analyzes the submitted URL string locally. It does not visit the destination, send HTTP requests, perform DNS lookups, or query external reputation services. Its output is therefore a model-based assessment of URL characteristics, not a live verification of the website.

## 1. Introduction and Problem Statement

Phishing URLs can imitate legitimate services through their length, character composition, domain structure, and path patterns. A binary prediction alone gives an analyst limited insight into why a URL was flagged. PHISH-X addresses this by presenting class probabilities, feature-level contributions to the model score, and separate structural advisories.

The project also demonstrates numerical-computation concepts in a complete machine-learning workflow. Rather than relying on a library estimator to fit Logistic Regression, the project implements the objective function, analytical derivatives, Gradient Descent, Newton-Raphson optimization, and a linear-system solver.

## 2. Project Objectives

The project aims to:

1. Build a Logistic Regression classifier for phishing-URL classification.
2. Implement the core optimization and numerical linear-algebra methods directly from their mathematical formulations.
3. Use a host-grouped train/test evaluation protocol to reduce host overlap between partitions.
4. Keep preprocessing consistent across training, evaluation, and inference.
5. Explain the model score using additive feature contributions.
6. Separate machine-learning predictions from independent URL-structure security advisories.
7. Provide an integrated analyst-facing interface for investigation, evaluation, optimization, and controlled threat simulation.

## 3. System Scope and Architecture

### 3.1 End-to-end workflow

1. **URL input:** an analyst enters a URL string into the application.
2. **Feature extraction:** the application extracts the five numerical model inputs in the exact training order.
3. **Preprocessing:** saved training-set standardization parameters transform the feature vector.
4. **Inference:** the saved Logistic Regression parameters and sigmoid function calculate the probability of class 1 (Legitimate).
5. **Classification:** the application presents the predicted class and both class probabilities using the configured decision threshold.
6. **Explanation:** the weighted feature contributions are displayed in log-odds space.
7. **Structural inspection:** independent URL checks generate security advisories. These checks do not silently alter the ML feature vector or prediction.
8. **Presentation:** Streamlit pages expose investigation, dataset, evaluation, optimization, simulation, and uncertainty-analysis capabilities.

### 3.2 Model input contract

The deployed model consumes exactly these five features, in this order:

| Order | Feature | Description |
|---:|---|---|
| 1 | `url_length` | Length of the URL string |
| 2 | `number_of_digits` | Number of numeric characters |
| 3 | `url_entropy` | Character-distribution entropy |
| 4 | `dot_count` | Number of dots |
| 5 | `path_length` | Length of the URL path |

The active feature specification is `1.0-legacy`. The dataset/extractor representation can contain 16 features, but the current Logistic Regression artifact uses only the five inputs listed above. The label mapping is **0 = Phishing** and **1 = Legitimate**.

### 3.3 Architectural separation

PHISH-X keeps three kinds of output distinct:

- **ML classification:** the class prediction and class probabilities produced by the trained Logistic Regression model.
- **Model explanation:** additive contributions showing how each standardized feature affects the model logit.
- **Structural security advisories:** rule-based observations about URL syntax and structure.

A structural warning is not a verified verdict about a destination and does not automatically change the ML prediction.

## 4. Numerical Methods and Mathematical Implementation

The model-fitting and optimization routines are implemented in the project source code. The project does not use a built-in Logistic Regression estimator or library optimizer to train the deployed model.

### 4.1 Feature standardization

For feature (j), the training mean is:

`mean_j = (1/n) * sum(x_ij)`

The population standard deviation is:

`std_j = sqrt((1/n) * sum((x_ij - mean_j)^2))`

Each feature value is transformed as:

`z_ij = (x_ij - mean_j) / std_j`

A constant feature uses a scale of 1 to avoid division by zero. The scaler is fitted using Group Train only; the saved parameters are then reused for Group Test and inference. This avoids fitting preprocessing statistics on the held-out test data.

### 4.2 Logistic Regression and sigmoid

For standardized feature vector (x), weights (w), and bias (b):

`z = w^T x + b`

`p = sigmoid(z) = 1 / (1 + exp(-z))`

The output (p) represents the model probability for class 1 (Legitimate). The Phishing probability is (1-p).

### 4.3 Binary cross-entropy with L2 regularization

The objective is:

`J(w,b) = -(1/n) * sum[y_i log(p_i) + (1-y_i) log(1-p_i)] + (lambda/(2n)) * ||w||^2`

The L2 term applies to the weights, not the bias. Probability handling is implemented with numerical stability in mind.

### 4.4 Analytical gradients

For the weight vector:

`gradient_w = (1/n) * X^T (p-y) + (lambda/n) * w`

For the bias:

`gradient_b = (1/n) * sum(p-y)`

These derivatives are calculated by the project implementation and supplied to the optimization routines.

### 4.5 Gradient Descent

Gradient Descent iteratively updates the parameters:

`w_(k+1) = w_k - alpha * gradient_w`

`b_(k+1) = b_k - alpha * gradient_b`

The Optimization Lab presents the implemented method's loss/convergence history and related run information.

### 4.6 Newton-Raphson optimization

The Hessian for the weight parameters is based on:

`H = (1/n) * X^T R X + (lambda/n) * I`

where (R) is diagonal with entries (p_i(1-p_i)). The implemented parameter system includes the bias term and damping.

The Newton update is:

`theta_(k+1) = theta_k - (H + damping*I)^(-1) * gradient`

The implementation does not calculate the inverse using a library inverse routine. It solves the linear system using the project's manually implemented **Gaussian Elimination with Partial Pivoting**. Damping, line search, and convergence/stopping checks are also applied.

The recorded training configuration uses:

| Setting | Value |
|---|---:|
| Optimizer | Newton-Raphson |
| L2 regularization | 0.001 |
| Damping | 1e-8 |
| Convergence tolerance | 1e-7 |
| Maximum iterations | 100 |
| Recorded convergence | 10 iterations |

## 5. Dataset Preparation and Evaluation Protocol

The evaluation uses a held-out **Group Split by Host**. URLs are grouped by host before partitioning to reduce the risk of URLs from the same host appearing in both training and test sets. The scaler is fitted on the training partition only.

### 5.1 Dataset snapshot

The recorded dataset audit reports:

| Item | Count |
|---|---:|
| Raw rows | 101,219 |
| Phishing rows | 63,678 |
| Legitimate rows | 37,540 |
| Rows with missing label | 1 |
| Duplicate rows | 346 |
| Distinct URLs represented among duplicate rows | 302 |
| Cleaned rows | 100,862 |
| Group Train samples | 81,525 |
| Group Test samples | 19,337 |
| Shared hosts between Group Train and Group Test | 0 |

The cleaned dataset and recorded partitions were reported without missing values or duplicate URLs. Dataset counts describe the recorded project data and may change if the source dataset is replaced or refreshed.

### 5.2 Evaluation setup

- Evaluation partition: held-out Group Test by Host.
- Test sample count: **19,337**.
- Decision threshold: **0.5**.
- Label mapping: **0 = Phishing**, **1 = Legitimate**.

### 5.3 Confusion matrix

The following matrix uses **Phishing as the positive class**, consistent with the class-specific metrics below.

| | Predicted Phishing | Predicted Legitimate |
|---|---:|---:|
| Actual Phishing | TP = 11,481 | FN = 246 |
| Actual Legitimate | FP = 126 | TN = 7,484 |

### 5.4 Recorded held-out results

| Metric | Result |
|---|---:|
| Accuracy | 98.08% |
| Phishing precision | 98.91% |
| Phishing recall | 97.90% |
| Phishing F1-score | 98.41% |
| Legitimate precision | 96.82% |
| Legitimate recall | 98.34% |
| Legitimate F1-score | 97.57% |

These are the recorded results for the current held-out test split and model artifact. They are not a guarantee of performance on every future URL or on a different dataset. They are not presented as a fresh retraining result from the final documentation update.

## 6. Explainability

The Logistic Regression logit can be decomposed into additive terms:

`z = bias + sum_j(w_j * z_j)`

A positive contribution moves the logit toward class 1 (Legitimate); a negative contribution moves it toward class 0 (Phishing). Contributions explain how the fitted linear model formed its score, relative to the training-set scaling.

These values are **not causal explanations**. They describe the model's internal scoring calculation and should not be interpreted as proof that a particular URL characteristic caused a website to be malicious or legitimate.

## 7. Independent Structural Security Assessment

The security assessment checks URL structure separately from the machine-learning classifier. Depending on the input and parser outcome, checks can flag suspicious or unsupported schemes, misleading user-information components, repeated scheme patterns, user-info fields, invalid ports, punycode, embedded URLs, obfuscated IP representations, direct IP hosts, and incomplete strict parsing.

Important interpretation notes:

- A structural flag is an advisory for analyst attention, not a confirmed malicious verdict.
- No structural flags does **not** guarantee that a URL is safe.
- Structural advisories do not silently modify the classifier's prediction.
- The application analyzes the URL string; it does not verify the live destination.

## 8. Application Modules

The Streamlit workbench provides the following analytical views:

| Module | Purpose |
|---|---|
| Security Operations Overview | Central summary of phishing intelligence, dataset composition, and analytical readiness |
| Dataset Intelligence | Dataset composition, quality, and feature-oriented information |
| Model Evaluation | Held-out metrics, class-specific results, confusion matrix, and model metadata |
| Optimization Lab | Comparison of implemented Gradient Descent and Newton-Raphson behavior, including convergence history |
| URL Investigation | Prediction, class probabilities, feature contributions, and independent security advisories |
| Threat Simulation Lab | Controlled synthetic URL variations and comparison of resulting model outputs |
| Confidence & Uncertainty Lab | Probability balance, decision margin, threshold sensitivity, and score-based uncertainty indicators |

The Threat Simulation Lab is a controlled sensitivity experiment using synthetic lexical/structural perturbations. It is not a complete adversarial-robustness benchmark. The Confidence & Uncertainty Lab presents score-based indicators; these should not be described as calibrated probabilities unless a separate calibration procedure has been performed.

## 9. Reproducibility and Execution

From the repository root, with the project environment activated:

```bash
pip install -r requirements.txt
python src/phishx/models/train.py
streamlit run app/main.py
python -m pytest tests -q
```

The training process writes runtime artifacts under:

- `data/processed/model_artifacts/phishx_newton_model.joblib`
- `data/processed/model_artifacts/training_metrics.json`

The generated model artifact is local runtime output and is intentionally not committed as a source file. Re-run training to regenerate it from the available dataset.

For direct artifact-backed inference from the repository root, ensure the source package is on the Python path, for example:

```powershell
$env:PYTHONPATH="src"
python -c "from phishx.inference import load_model_artifact, predict_url; m=load_model_artifact('data/processed/model_artifacts/phishx_newton_model.joblib'); print(predict_url('https://example.com/login', m))"
```

## 10. Validation and Test Evidence

The integrated code was tested locally on **14 November 2026**. The full test command was:

```bash
python -m pytest tests -q
```

The recorded run completed with:

| Test result | Count |
|---|---:|
| Passed | **324** |
| Skipped | **1** |
| Passed subtests | **190** |
| Runtime | **18.28 seconds** |

GitHub Actions completed successfully for the supported Python versions **3.10, 3.11, 3.12, and 3.13** on the latest code validation cycle.

Additional integration checks confirmed that the saved Newton model artifact could be loaded and used for a URL prediction, returning class probabilities, five model features, and a structural security-assessment status. The Streamlit application was also launched successfully in the local environment.

The README-only documentation commit `17cb145` followed the code validation. The test count above refers to the recorded local test run; the documentation-only change did not modify application code. These checks do not represent a new model-training run or a fresh recalculation of the held-out metrics.

## 11. Limitations and Responsible Use

1. The deployed classifier uses five legacy numerical features, not all 16 features available in the broader dataset representation.
2. Feature definitions follow the legacy dataset specification to preserve training/inference parity.
3. The application does not visit URLs, inspect page content, follow redirects, or verify live website behavior.
4. It does not perform DNS, WHOIS, certificate-transparency, domain-reputation, or external threat-feed lookups.
5. HTTPS does not prove that a website is legitimate.
6. Dataset representativeness and distribution changes can affect real-world performance.
7. Feature contributions explain the model score; they are not causal claims.
8. Structural advisories are indicators for analyst attention, not definitive classifications.
9. Synthetic URL perturbations do not establish comprehensive adversarial robustness.
10. Score-based uncertainty indicators are not a substitute for probability calibration or human review.

PHISH-X is intended as an educational and decision-support workbench. Suspicious results should be reviewed by a human analyst and corroborated using appropriate security procedures.

## 12. Project Team

| Team Member | Project Role |
|---|---|
| **Hamsa Aboelghit** | AI / Team Lead |
| **Noruhan Ali** | AI |
| **Eyad Mohamed** | Security |
| **Roaa Elgarf** | AI |
| **Shawky Ahmed** | Security |
| **Amina Sabry** | AI |

## 13. Conclusion

PHISH-X brings together a manually implemented numerical Logistic Regression pipeline, URL feature extraction, additive model-score explanations, independent structural security advisories, and a Streamlit analyst workbench. Its numerical-computations contribution is demonstrated through standardization, binary cross-entropy, analytical gradients, Gradient Descent, Newton-Raphson optimization, and Gaussian Elimination with Partial Pivoting.

The project also documents its evaluation protocol, dataset limitations, inference scope, and responsible-use boundaries. The result is an explainable educational security-analysis tool that demonstrates how numerical methods can support a practical machine-learning workflow without overstating what URL-only analysis can prove.
