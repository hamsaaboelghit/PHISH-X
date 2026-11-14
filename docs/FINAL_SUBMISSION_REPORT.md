# PHISH-X — Final Project Report

## 1. Project Overview

**PHISH-X (Phishing X-Ray)** is a software-only phishing URL analysis workbench. It classifies a submitted URL as **Phishing** or **Legitimate**, displays the two class probabilities, explains the model score through feature contributions, and reports separate URL-structure security advisories.

The application analyses the URL string locally. It does not open the submitted URL, send HTTP requests, perform DNS lookups, or verify whether a website is currently active.

## 2. Problem Statement and Objectives

Phishing URLs can imitate legitimate services through URL structure and naming patterns. A useful first-line analysis tool should provide more than a binary label: it should expose the model's confidence, show how the input features affect the score, and distinguish statistical predictions from independent security warnings.

The project objectives are to:
- implement a Logistic Regression classifier using numerical-computation methods coded from their mathematical equations;
- train and evaluate it using a host-grouped train/test split;
- preserve consistent preprocessing between training, evaluation, and inference;
- provide interpretable additive feature contributions;
- present an independent structural security assessment and a usable analyst interface.

## 3. System Architecture

The pipeline is:

1. **URL input:** the analyst supplies a URL string.
2. **Feature extraction:** the application extracts the five model inputs in the exact training order.
3. **Preprocessing:** the saved training-set standardization parameters transform the feature vector.
4. **Inference:** the saved Logistic Regression coefficients and sigmoid function produce the probability of the Legitimate class.
5. **Explanation:** each feature's weighted contribution is displayed in log-odds space.
6. **Security assessment:** separate structural checks produce advisories; these checks are not silently added to the classifier's feature vector.
7. **Presentation:** Streamlit pages provide URL Investigation, Optimization Lab, Dataset Intelligence, and Model Evaluation.

### Model input contract

The current model uses these five numerical features, in this exact order:

1. `url_length`
2. `number_of_digits`
3. `url_entropy`
4. `dot_count`
5. `path_length`

The current label mapping is **0 = Phishing** and **1 = Legitimate**. The feature specification is `1.0-legacy`. Although the dataset feature representation contains 16 features, the current Logistic Regression model consumes only the five listed above.

## 4. Numerical Methods Implemented

The classifier and its optimization routines are implemented directly in the project source code. The project does not use a built-in Logistic Regression estimator or a library optimizer to fit the model.

### 4.1 Numerical standardization

For each feature, the scaler calculates the training-set mean:

`mean_j = (1/n) * sum(x_ij)`

and population standard deviation:

`std_j = sqrt((1/n) * sum((x_ij - mean_j)^2))`

Each value is transformed using:

`z_ij = (x_ij - mean_j) / std_j`

A constant feature uses a scale of 1 to avoid division by zero. The scaler is fitted on Group Train only; the same saved parameters are applied once to Group Test and later to inference inputs.

### 4.2 Logistic Regression and sigmoid

For a feature vector x, weights w, and bias b:

`z = w^T x + b`

`p = sigmoid(z) = 1 / (1 + exp(-z))`

The output p represents the model probability for class 1 (Legitimate). The Phishing probability is `1 - p`.

### 4.3 Binary cross-entropy and L2 regularization

The binary cross-entropy objective is:

`J(w,b) = -(1/n) * sum[y_i log(p_i) + (1-y_i) log(1-p_i)] + (lambda/(2n)) * ||w||^2`

The regularization term applies to weights, not the bias. The implementation uses numerically stable probability handling.

### 4.4 Analytical gradient

For the weight vector:

`gradient_w = (1/n) * X^T (p-y) + (lambda/n) * w`

For the bias:

`gradient_b = (1/n) * sum(p-y)`

These derivatives are calculated in the project implementation and are used by the optimization methods.

### 4.5 Gradient Descent

Gradient Descent updates the parameters iteratively:

`w_(k+1) = w_k - alpha * gradient_w`

`b_(k+1) = b_k - alpha * gradient_b`

The Optimization Lab runs the hand-implemented method and presents its loss/convergence history.

### 4.6 Newton-Raphson optimization

The Hessian for the weight parameters is based on:

`H = (1/n) * X^T R X + (lambda/n) * I`

where R is the diagonal matrix with entries `p_i(1-p_i)`. The implementation constructs the corresponding parameter system including the bias and damping.

The Newton update is:

`theta_(k+1) = theta_k - (H + damping*I)^(-1) * gradient`

The inverse is not calculated using a library inverse routine. The linear system is solved with the project's manually implemented Gaussian Elimination with Partial Pivoting. The implementation also uses damping, line search, and convergence/stopping checks.

The training pipeline uses Newton-Raphson Logistic Regression with L2 = 0.001, damping = 1e-8, tolerance = 1e-7, and a maximum of 100 iterations. The recorded training run converged in 10 iterations.

## 5. Dataset Split and Evaluation Protocol

The project evaluates on a held-out **Group Split by Host** test set. Grouping by host is intended to reduce leakage from URLs belonging to the same host appearing in both training and test partitions.

The recorded evaluation contains **19,337 test samples**. The model's threshold is 0.5. The class mapping is 0 = Phishing and 1 = Legitimate.

The confusion matrix is reported using:
- TN = actual Phishing predicted Phishing = 11,481
- FP = actual Phishing predicted Legitimate = 246
- FN = actual Legitimate predicted Phishing = 126
- TP = actual Legitimate predicted Legitimate = 7,484

### Recorded evaluation results

| Metric | Result |
|---|---:|
| Accuracy | 98.08% |
| Phishing precision | 98.91% |
| Phishing recall | 97.90% |
| Phishing F1-score | 98.41% |
| Legitimate precision | 96.82% |
| Legitimate recall | 98.34% |
| Legitimate F1-score | 97.57% |

These are the recorded results for the current held-out test split and model artifact. They are not a guarantee of performance on every future URL or on a different dataset.

## 6. Explainability and Security Assessment

The feature explanation decomposes the linear model's logit into additive terms:

`z = bias + sum_j(w_j * z_j)`

A positive contribution moves the logit toward class 1 (Legitimate); a negative contribution moves it toward class 0 (Phishing). Contributions describe how the fitted model formed its score. They are not causal explanations, and a contribution must be interpreted relative to the training-set feature scaling.

Structural security advisories are generated independently from the machine-learning prediction. For example, a direct IP address in a URL may trigger an advisory even though it is not itself proof of phishing. An advisory is not a verified verdict about the destination.

## 7. Application Views

- **URL Investigation:** prediction, class probabilities, feature contributions, numerical breakdown, and independent security advisories.
- **Optimization Lab:** compares the implemented Gradient Descent and Newton-Raphson methods using loss histories, iteration counts, and runtime measurements.
- **Dataset Intelligence:** presents dataset-oriented information available in the application.
- **Model Evaluation:** presents held-out metrics, class-specific precision/recall/F1, confusion matrix, and model metadata.
- **Threat Simulation Lab:** compares model outputs for controlled synthetic URL variations; it is a limited sensitivity experiment, not a full robustness benchmark.
- **Confidence & Uncertainty Lab:** explores class scores, threshold distance, and binary entropy as uncalibrated score-based indicators.

## 8. Reproducibility and Run Instructions

From the repository root, with the project environment activated:

```bash
pip install -r requirements.txt
python src/phishx/models/train.py
streamlit run app/main.py
python -m pytest -q
```

Training writes the model artifact and metrics under:

- `data/processed/model_artifacts/phishx_newton_model.joblib`
- `data/processed/model_artifacts/training_metrics.json`

The generated model artifact is local runtime output and is intentionally not committed as a source file. Re-run training to regenerate it from the available dataset.

## 9. Validation Evidence

The latest user-reported full test run on the integrated project completed with:

- **319 passed**
- **1 skipped**
- **190 subtests passed**

A fresh local rerun on **14 November 2026** produced the same result in 27.93 seconds. The GitHub Actions push workflow for commit `f238f2b77c17f6a3c7aeed12fbfd052820b70e09` also completed successfully.

The Streamlit AppTest for the Model Evaluation view reported no application exceptions and confirmed the expected metric labels were rendered.

These results describe the reported test run; rerun the commands above against the final checked-out commit if a fresh delivery-time verification is required.

## 10. Limitations and Responsible Use

- The classifier currently uses five legacy numerical features, not all 16 features available in the dataset.
- Feature definitions follow the legacy dataset specification; some URL parsing behaviours are intentionally retained for training/inference parity.
- A URL's predicted class is a model estimate, not proof that a site is safe or malicious.
- The application does not visit URLs or verify live site content, certificates, DNS records, redirects, or page behaviour.
- Dataset representativeness and distribution changes can affect real-world performance.
- Feature contributions are model-score explanations, not causal claims.
- Security advisories are indicators for analyst attention, not definitive classifications.

PHISH-X should be treated as a decision-support and educational analysis tool, with suspicious results reviewed by a human analyst.

## Project Team

| Team member | Responsibility |
|---|---|
| Hamsa Aboelghit | AI / Team Lead |
| Noruhan Ali | AI |
| Eyad Mohamed | Security |
| Roaa Elgarf | AI |
| Shawky Ahmed | Security |
| Amina Sabry | AI |

## 11. Conclusion

PHISH-X combines a manually implemented numerical Logistic Regression training pipeline with URL feature extraction, interpretable model-score contributions, independent structural security advisories, and a Streamlit analyst workbench. Its central numerical-computations contribution is the explicit implementation of standardization, binary cross-entropy, analytical derivatives, Gradient Descent, Newton-Raphson optimization, and Gaussian Elimination with Partial Pivoting, supported by a host-grouped evaluation protocol and automated tests.
