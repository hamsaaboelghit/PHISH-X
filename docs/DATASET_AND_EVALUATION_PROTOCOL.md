
# PHISH-X
## Dataset & Evaluation Protocol

### 1. Project Objective

PHISH-X is an explainable AI-based phishing URL detection system.

The system aims to classify URLs into:
- Phishing (0)
- Legitimate (1)

The project uses URL-derived numerical features and Logistic Regression, with numerical optimization methods forming a core part of the project.

---

### 2. Dataset Information

- Dataset: LegitPhish Dataset
- Original records: 101,219
- Original columns: 18
- Cleaned records: 100,872
- Final features and target columns: 18

Target mapping:
- 0 = Phishing
- 1 = Legitimate

---

### 3. Data Cleaning Decisions

The following operations were performed:

| Operation | Removed records |
|---|---:|
| Missing or invalid labels | 1 |
| Missing or blank URLs | 0 |
| Duplicate URLs | 346 |
| Conflicting URL labels | 0 |

Final dataset:
- 100,872 records
- 63,492 Phishing
- 37,380 Legitimate
- No missing labels
- No duplicate URLs

The original raw dataset was preserved without modification.

Output:
`data/processed/cleaned_dataset.csv`

---

### 4. Dataset Quality Findings

The following findings require attention during model development:

1. The dataset contains 64,001 unique hosts.
2. All legitimate records use domain hosts.
3. 48,894 phishing records use IP addresses.
4. Only one host appeared in both classes: github.com.
5. The `tld_popularity` feature has a strong relationship with the target and requires further investigation.
6. Some stored features have not yet been validated against our own extraction definitions.

These findings indicate potential dataset bias and must be considered when interpreting model performance.

---

### 5. Baseline Experiment

An IP-only rule was tested:

- IP Address → Phishing
- Domain → Legitimate

Results:

| Metric | Result |
|---|---:|
| Accuracy | 85.55% |
| Phishing Precision | 100% |
| Phishing Recall | 77.04% |
| Phishing F1-score | 87.03% |

This experiment demonstrates that a single feature can achieve high accuracy on this dataset.

Therefore, accuracy alone is insufficient to establish model quality.

---

### 6. Dataset Splitting Strategy

Two splitting strategies were generated.

#### A. Random Stratified Split

- Training records: 80,697
- Testing records: 20,175
- Shared hosts: 4,734

This split preserves class proportions but allows hosts to appear in both training and testing.

It will be used for comparison only.

#### B. Group Split by Host

- Training records: 81,165
- Testing records: 19,707
- Shared hosts: 0

All URLs belonging to the same host are assigned to the same partition.

This is the primary evaluation strategy because it tests performance on previously unseen hosts.

---

### 7. Reproducibility

Both splitting strategies use:

- Test size: 20%
- Random state: 42

Generated files:

- `random_train.csv`
- `random_test.csv`
- `group_train.csv`
- `group_test.csv`
- `split_metadata.json`

Location:
`data/processed/splits/`

The generated splits were validated for:
- URL overlap
- Host overlap in Group Split
- Record counts
- Class distributions

---

### 8. Next Development Tasks

1. Investigate dataset bias and feature leakage.
2. Validate remaining URL features.
3. Define the final feature extraction contract.
4. Implement Logistic Regression using NumPy.
5. Implement Gradient Descent and Newton's Method.
6. Compare optimization methods.
7. Evaluate using the fixed Group Split.
8. Build explainability and the Streamlit workbench.

---

### 9. Current Evaluation Decision

Group Split by Host is the primary evaluation strategy.

Random Stratified Split is retained as a comparison experiment.

No model training has been performed yet.
