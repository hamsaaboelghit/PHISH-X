# PHISH-X — Evaluation Methodology

## 1. Purpose

This document describes the methodology used to divide the PHISH-X dataset into training and testing sets.

It explains the difference between random stratified splitting and host-based group splitting, and documents why host-based group splitting is selected as the primary evaluation strategy.

The objective is to evaluate how well the phishing detection model generalizes to URLs from previously unseen hosts.

## 2. Dataset Preparation

The cleaned dataset contains 100,872 records:

- 63,492 Phishing URLs.
- 37,380 Legitimate URLs.

The dataset preparation process included:

1. Removing records with missing target labels.
2. Removing records with missing or blank URLs.
3. Identifying and removing duplicate URLs.
4. Checking for conflicting labels.
5. Preserving the original raw dataset without modification.

The target column is `ClassLabel`:

- `0`: Phishing.
- `1`: Legitimate.

The URL column is retained for reference and host-based grouping. It should not be used directly as a numerical model input unless a separate experiment explicitly defines that approach.

## 3. Data Splitting Strategies

Two splitting strategies were prepared for comparison.

### 3.1 Random Stratified Split

The random stratified split divides the dataset into training and testing sets while maintaining approximately the same class distribution in both sets.

Documented configuration:

- Training records: 80,697.
- Testing records: 20,175.
- Test proportion: 20%.
- Random state: 42.
- Shared hosts between training and testing: 4,734.

**Advantages:**

- Maintains approximate class proportions.
- Provides a reproducible random baseline.
- Useful for comparison with other evaluation strategies.

**Limitation:**

URLs from the same host may appear in both training and testing sets. This can make the test set less independent and may overestimate performance on previously unseen hosts.

### 3.2 Host-Based Group Split

The host-based group split assigns all URLs belonging to the same host to only one of the two sets.

Documented results:

- Training records: 81,165.
- Testing records: 19,707.
- Shared hosts between training and testing: 0.

**Advantages:**

- Prevents the same host from appearing in both training and testing sets.
- Reduces the risk of host-related information overlap.
- Provides a more realistic evaluation of generalization to unseen hosts.

**Limitation:**

The class proportions and record counts may differ from a standard random stratified split because records are assigned according to host groups.

## 4. Primary Evaluation Strategy

The host-based group split is selected as the primary evaluation strategy.

This decision is based on the dataset's host concentration and the possibility that URLs from the same host may share patterns.

A random split could allow the model to learn characteristics associated with hosts that also appear in the test set.

By keeping each host within a single split, the group-based strategy provides a stronger test of generalization to unseen hosts.

The random stratified split is retained as a secondary comparison.

## 5. Reproducibility

The documented split configuration uses:

- Test proportion: 20%.
- Random state: 42.
- Primary strategy: Host-based group splitting.
- Comparison strategy: Random stratified splitting.

The prepared split files are stored under:

`data/processed/splits/`

The directory contains:

- `group_train.csv`
- `group_test.csv`
- `random_train.csv`
- `random_test.csv`
- `split_metadata.json`

These files support consistent experiments using the same prepared data partitions.

## 6. Evaluation Metrics

The following metrics are recommended for evaluating the phishing classification model:

### 6.1 Accuracy

Measures the proportion of all predictions that are correct.

### 6.2 Precision

Measures the proportion of URLs predicted as phishing that are actually phishing.

### 6.3 Recall

Measures the proportion of actual phishing URLs correctly identified by the model.

### 6.4 F1-Score

Provides a balance between precision and recall using their harmonic mean.

### 6.5 Confusion Matrix

Shows the number of:

- True Positives.
- True Negatives.
- False Positives.
- False Negatives.

For a phishing detection system, recall is particularly important because missed phishing URLs may expose users to security risks. Precision is also important because excessive false alarms can reduce user trust.

For binary evaluation, class `0` (Phishing) is the positive class (pos_label=0).

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1-Score = 2 × (Precision × Recall) / (Precision + Recall)

The averaging method must be stated explicitly when reporting metrics. For confusion matrices, class `0` is positive and class `1` is negative.

## 7. Important Evaluation Considerations

1. The test set must remain separate from model training and model selection.
2. Preprocessing steps that learn parameters from data must be fitted using training data only.
3. Feature selection and hyperparameter tuning must not use the final test set.
4. Evaluation should use the host-based group split as the primary result.
5. Random split results should be reported separately for comparison.
6. Metrics should be interpreted alongside dataset bias and feature limitations.
7. Final performance claims should only be made after the model has been trained and evaluated.

## 8. Current Evaluation Status

The dataset cleaning and splitting stages have been documented, and both split strategies have been prepared.

However, the final machine learning model evaluation results are not included in this document.

Model training, prediction results, metric values, and final performance comparisons must be added after the AI implementation and evaluation stages are completed.

## 9. Related Documentation

- `docs/DATASET_AND_EVALUATION_PROTOCOL.md`
- `docs/FEATURE_VALIDATION_SUMMARY.md`
- `docs/FEATURE_REFERENCE.md`
- `docs/DATASET_BIAS_AND_LIMITATIONS.md`
- `dataset_audit.md`

## 10. Conclusion

The evaluation methodology uses host-based group splitting as the primary strategy to reduce host overlap between training and testing data.

The random stratified split provides a useful comparison, while the group-based split offers a more meaningful assessment of generalization to unseen hosts.

Final model performance must be measured and reported after model implementation, without using the test set during training or model selection.