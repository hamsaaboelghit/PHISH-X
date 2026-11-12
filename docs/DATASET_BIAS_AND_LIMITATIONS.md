# PHISH-X — Dataset Bias and Limitations

## 1. Purpose

This document describes potential biases, limitations, and data-related risks identified during the analysis of the PHISH-X dataset.

The objective is to understand how dataset characteristics may affect model training, evaluation, and generalization to previously unseen URLs and hosts.

The findings are based on the original dataset audit and the documented evaluation protocol.

## 2. Dataset Overview

The dataset contains 101,219 original records and 18 columns, including:

- One URL column.
- Sixteen numerical features.
- One target label (`ClassLabel`).

The original class distribution is:

| Class | Meaning | Records |
|---|---|---:|
| 0 | Phishing | 63,678 |
| 1 | Legitimate | 37,540 |
| Missing | Unknown | 1 |

The cleaned dataset contains 100,872 records:

- 63,492 Phishing URLs.
- 37,380 Legitimate URLs.

The cleaning process removed duplicate URL records and the record with a missing target label. The original raw dataset was preserved.

## 3. Identified Dataset Biases

### 3.1 IP Address Distribution Bias

One of the most significant findings is the difference in IP address usage between the two classes.

According to the cleaned dataset audit:

| Class | Records Using Domain Hosts | Records Using IP Addresses |
|---|---:|---:|
| Phishing | 14,598 | 48,894 |
| Legitimate | 37,380 | 0 |

Approximately 77% of phishing records use IP addresses as hosts, while all legitimate records use domain hosts.

This strong difference may allow a machine learning model to rely heavily on IP address presence when making predictions.

However, this pattern may reflect the dataset's collection process rather than the general characteristics of phishing URLs on the internet.

**Potential impact:** The model may perform well on this dataset but may not generalize equally well to real-world phishing URLs that use ordinary domain names.

### 3.2 Host Concentration Bias

The cleaned dataset contains:

- 100,872 records.
- 64,001 unique hosts.
- 12,545 hosts appearing in more than one URL record.
- 455 hosts appearing in more than 10 records.
- 17 hosts appearing in more than 100 records.

The most frequent 1% of hosts account for approximately 22.60% of all records.

The most frequent 5% account for approximately 30.46%, while the most frequent 10% account for approximately 36.81%.

This concentration may cause a model to learn host-specific patterns rather than general phishing characteristics.

**Potential impact:** Random splitting may place URLs from the same host in both training and testing sets, making evaluation results overly optimistic.

### 3.3 TLD Popularity Bias

The `tld_popularity` feature has a strong relationship with the target label.

Its correlation with the class label is approximately 0.593.

The value 1 is concentrated among selected TLDs, particularly:

- `.com`
- `.org`
- `.net`
- `.edu`
- `.gov`

This may encourage the model to associate particular TLD categories with a specific class.

However, this relationship does not prove data leakage or establish that the feature is invalid.

**Potential impact:** The model may learn dataset-specific domain patterns that do not represent general phishing behavior.

### 3.4 Feature Extraction Uncertainty

The original feature extraction implementation was not found in the project repository.

Several features have unresolved extraction rules or discrepancies, including:

- `token_count`
- `query_param_count`
- `tld_length`
- `subdomain_count`
- `domain_name_length`
- `tld_popularity`
- `suspicious_file_extension`

Other features, such as `path_length` and `has_ip_address`, showed a small number of mismatches during independent validation.

**Potential impact:** Uncertain feature definitions may affect reproducibility and consistency when processing new URLs.

## 4. Data Leakage and Evaluation Risks

### 4.1 Random Split Risk

The random stratified split contains 4,734 hosts shared between training and testing sets.

URLs from the same host may have similar characteristics, which can make the test set less independent from the training data.

This does not automatically mean that leakage occurred, but it creates a risk of overestimating generalization performance.

### 4.2 Host-Based Group Split

The host-based group split was created to prevent host overlap between training and testing sets.

The documented split contains:

- 81,165 training records.
- 19,707 testing records.
- Zero shared hosts.

This is the primary evaluation strategy because it provides a more realistic test of generalization to unseen hosts.

The random stratified split is retained as a comparison.

### 4.3 Feature Correlation

Strong relationships between individual features and the target label should be investigated carefully.

A high correlation does not independently establish data leakage. It may reflect genuine dataset patterns, collection bias, or relationships introduced during feature extraction.

Feature importance and model behavior should therefore be examined during evaluation.

## 5. Generalization Limitations

The dataset may not fully represent the diversity of real-world phishing and legitimate URLs.

Potential limitations include:

1. Heavy use of IP addresses among phishing records.
2. No legitimate records using IP address hosts in the cleaned dataset.
3. Concentration of records among a relatively small group of frequent hosts.
4. Possible dependence on selected TLD categories.
5. Uncertain definitions for some numerical features.
6. Potential differences between the dataset collection period and future phishing trends.
7. Limited evidence that the dataset represents all industries, countries, hosting providers, or phishing techniques.

These limitations should be considered when interpreting model performance.

## 6. Recommendations

1. Use host-based group splitting as the primary evaluation strategy.
2. Keep random stratified results as a comparison rather than the main measure of generalization.
3. Investigate feature importance to identify excessive dependence on IP address or TLD-related features.
4. Review uncertain feature extraction rules before making final feature-selection decisions.
5. Test the model on additional datasets when possible.
6. Preserve the original raw dataset and document preprocessing changes.
7. Report dataset limitations alongside model evaluation metrics.
8. Avoid presenting dataset-specific patterns as universal phishing indicators.

## 7. Related Documentation

- `dataset_audit.md`
- `docs/DATASET_AND_EVALUATION_PROTOCOL.md`
- `docs/FEATURE_VALIDATION_SUMMARY.md`
- `docs/FEATURE_REFERENCE.md`

## 8. Conclusion

The PHISH-X dataset provides a useful starting point for phishing URL classification experiments. However, its class distribution, host concentration, IP address patterns, and uncertain feature extraction rules introduce important limitations.

The host-based group split helps reduce host overlap between training and testing data, but it does not eliminate all possible dataset biases.

Model performance should therefore be interpreted in the context of these limitations, and further evaluation on independent datasets is recommended before making claims about real-world generalization.