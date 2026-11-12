# PHISH-X — Dataset Source and Methodology

## 1. Dataset Overview

PHISH-X uses the **LegitPhish Dataset**, published on Mendeley Data.

- Dataset name: LegitPhish Dataset
- Authors: Rachana Potpelwar, Uday Kulkarni, and Jaishri Waghmare
- Publication year: 2025
- Version: 2
- DOI: https://doi.org/10.17632/hx4m73v2sf.2
- Dataset URL: https://data.mendeley.com/datasets/hx4m73v2sf/2
- License: Creative Commons Attribution 4.0 International (CC BY 4.0)

The dataset contains URLs labeled as phishing or legitimate, together with numerical features describing URL characteristics.

## 2. Dataset Structure

The original dataset contains:

- 101,219 records
- 18 columns
- 16 numerical URL features
- 1 URL column
- 1 target label column (`ClassLabel`)

The `ClassLabel` column uses the following encoding:

- `0`: Phishing
- `1`: Legitimate

The URL column is retained for reference, auditing, and URL-level analysis. It should not be used directly as a numerical model input.

## 3. Original Dataset Distribution

The original dataset contains:

| Label | Class | Records |
|---|---|---:|
| 0 | Phishing | 63,678 |
| 1 | Legitimate | 37,540 |
| Missing | Unlabeled | 1 |
| **Total** | | **101,219** |

These figures describe the original dataset before cleaning.

## 4. Data Preparation and Cleaning

The project applies a preparation process to create a cleaned dataset while preserving the original raw file.

The documented cleaning steps are:

1. Load the original dataset.
2. Check the required URL and target-label columns.
3. Normalize the target labels.
4. Remove records with missing or invalid target labels.
5. Remove blank URLs.
6. Check for conflicting labels assigned to the same URL.
7. Remove duplicate URLs while keeping the first occurrence.
8. Save the cleaned dataset without modifying the original raw dataset.

### Cleaning Results

| Check | Result |
|---|---:|
| Original records | 101,219 |
| Missing target labels | 1 |
| Blank URLs | 0 |
| Duplicate URL rows removed | 346 |
| Conflicting URL labels | 0 |
| Cleaned records | 100,872 |

### Cleaned Class Distribution

- Phishing: 63,492
- Legitimate: 37,380
- Total: 100,872

The raw and cleaned datasets are kept separate to preserve the original source data and make the preparation process reproducible.

## 5. Feature Extraction Information

The dataset provides 16 numerical features derived from URL characteristics.

The dataset description mentions Python libraries such as `urllib`, `re`, `tldextract`, and `numpy` in the feature extraction process.

However, the original feature extraction implementation was not found in the PHISH-X project repository. Therefore, the exact extraction formula for every feature cannot be independently confirmed from the available project files.

The PHISH-X team performed independent validation checks by comparing stored feature values with selected interpretations and calculation methods.

Validation results are documented in:

- `docs/FEATURE_REFERENCE.md`
- `docs/FEATURE_VALIDATION_SUMMARY.md`

Features that did not consistently match the tested definitions remain under investigation. No uncertain feature values were automatically corrected or removed during the audits.

## 6. Dataset Splitting Methodology

The project documents two splitting strategies:

### 6.1 Random Stratified Split

- Training records: 80,697
- Testing records: 20,175
- Shared hosts between training and testing: 4,734

This split preserves class proportions but may allow URLs from the same host to appear in both sets.

It is retained as a comparison baseline.

### 6.2 Host-Based Group Split

- Training records: 81,165
- Testing records: 19,707
- Shared hosts between training and testing: 0

This strategy keeps records from the same host in one split only.

It is the primary evaluation strategy because it reduces the risk of host overlap between training and testing data.

Both strategies use a 20% test portion and random state 42, as documented in the project evaluation protocol.

## 7. Dataset Limitations

Several limitations must be considered:

- The dataset may not represent all phishing and legitimate URLs found in real-world environments.
- Phishing and legitimate records have different host distributions.
- Many phishing records use IP addresses, while all legitimate records in the cleaned dataset use domain hosts.
- Some hosts appear repeatedly, which can affect evaluation if host overlap is not controlled.
- The exact extraction formulas for some supplied features are not fully documented or independently verified.
- Strong relationships between individual features and class labels should not automatically be interpreted as proof of data leakage.

These limitations are discussed further in `docs/DATASET_BIAS_AND_LIMITATIONS.md`.

## 8. Reproducibility and Data Integrity

The project maintains separate raw and processed datasets.

The preparation and audit scripts are designed to inspect or prepare data without silently changing the original source file.

Relevant project files include:

- `src/phishx/features/prepare_dataset.py`
- `src/phishx/data_audit.py`
- `src/phishx/feature_audit.py`
- `docs/DATASET_AND_EVALUATION_PROTOCOL.md`

Dataset preparation and evaluation details should be updated if the team changes the preprocessing pipeline, feature set, or splitting strategy.

## 9. Current Project Status

The dataset has been inspected, cleaned, audited, and split using the documented procedures.

The host-based group split is designated as the primary evaluation split.

At the time of writing, the documented dataset audits do not establish final model performance. Model evaluation results should be added after the training and testing experiments are completed.

## 10. Related Documentation

- `dataset_audit.md`
- `docs/DATASET_AND_EVALUATION_PROTOCOL.md`
- `docs/FEATURE_REFERENCE.md`
- `docs/FEATURE_VALIDATION_SUMMARY.md`
- `docs/DATASET_BIAS_AND_LIMITATIONS.md`
- `docs/EVALUATION_METHODOLOGY.md`
- `docs/REFERENCES.md`