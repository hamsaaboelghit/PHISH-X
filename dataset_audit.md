# PHISH-X — Dataset Audit

## 1. Dataset Information

- **Dataset Name:** LegitPhish Dataset
- **Source / URL:** https://data.mendeley.com/datasets/hx4m73v2sf/2
- **DOI:** 10.17632/hx4m73v2sf.2
- **License:** CC BY 4.0
- **Authors:** Rachana Potpelwar, Uday Kulkarni, and Jaishri Waghmare
- **Original Dataset Records:** 101,219
- **Original Columns:** 18
- **Numerical Features:** 16
- **Target Column:** ClassLabel
- **Cleaned Dataset Records:** 100,872

## 2. Target Labels

- **Target Column:** ClassLabel
- **Label Classes:**
  - 0 = Phishing
  - 1 = Legitimate
- **Original Class Distribution:**
  - Phishing (0): 63,678
  - Legitimate (1): 37,540
  - Missing labels: 1
- **Cleaned Class Distribution:**
  - Phishing (0): 63,492
  - Legitimate (1): 37,380
- **Class Imbalance:** The dataset is moderately imbalanced, with phishing records representing approximately 63% of the cleaned dataset.

## 3. Data Quality

- **Missing Values:** One missing target label in the original dataset.
- **Duplicate URLs:** 346 duplicate URL records were identified and removed during cleaning.
- **Invalid or Blank URLs:** No blank URLs were found in the original dataset. URL parsing limitations and malformed URL structures were identified during feature validation.
- **Inconsistent Labels:** No URLs with conflicting labels were found.
- **Cleaning:** Missing-label records, blank URLs, and duplicate URLs were handled by the preparation script. The original raw dataset was preserved without modification.

## 4. Data Leakage Checks

- **Identifier Columns:** The original URL column is retained for reference and URL analysis, but should not be used directly as a numerical model feature.
- **Duplicate URLs Across Splits:** The primary host-based split is designed to prevent shared hosts between training and testing data.
- **Domain Overlap:** The primary group split contains zero shared hosts between training and testing sets.
- **Random Split Comparison:** The random stratified split contains 4,734 shared hosts and is retained for comparison only.
- **Suspicious or Leakage-Prone Features:** Dataset-level patterns require attention. In particular, legitimate records use domain hosts, while a large proportion of phishing records use IP addresses. The `tld_popularity` feature also shows a strong association with the target label. These patterns may encourage shortcut learning and require further investigation. They do not, by themselves, prove target leakage.

## 5. Feature Review

- **URL-Based Features:** All 16 numerical features are derived from URL-related information.
- **Non-URL Features:** No independent non-URL numerical features were identified.
- **Features Validated Under Tested Definitions:**
  - `url_length`
  - `number_of_digits`
  - `dot_count`
  - `url_entropy`
  - `https_flag`
  - `has_hyphen_in_domain`
  - `percentage_numeric_chars`
- **Features with Minor Discrepancies:**
  - `path_length`: 10 mismatches.
  - `has_ip_address`: 22 mismatches.
- **Features Requiring Investigation:**
  - `domain_name_length`
  - `tld_length`
  - `subdomain_count`
  - `token_count`
  - `query_param_count`
  - `tld_popularity`
  - `suspicious_file_extension`
- **Features to Exclude:** No feature is excluded at this stage. Features requiring investigation should remain under review and should not be silently corrected or removed without further evidence.

## 6. Final Decision

- [ ] Approved
- [x] Approved with Modifications
- [ ] Rejected

### Notes

The cleaned dataset is suitable for preliminary experiments under the documented conditions.

The original raw dataset must remain unchanged. Features with uncertain extraction rules or observed discrepancies must be documented and investigated before making final feature-selection decisions.

The host-based group split is the primary evaluation strategy because it prevents host overlap between training and testing data. The random stratified split is retained only as a comparison.

This decision is provisional and does not represent final approval of model performance. Final acceptance depends on model evaluation, robustness testing, and further investigation of dataset limitations.

**Reference:** `docs/FEATURE_VALIDATION_SUMMARY.md` and `docs/DATASET_AND_EVALUATION_PROTOCOL.md`.