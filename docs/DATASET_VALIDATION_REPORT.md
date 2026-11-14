# Dataset Validation Report

## 1. Scope

This report documents read-only validation of the PHISH-X datasets, train/test splits, host separation, missing values, duplicate URLs, and feature consistency.

No original dataset, model, feature implementation, or existing documentation was modified.

## 2. Files Reviewed

- `data/raw/url_features_extracted1.csv`
- `data/processed/cleaned_dataset.csv`
- `data/processed/splits/group_train.csv`
- `data/processed/splits/group_test.csv`
- `data/processed/splits/random_train.csv`
- `data/processed/splits/random_test.csv`
- `data/processed/splits/split_metadata.json`
- `src/phishx/features/url_features.py`
- `src/phishx/features/feature_definitions_repro.py`
- `tests/test_dataset_parity.py`
- Relevant dataset and feature documentation under `docs/`

## 3. Dataset and Split Counts

Label mapping from `split_metadata.json`:

- `0` = Phishing
- `1` = Legitimate

| Dataset | Rows | Phishing (0) | Legitimate (1) |
|---|---:|---:|---:|
| Raw dataset | 101,219 | 63,678 | 37,540 |
| Cleaned dataset | 100,862 | 63,482 | 37,380 |
| Group Train | 81,525 | 51,755 | 29,770 |
| Group Test | 19,337 | 11,727 | 7,610 |
| Random Train | 80,689 | 50,785 | 29,904 |
| Random Test | 20,173 | 12,697 | 7,476 |

The raw dataset contains one missing `ClassLabel`, so its labeled records total 101,218.

Both split strategies account for all 100,862 cleaned records:

- Group Split: 81,525 + 19,337 = 100,862.
- Random Split: 80,689 + 20,173 = 100,862.

The metadata reports 4,805 shared hosts for the Random Split and zero for the Group Split.

## 4. Missing Values and Duplicate URLs

| File | Rows with missing values | Missing cells | Duplicate URL rows | Distinct duplicated URLs |
|---|---:|---:|---:|---:|
| cleaned_dataset.csv | 0 | 0 | 0 | 0 |
| group_train.csv | 0 | 0 | 0 | 0 |
| group_test.csv | 0 | 0 | 0 | 0 |
| random_train.csv | 0 | 0 | 0 | 0 |
| random_test.csv | 0 | 0 | 0 | 0 |
| url_features_extracted1.csv | 1 | 1 | 346 | 302 |

The single missing value in the raw dataset is in `ClassLabel`.

No missing URLs were found in the audited files.

The raw dataset contains duplicate URL values: 346 duplicate occurrences across 302 distinct duplicated URL values. No duplicate URLs were found in the processed dataset or split files.

## 5. Group Split Isolation

An independent comparison was performed using the URL and host columns in the Group Train and Group Test files.

| Check | Group Train | Group Test | Shared |
|---|---:|---:|---:|
| Unique URLs | 81,525 | 19,337 | 0 |
| Unique host values | 51,198 | 12,800 | 0 |

Result: no shared URL values or host-column values were found between Group Train and Group Test.

This agrees with `split_metadata.json`, which reports `shared_hosts: 0` for the Group Split.

The host comparison used the provided host column after trimming whitespace and converting values to lowercase.

## 6. Five Model Features: Numeric Validation

The following five features were checked in the cleaned dataset:

- `url_length`
- `number_of_digits`
- `url_entropy`
- `dot_count`
- `path_length`

All five features contain 100,862 valid numeric finite values.

| Feature | Missing | Non-numeric | Infinite | Minimum | Maximum | Unique values |
|---|---:|---:|---:|---:|---:|---:|
| url_length | 0 | 0 | 0 | 10 | 474 | 235 |
| number_of_digits | 0 | 0 | 0 | 0 | 164 | 113 |
| url_entropy | 0 | 0 | 0 | 2.610548625 | 5.871503018 | 12,388 |
| dot_count | 0 | 0 | 0 | 1 | 19 | 18 |
| path_length | 0 | 0 | 0 | 0 | 317 | 198 |

These checks establish numeric value hygiene and observed ranges. They do not, by themselves, establish formula parity.

## 7. Feature Extraction Parity Test

Command executed:

`python -m pytest tests/test_dataset_parity.py -q`

Result:

`18 passed in 9.60s`

The test module:

- Reads `data/raw/url_features_extracted1.csv`.
- Uses rows with non-null, non-empty URLs.
- Checks that all names in `FEATURE_NAMES` exist in the raw dataset.
- Checks that every eligible URL is extracted successfully.
- Compares every extracted feature against its stored dataset value using an absolute tolerance of `1e-6`.

The 18 passing tests consist of two general tests and one parameterized comparison for each of the 16 features.

Result: all 16 extractor features passed the raw-dataset parity checks, including the five model features listed above.

This test validates extraction parity against the raw dataset. It is not a separate direct comparison against every row of `cleaned_dataset.csv`.

## 8. Confirmed Feature Definition Reproducibility Audit

The read-only `feature_definitions_repro.py` audit was also executed against the current cleaned dataset.

- Current rows audited: 100,862.
- Seven confirmed feature formulas had zero mismatches:
  - `query_param_count`
  - `subdomain_count`
  - `has_ip_address`
  - `tld_popularity`
  - `suspicious_file_extension`
  - `tld_length`
  - `domain_name_length`
- 1,298 sentinel rows were excluded from comparisons for `subdomain_count`, `tld_length`, and `domain_name_length`, as specified by the audit.
- Dataset SHA-256: `5f82652f04a00ddc3cba1646666a28b66bb0229a5b6e0fcf136a026260d28d66`

The `token_count` result is explicitly labeled an unknown/rejected audit hypothesis in the script. It produced 48,545 mismatches and is not counted as a confirmed feature-definition failure.

## 9. Documentation Discrepancies and Observations

1. Some existing documentation refers to a historical cleaned dataset of 100,872 rows, while the current cleaned dataset and split metadata contain 100,862 rows. The current split counts consistently sum to 100,862.
2. The current raw dataset has 101,219 rows, including one missing label, while the cleaned dataset has 100,862 rows. The difference is recorded here without assuming its cause.
3. Existing documentation differs in its treatment and historical count of sentinel rows. The current reproducibility audit reports 1,298 sentinel rows. These values were not changed.
4. `FEATURE_DEFINITIONS.md` treats `token_count` as unknown, while other feature documentation describes a proposed definition. The audit hypothesis is not treated as a confirmed feature contract.
5. The metadata reports 4,805 shared hosts for the Random Split. The independent overlap check in this report was performed for the Group Split; the Random Split host count is reported from metadata, not independently recomputed here.

These discrepancies are documented for review. No attempt was made to silently reconcile or alter existing data or documentation.

## 10. Overall Result

- Processed dataset and split counts agree with the current split metadata.
- No missing values or duplicate URLs were found in the processed dataset or split files.
- The raw dataset contains one missing label and duplicate URL values.
- Group Train and Group Test have no shared URL values or provided host-column values.
- All five requested model features passed numeric value checks.
- All 16 extractor features passed the raw-dataset parity test.
- Seven confirmed feature definitions passed the separate reproducibility audit with zero mismatches.
- Historical dataset-count and feature-documentation discrepancies remain documented and unresolved.

This report is a validation record only. It does not authorize changes to the original datasets, feature definitions, model implementation, or existing project documentation.
