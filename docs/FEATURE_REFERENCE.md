# PHISH-X — Feature Reference

## 1. Purpose

This document describes the 16 numerical features used in the PHISH-X dataset for phishing URL classification.

It provides a reference for each feature, including its meaning, data type, validation status, and known limitations.

The original feature extraction implementation was not found in the project repository. Therefore, definitions marked as unconfirmed should not be treated as verified extraction formulas.

## 2. Feature Reference

| No. | Feature | Description | Type | Validation Status |
|---|---|---|---|---|
| 1 | `url_length` | Total number of characters in the complete URL. | Numerical | Validated |
| 2 | `has_ip_address` | Indicates whether an IP address is detected in the URL. | Binary | Partially Validated |
| 3 | `dot_count` | Number of dots in the complete URL. | Numerical | Validated |
| 4 | `https_flag` | Indicates whether the URL uses the HTTPS scheme. | Binary | Validated |
| 5 | `url_entropy` | Shannon entropy calculated from the characters of the complete URL. | Numerical | Validated |
| 6 | `token_count` | Number of tokens identified in the URL. The original tokenization method is unknown. | Numerical | Requires Investigation |
| 7 | `subdomain_count` | Represents the number of subdomains associated with the URL hostname. The original counting method is unconfirmed. | Numerical | Requires Investigation |
| 8 | `query_param_count` | Represents the number of query parameters in the URL. The stored values do not consistently match standard query parsing. | Numerical | Requires Investigation |
| 9 | `tld_length` | Represents the length of the top-level domain. Port handling and missing protocols affect the observed values. | Numerical | Requires Investigation |
| 10 | `path_length` | Length of the URL path component. | Numerical | Validated with Minor Discrepancies |
| 11 | `has_hyphen_in_domain` | Indicates whether the extracted hostname contains a hyphen. | Binary | Validated for Extracted Hostnames |
| 12 | `number_of_digits` | Total number of numeric digits in the complete URL. | Numerical | Validated |
| 13 | `tld_popularity` | Binary feature associated with selected top-level domains. The exact classification rule is unknown. | Binary | Requires Investigation |
| 14 | `suspicious_file_extension` | Indicates whether a URL is associated with a suspicious file extension. The original extension list and detection method are unknown. | Binary | Requires Investigation |
| 15 | `domain_name_length` | Represents the length of the domain name component. The exact extraction rule is unconfirmed. | Numerical | Requires Investigation |
| 16 | `percentage_numeric_chars` | Percentage of URL characters that are numeric digits, calculated using the digit count and URL length. | Numerical | Validated |

## 3. Feature Categories

### 3.1 URL Structure Features

These features describe the overall structure and components of a URL:

- `url_length`
- `dot_count`
- `path_length`
- `token_count`
- `query_param_count`
- `number_of_digits`
- `percentage_numeric_chars`
- `url_entropy`

### 3.2 Domain and Host Features

These features describe domain-related characteristics:

- `has_ip_address`
- `subdomain_count`
- `tld_length`
- `has_hyphen_in_domain`
- `tld_popularity`
- `domain_name_length`

### 3.3 Security-Related Features

These features represent selected security-related URL indicators:

- `https_flag`
- `suspicious_file_extension`

## 4. Data Types

The dataset contains two main feature types:

- **Numerical features:** Values representing counts, lengths, percentages, or entropy.
- **Binary features:** Values representing two possible states, generally 0 and 1.

The feature reference describes the intended interpretation of each column. It does not independently establish that every stored value follows the original authors' extraction rules.

## 5. Known Limitations

The following limitations should be considered when using these features:

1. The original feature extraction source code is unavailable.
2. Some features have unresolved differences between stored values and independently calculated values.
3. Missing URL protocols and malformed URLs may affect domain-related features.
4. Port numbers may influence the stored `tld_length` values.
5. The exact tokenization, query parameter counting, TLD popularity, and suspicious extension rules remain unconfirmed.
6. Dataset-specific domain patterns may influence model learning and generalization.

## 6. Usage Recommendations

- Use validated features according to their documented tested definitions.
- Keep partially validated and unverified features under review.
- Do not modify or remove features solely because an independent audit produced mismatches.
- Document future changes to feature definitions and preprocessing separately.
- Review feature behavior during model training and evaluation.
- Preserve the original dataset for reproducibility.

## 7. Related Documentation

- `dataset_audit.md`
- `docs/FEATURE_VALIDATION_SUMMARY.md`
- `docs/DATASET_AND_EVALUATION_PROTOCOL.md`

## 8. Conclusion

This reference provides a structured overview of the 16 numerical features used in PHISH-X.

It supports consistent understanding and documentation across the project team while clearly distinguishing verified interpretations from features that require further investigation.

The feature definitions should be updated if the original extraction implementation or additional reliable documentation becomes available.