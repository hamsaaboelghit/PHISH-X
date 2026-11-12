# PHISH-X — Feature Validation Summary

## 1. Purpose

This document summarizes the validation of the 16 numerical features in the original PHISH-X source dataset, which contains 101,219 records.

The objective is to compare stored feature values against independently calculated values, identify inconsistencies, and document limitations.

**Important:** The original feature extraction implementation was not found in the project repository. Therefore, matching an independently tested formula does not necessarily prove that it is the exact original extraction method.

## 2. Validation Results

| Feature | Status | Findings |
|---|---|---|
| `url_length` | Validated | All 101,219 records matched the full URL string length. |
| `number_of_digits` | Validated | All records matched the tested digit-counting method across the complete URL. |
| `dot_count` | Validated | All records matched the number of dots in the complete URL. |
| `url_entropy` | Validated | All records matched Shannon entropy calculated over URL characters within the tested tolerance. |
| `https_flag` | Validated | No mismatches using the HTTPS scheme test. |
| `has_hyphen_in_domain` | Validated for extracted hostnames | No mismatches among valid extracted hostnames. |
| `percentage_numeric_chars` | Validated | All records matched the tested formula: digit count divided by URL length, multiplied by 100. |
| `path_length` | Validated with minor discrepancies | 10 mismatches out of 101,219 records. The examples indicate possible differences in HTML entity handling and URL/port parsing. |
| `has_ip_address` | Partially Validated | 22 mismatches out of 101,218 compared records. Differences may involve IP addresses in paths, subdomains, or malformed URLs. |
| `domain_name_length` | Requires Investigation | 1,300 records without a protocol have zero domain length. The independent comparison also has limitations involving IP addresses and public suffixes. |
| `tld_length` | Requires Investigation | Zero values occur in 1,300 records without a protocol. Port-containing URLs also show evidence that the port may affect the stored length. |
| `subdomain_count` | Requires Investigation | 1,308 records have a value of -1, including 1,300 URLs without a protocol and 8 malformed URLs. |
| `token_count` | Requires Investigation | 48.14% mismatch under the tested tokenization method. The original tokenization rule is unknown. |
| `query_param_count` | Requires Investigation | The stored values differ substantially from standard query parsing. A simple ampersand-based rule nearly matches but does not explain all records. |
| `tld_popularity` | Requires Investigation | Binary values are strongly concentrated among selected TLDs, particularly `.com`, `.org`, `.net`, `.edu`, and `.gov`. |
| `suspicious_file_extension` | Requires Investigation | The feature appears related to suspicious file extensions, but the original extension list and extraction method are unknown. |

## 3. Important Findings

### 3.1 URL Parsing and Missing Protocols

A group of 1,300 records does not contain a URL protocol. These records consistently have:

- `tld_length = 0`
- `domain_name_length = 0`
- `subdomain_count = -1`

An additional 8 malformed URLs also have `subdomain_count = -1`.

These patterns suggest that URL parsing failures may affect multiple features. However, the original extraction implementation is unavailable, so the exact cause remains unconfirmed.

### 3.2 TLD Popularity

The detailed audit found that the value 1 is heavily concentrated among selected TLDs:

- `.com`: 25,592 out of 26,247
- `.org`: 5,457 out of 5,509
- `.net`: 1,287 out of 1,415
- `.edu`: 503 out of 503
- `.gov`: 390 out of 390

The feature has a correlation of approximately 0.593 with the class label.

This may introduce dataset bias or allow a model to rely heavily on particular domain categories. However, correlation alone does not establish data leakage.

### 3.3 Query Parameter Count

The standard query-string parsing audit produced substantial differences from the stored values.

A simple `URL.count("&") + 1` comparison produced only 38 mismatches. However, ampersands can also appear in URL paths and encoded content, so this rule cannot be considered a confirmed extraction formula.

Therefore, the original extraction method remains unconfirmed.

### 3.4 Suspicious File Extension

The audit found 33 potential cases where a suspicious extension appeared in the URL while the stored feature was zero.

Further inspection found:
- No matches at the end of the URL path under the tested path-matching rule.
- Four candidate matches appeared in query parameters.
- Other candidates included extensions appearing in domain names or other URL components.

These cases do not establish 33 confirmed errors. The original detection rules must be obtained before making a final judgment.

### 3.5 IP Address Detection

The independent hostname-based comparison found 22 mismatches out of 101,218 compared records.

Some inspected examples contained IP addresses in URL paths or subdomains, while others involved malformed URL structures.

This suggests that the original detection method may use a different interpretation of an IP address than the tested hostname-only method. The exact rule remains unconfirmed.

### 3.6 Path Length

The independent path-length comparison found 10 mismatches out of 101,219 records.

The inspected examples indicate possible differences in handling HTML entities and URLs containing ports or unusual structures.

The feature matches in the vast majority of records, but these discrepancies should remain documented until the original extraction method is known.

## 4. Dataset and Methodology Limitations

- The original feature extraction source code was not available in the repository.
- Independent validation methods may differ from the original authors' definitions.
- Some URL parsing methods do not correctly handle malformed URLs, missing protocols, ports, or multi-label public suffixes.
- Strong feature-label relationships may reflect dataset-specific patterns rather than general phishing behavior.
- A matching audit result validates only the tested interpretation of a feature.
- The raw source dataset was preserved without modification during these audits.

## 5. Recommendations

1. Obtain the original feature extraction code or detailed feature definitions, if available.
2. Investigate features marked as Requires Investigation before modifying or removing them.
3. Preserve the original raw dataset.
4. Document any future preprocessing decisions separately.
5. Evaluate potential dataset bias during model evaluation.
6. Prefer host-based group splitting when evaluating generalization to unseen hosts.
7. Avoid treating diagnostic rules or feature correlations as proof of model performance or data leakage.

## 6. Conclusion

The audit successfully verified several features under clear, independently tested definitions. Other features showed inconsistencies or depended on extraction rules that could not be confirmed.

No raw or processed dataset values were modified during these audits.

The findings should be treated as a validation and investigation report, not as proof that every unverified feature is incorrect.