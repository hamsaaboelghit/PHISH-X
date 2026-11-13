# PHISH-X — Dataset Audit

**Audit decision:** Approved with modifications / documented limitations  
**Primary evidence:** `docs/security_dataset_evidence.json`, `docs/SECURITY_DATASET_AUDIT.md`, `docs/URL_SECURITY_AND_FEATURE_SPECIFICATION.md`, and `docs/DATASET_AND_EVALUATION_PROTOCOL.md`.

## 1. Dataset information

- **Dataset:** supplied LegitPhish URL dataset.
- **Raw snapshot:** 101,219 records, as recorded by the feature-reproduction audit.
- **Historical cleaned snapshot:** 100,872 records, as recorded by the earlier dataset audit.
- **Current committed Group Split metadata:** 81,525 training records + 19,337 test records = 100,862 manifest records.
- **Important reconciliation note:** the historical cleaned-row total (100,872) and current split-manifest total (100,862) differ by 10. The current training run uses the committed manifests. Reconcile the exact cleaned CSV and manifest snapshots before publishing one overall cleaned-row total.
- **Target column:** `ClassLabel`.
- **Label mapping:** 0 = Phishing; 1 = Legitimate.
- **Historical class distribution:** 63,492 Phishing and 37,380 Legitimate (from the historical 100,872-row audit snapshot).
- **Dataset hash recorded by security evidence:** `ed8d830fba05688b5f57f7e7deacb8f377268898cb6f36da50bde1eebd8d95ec`.

## 2. Data quality

| Check | Historical audit result |
|---|---:|
| Rows with missing/invalid labels | 1 |
| Duplicate URL rows removed | 346 |
| Conflicting URL labels | 0 |
| Blank URL rows | 0 |
| Unique hosts reported by protocol | 64,001 |

The original raw dataset is retained separately from the cleaned dataset. Duplicate URLs and missing labels were handled during preparation; conflicting labels were not found in the reported audit.

## 3. Data leakage and split checks

The current primary split is Group Split by Host:

| Split | Records |
|---|---:|
| Group Train | 81,525 |
| Group Test | 19,337 |
| Shared hosts | 0 |

The random stratified comparison split has 4,805 shared hosts and is not the primary reported evaluation. The group split is preferred because URLs from the same host are not distributed across train and test.

The production dataset loader validates manifest host values, label consistency, URL uniqueness within each manifest, URL disjointness between partitions, host disjointness, and finite numeric model features.

## 4. Class imbalance and shortcut risks

The historical class distribution is approximately 62.94% Phishing and 37.06% Legitimate. Class-specific metrics are therefore reported rather than relying on accuracy alone.

Important documented dataset patterns:

- Strict parsed-host analysis found 48,894 phishing rows with IP-literal hosts and zero legitimate rows in the audited snapshot.
- The legacy `has_ip_address` feature reports 48,916 phishing rows because it searches for an IPv4-looking pattern anywhere in the URL; 22 matches are outside the parsed host.
- An IP-only rule achieved approximately 85.55% accuracy in the historical baseline audit.
- HTTPS usage, port-related legacy fields, scheme-less URLs, and suspicious extension flags also exhibit strong dataset-specific associations with labels.
- These associations may encode collection-source shortcuts rather than durable phishing behaviour.

These findings are documented in the security evidence and feature specification. They are not proof that a URL is malicious or that an individual feature is causal.

## 5. Feature review

The extractor reproduces the dataset's 16 legacy URL features. The current production Logistic Regression uses only these five inputs:

- `url_length`
- `number_of_digits`
- `url_entropy`
- `dot_count`
- `path_length`

The other extracted features are not silently passed to the model. The five-feature order and legacy feature-specification version are validated by the model artifact.

Known weaknesses include legacy parser behaviour, no Public Suffix List, limited handling of IDN/confusable characters in the model vector, and no external reputation/DNS/WHOIS/certificate lookups. Structural signals are surfaced separately as advisories.

## 6. Final decision

<badge>Approved with documented limitations</badge>

The dataset is usable for the course project when:

1. Group Split by Host remains the primary evaluation.
2. Both Phishing and Legitimate precision/recall/F1 are reported.
3. Dataset shortcut risks are disclosed.
4. The historical 10-record count discrepancy is not hidden or silently reconciled.
5. The reported accuracy is described as performance on the supplied fixed split, not as a real-world guarantee.
6. The model's five-feature contract is kept consistent across training and inference.

## 7. Detailed evidence

- [Security Dataset Audit](docs/SECURITY_DATASET_AUDIT.md)
- [URL Security & Feature Specification](docs/URL_SECURITY_AND_FEATURE_SPECIFICATION.md)
- [Dataset & Evaluation Protocol](docs/DATASET_AND_EVALUATION_PROTOCOL.md)
- [Final Project Report](docs/FINAL_PROJECT_REPORT.md)
