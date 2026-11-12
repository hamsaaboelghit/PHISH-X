# Eiad ↔ Shawky: shared URL security test contract (pending review)

Status: prepared for coordination; not sent or approved. No new extractor implemented.

Review update (2026-11-12): local review feedback was addressed on branch
`shawky/security-dataset-audit` (app restoration, audit validation/evidence,
test determinism and missing-input coverage). Eiad agreement on the items
below is still pending; `test_production_feature_contract` remains skipped
and no shared-extractor validation or integration is claimed.

Please confirm:

1. Importable shared parser/extractor module and function signature. It should import without starting the UI or accessing data/network.
2. Allowed types, size limits, schemes, schemeless/protocol-relative input and missing/invalid return/exception contract. Invalid must not mean legitimate.
3. Raw vs normalized URL for lengths, dots, digits, entropy and path; ASCII vs Unicode digits; leading/trailing whitespace vs embedded control rejection.
4. Strict IPv4/IPv6, ports, userinfo, trailing dots, IDNA and ambiguous integer/hex/leading-zero IP policy.
5. Backslash and percent-encoded authority handling; do not normalize into a different host without an explicit policy.
6. PSL-based vs preliminary label-based subdomains, multi-label suffixes and missing/sentinel values. Pin any PSL data locally; no test-time downloads.
7. Query pair counts: duplicates, blank values, empty segments, encoded separators and fragments. Example `?a=1&a=&b=3` should have three pairs if agreed.
8. Feature names/types/order and training-serving consistency. Resolve stored-IP versus strict-host difference and negative-subdomain bundle with dataset owners.

After agreement:

- Bind the 28 case specifications to the real module, retaining the existing helper characterization tests as clearly separate audit coverage.
- Replace the explicitly skipped production-contract test with assertions of validity, host/IP status and agreed numeric feature values.
- Add exact length/digit/dot/path/query expectations and repeat-call determinism, finite-value/type/schema checks, missing-value checks, and equivalent-normalization metamorphic tests under the agreed definitions.
- For malformed inputs assert the agreed invalid result rather than expecting arbitrary feature vectors. Block network operations during every parser/extractor test.
- Record review date, Eiad's approval, module revision and test results here. Do not claim shared-extractor coverage until this step is finished.
