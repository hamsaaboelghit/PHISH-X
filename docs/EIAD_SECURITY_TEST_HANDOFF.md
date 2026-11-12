# Eiad ↔ Shawky: shared URL security test contract

Status: **production contract defined and tested** (Eiad's review of
`origin/eyad`, follow-up on branch `shawky/eyad-followup-fixes`).
No new extractor was implemented in the follow-up; the shared extractor
below is the one delivered on `origin/eyad`.

## Confirmed contract

1. **Module / interface.** Shared extractor: `phishx.features.url_features`
   (`src/phishx/features/url_features.py`). Interface:
   `extract_features(url) -> UrlFeatures`,
   `extract_features_batch(urls) -> list[UrlFeatures]`, plus
   `FEATURE_NAMES` and `FEATURE_SPEC_VERSION = "1.0-legacy"`. It imports
   without starting the UI or accessing data/network.
2. **Input / failure contract.** Allowed types: strings (anything else
   yields `ok=False` / `invalid_type`). Size limit: 8,192 characters
   (`too_long` beyond that). Blank input yields `ok=False` (`empty`).
   Malformed authority yields `ok=False` (`malformed`). Invalid must not
   mean legitimate: `to_vector()` raises on failure.
3. **Normalization.** Leading/trailing whitespace is stripped; `\t\r\n`
   are deleted everywhere (shared `normalize_url_text()` helper, used by
   both the strict parser and the advisory signals). Lengths, dots,
   digits, entropy and path are computed on the normalized text.
4. **Hosts / ports / userinfo.** Strict parser (`url_parser.parse_url`)
   separates user-info, host and port; IPv4 / IPv6 / obfuscated IPv4
   (WHATWG IPv4 algorithm) and IDNA (2003 codec) are handled for
   diagnostics. Invalid ports are surfaced via the `has_invalid_port`
   signal and must not be read as a safe default.
5. **Backslash / percent-encoding.** Backslash is a browser-aware path
   delimiter (e.g. `https://example.com\@other.example/` → host
   `example.com`, path `/@other.example/`). Percent-escapes are never
   decoded for model features; they are counted for diagnostics.
6. **Subdomains.** Legacy label-based definition
   (`len(netloc.split(".")) - 2`, no PSL) is kept for the 16 model
   features. PSL-based semantics remain a future proposal (spec §9.4).
7. **Query counts.** Legacy definition (`len(query.split("&"))`,
   minimum 1) is kept for the model features.
8. **Feature names / order / training-serving consistency.** The 16
   dataset features in `FEATURE_NAMES` order (spec §4.1). The extractor
   always returns all 16; a model-side subset (e.g. a 5-feature
   baseline) is a training-time selection by name, not a competing
   extractor. Full-dataset parity (`tests/test_dataset_parity.py`)
   guarantees training-serving consistency.

## Test status

- `test_production_feature_contract` is **enabled** (no longer skipped)
  and asserts module, interface, feature order, hand-computed values,
  determinism, batch order, and the failure contract, with network
  blocked in `setUp`.
- The 28 synthetic cases (`tests/cases/url_security_cases.json`) remain
  characterization tests for the **old audit helpers**
  (`subdomain_audit`), clearly separate from production acceptance.
- Suite result on this branch (Python 3.13.16): **202 passed,
  0 skipped, 136 subtests passed**; `compileall` covers `src tests app`.

## Remaining / out of scope

- Which feature subset the AI team trains on (5-feature baseline vs
  full 16) is a model-training decision; the extractor contract above
  is unaffected either way.
- Wiring the production extractor into app prediction is a separate,
  reviewed step (spec §10.1). The app currently shows display signals
  only.
- PSL-based subdomains, new security features, and dataset regeneration
  remain proposals requiring team agreement and a new spec version.
