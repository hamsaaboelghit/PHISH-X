# URL Security & Feature Engineering — Delivery Notes

<<<<<<< Updated upstream
## Included fixes
=======
## Included fixes (original delivery, `origin/eyad` v1)
>>>>>>> Stashed changes

- Hardened strict authority parsing: bracketed hosts must contain a valid IPv6 literal; malformed brackets, unbracketed IPv6, and ambiguous multi-colon host/port forms are rejected.
- Bounded port-number conversion before integer parsing, so extremely long ports are treated as invalid without raising.
- Corrected `double_scheme` to detect a nested scheme only at the beginning of the URL; embedded URLs in paths/queries remain covered by the separate `embedded_url_in_path_or_query` signal.
- Preserved the presence of an empty fragment (`#`) and split query/fragment components for opaque schemes such as `javascript:`.
- Hardened legacy bracket validation without changing the 16 model-feature formulas.
- Added regression tests for each reported edge case.

<<<<<<< Updated upstream
## Compatibility safeguards

- `FEATURE_NAMES`, feature order, and the legacy definitions of all 16 model features are unchanged.
- The raw and processed datasets, `app/main.py`, and existing audit modules were not edited.
- Security signals remain advisory and separate from the model feature vector.
- URL processing remains offline; no URL fetching, DNS lookup, or network access was added.

## Verification performed for this package

- `python -m pytest tests -q` — **188 passed**.
- `python -m compileall -q src tests` — passed.
- Full-dataset parity test is included in the suite and passed as part of the 188 tests.
- Local verification environment: Python 3.13.5.
- Added `.github/workflows/tests.yml` to run tests on Python 3.10, 3.11, 3.12, and 3.13 after pushing to GitHub. Results for those remote matrix jobs will be produced by GitHub Actions.

## Files changed

- `src/phishx/features/url_parser.py`
- `src/phishx/features/url_signals.py`
- `tests/test_url_parser.py`
- `tests/test_url_signals.py`
- `tests/test_url_features.py`
- `docs/URL_SECURITY_AND_FEATURE_SPECIFICATION.md`
- `.github/workflows/tests.yml`
- `DELIVERY_NOTES.md`
=======
## Review follow-up fixes (this branch, `shawky/eyad-followup-fixes`)

Addressing Eiad's review of `origin/eyad` before final approval:

- **Opaque-scheme priority (parser bug fix).** `javascript:123` and `data:123` were misread as a schemeless `host:port` (`_HOST_PORT_RE` matched before the opaque-scheme check). Known opaque schemes (`javascript`, `data`, `mailto`, …) now win over the host:port reading, so they parse as opaque with no host. A genuine schemeless host:port such as `example.com:8080` (or `localhost:8080`) is preserved as implied host:port. Unknown single-label `scheme:digits` input keeps the host:port (address-bar) reading.
- **Parser tests added.** `javascript:123` → opaque/no host; `data:123` → opaque/no host; `https://example.com\@other.example/` → host `example.com`, path `/@other.example/` (the backslash is a path delimiter, so the `@` is not user-info); `example.com:8080` stays implied host:port.
- **Shared normalisation.** `parse_url` deletes `\t\r\n` everywhere, but the advisory signals used `url.strip()` only for the raw-text checks, so a tab hidden inside `http://ht\ttp://…` could make the parser and the `double_scheme` check disagree. Both now use the shared `normalize_url_text()` helper.
- **Invalid port is visible.** New signal `has_invalid_port` (from `not port_valid`). `has_nondefault_port` remains defined only for valid ports, so an invalid port (`http://a.com:99999/`) is reported as invalid — never silently read as "default port, therefore safe".
- **Production feature contract defined and tested.** The shared extractor is `phishx.features.url_features.extract_features` / `extract_features_batch`, returning the 16 dataset features in `FEATURE_NAMES` order (spec `1.0-legacy`). `test_production_feature_contract` is now enabled and asserts module, interface, feature order, hand-computed values, determinism, batch order, and the failure contract (invalid input is `ok=False`, never a legitimate-looking vector). The extractor always returns all 16 features; a model-side subset (e.g. a 5-feature baseline) is a training-time selection by name, not a competing extractor.
- **App integration contract.** `extract_basic_signals()` in `app/main.py` is a display helper for the URL Investigation page only — it is separate from the production extractor and its output must never be fed to a model. Security diagnostics (`analyze_url_security`) stay separate from the model feature vector. A clarifying comment was added at the function; no UI/logic was changed.
- **CI.** `compileall` now covers `src tests app` (previously `src tests` only).

## Compatibility safeguards

- `FEATURE_NAMES`, feature order, and the legacy definitions of all 16 model features are unchanged.
- The raw and processed datasets and the fixed train/test splits were not edited.
- Security signals remain advisory and separate from the model feature vector.
- URL processing remains offline; no URL fetching, DNS lookup, or network access was added.
- The 28 synthetic cases in `tests/cases/url_security_cases.json` exercise the **old audit helpers** (`subdomain_audit`), not the new production parser/extractor. Production acceptance is asserted by `test_production_feature_contract` and the `test_url_*` suites.

## Verification performed for this package

- `python -m pytest tests -q` — **202 passed, 0 skipped, 136 subtests passed** (this branch, after the follow-up fixes; Python 3.13.16, pytest 9.0.3).
- `python -m compileall -q src tests app` — passed (one pre-existing `SyntaxWarning` in `app/main.py`, untouched).
- `PYTHONPATH=src python3 -m unittest discover -s tests` — **OK** (7 tests, including the enabled production contract).
- Full-dataset parity test is included in the suite and passed as part of the 202 tests.
- GitHub Actions workflow `.github/workflows/tests.yml` runs the suite on Python 3.10, 3.11, 3.12, and 3.13 after push / pull request. Local verification was performed on Python 3.13.16; the remote matrix results are produced by GitHub Actions after push.
- Note on counts: the pre-follow-up `origin/eyad` baseline was 194 passed / 1 skipped / 116 subtests locally. A CI figure of 199 passed / 1 skipped / 183 subtests was reported for the review but could not be reproduced locally on either `origin/eyad` (194/1/116) or `origin/main` (201/1/190); the numbers above are the locally verified results for this branch.

## Files changed

Original delivery (vs pre-delivery base `38b5e2a`):

- `src/phishx/features/url_parser.py` (new)
- `src/phishx/features/url_features.py` (new)
- `src/phishx/features/url_signals.py` (new)
- `src/phishx/security_dataset_audit.py` (modified)
- `app/main.py` (modified — URL Investigation page and display helpers; see correction below)
- `app/components/cards.py` (new)
- `app/components/charts.py` (new)
- `app/utils/__init__.py` (new)
- `app/utils/url_helpers.py` (new)
- `tests/test_url_parser.py` (new)
- `tests/test_url_features.py` (new)
- `tests/test_url_signals.py` (new)
- `tests/test_dataset_parity.py` (new)
- `tests/test_url_security_cases.py` (modified)
- `tests/conftest.py` (new)
- `tests/cases/url_security_cases.json` (unchanged input data)
- `docs/URL_SECURITY_AND_FEATURE_SPECIFICATION.md` (new)
- `docs/EIAD_SECURITY_TEST_HANDOFF.md` (modified)
- `docs/SECURITY_DATASET_AUDIT.md` (modified)
- `docs/security_dataset_evidence.json` (modified)
- `requirements-dev.txt` (new)
- `.github/workflows/tests.yml` (new)
- `DELIVERY_NOTES.md` (this file)

Review follow-up (this branch):

- `src/phishx/features/url_parser.py` (opaque-scheme priority, `normalize_url_text`)
- `src/phishx/features/url_signals.py` (shared normalisation, `has_invalid_port`)
- `tests/test_url_parser.py` (opaque/backslash/host:port tests)
- `tests/test_url_signals.py` (invalid-port and normalisation tests)
- `tests/test_url_security_cases.py` (production contract enabled)
- `app/main.py` (clarifying comment only; no logic change)
- `.github/workflows/tests.yml` (`compileall` now includes `app`)
- `docs/URL_SECURITY_AND_FEATURE_SPECIFICATION.md` (contract, counts, wording)
- `docs/EIAD_SECURITY_TEST_HANDOFF.md` (status update)
- `DELIVERY_NOTES.md` (this file)

**Correction:** an earlier version of these notes stated that `app/main.py` was not edited. That was incorrect: `app/main.py` was modified in the original delivery (URL Investigation page, `extract_basic_signals()` display helper, and related UI). The datasets, splits, and audit modules' validation behaviour were not changed in the follow-up; `src/phishx/security_dataset_audit.py` was modified in the original delivery as listed above.
>>>>>>> Stashed changes

No Git history is included in the uploaded ZIP, so branch creation, commits, push, and pull-request creation must be performed in the original Git repository.
