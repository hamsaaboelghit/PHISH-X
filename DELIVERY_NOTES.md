# URL Security & Feature Engineering — Delivery Notes

## Included fixes

- Hardened strict authority parsing: bracketed hosts must contain a valid IPv6 literal; malformed brackets, unbracketed IPv6, and ambiguous multi-colon host/port forms are rejected.
- Bounded port-number conversion before integer parsing, so extremely long ports are treated as invalid without raising.
- Corrected `double_scheme` to detect a nested scheme only at the beginning of the URL; embedded URLs in paths/queries remain covered by the separate `embedded_url_in_path_or_query` signal.
- Preserved the presence of an empty fragment (`#`) and split query/fragment components for opaque schemes such as `javascript:`.
- Hardened legacy bracket validation without changing the 16 model-feature formulas.
- Added regression tests for each reported edge case.

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

No Git history is included in the uploaded ZIP, so branch creation, commits, push, and pull-request creation must be performed in the original Git repository.
