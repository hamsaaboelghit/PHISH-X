# Test Execution Report — Tasks 1–3 (Task 4 pending Eiad)

Date: 2026-11-12
Branch: `shawky/security-tasks-1-3` (based on `main` at `38b5e2a`)
Base: `origin/main` = `38b5e2a` (Merge PR #2). `git fetch origin` could not
run in the sandbox (no remote configured there); the local `origin/main`
ref from the initial clone was verified instead. Re-run `git fetch origin`
on a machine with remote access before pushing.

## Task 1 — Test execution & verification

Command (as specified):

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Equivalent run in this environment (`PYTHONPATH=src python3 -m unittest
discover -s tests -v`):

```text
Ran 12 tests in 0.065s
OK (skipped=1)
```

| Result | Count |
|---|---:|
| Passed | 11 |
| Failed | 0 |
| Skipped | 1 (`test_production_feature_contract`, blocked on Eiad contract) |
| Total discovered | 12 |

Discovery check: test files exist in the repository
(`tests/test_url_security_cases.py`, `tests/cases/url_security_cases.json`)
and discovery finds 12 tests (not `Ran 0 tests`). No failures were found,
so no behavior was changed to make tests pass. (Initial Task 1 run found
10 tests; Tasks 2–3 added 2 more: empty-dataset and parser-safety.)

## Task 2 — Dataset label validation

`validate_dataframe()` in `src/phishx/security_dataset_audit.py` requires
both `ClassLabel` values `0` and `1`; a missing class raises `ValueError`
with a clear message. Unit tests cover: both classes (int and float
labels), class `0` only, class `1` only, and empty datasets (with and
without required columns). Cohort `class_percent` values are asserted
finite (no unintended `NaN` in JSON output); the cohorts computation also
guards against `NaN` defensively.

## Task 3 — Parser input safety (existing helpers only)

Characterization tests for `parse_hostname()`, `is_ip_address()` and
`analyze_subdomain()` cover: `None`; integer and float inputs; empty and
whitespace strings; `"Offline"` in multiple capitalizations; malformed
URLs (broken IPv6 bracket, out-of-range port, embedded control
character); and correct IPv4/IPv6. These tests characterize the current
behavior of the existing audit helpers only — they do not prove that all
malformed URLs are rejected, nor that a production extractor would be
safe. Missing/non-string/empty/`Offline`/broken-bracket inputs return
`None`/`False` and never raise, but other malformed inputs still yield
hostnames (see below). No production feature definitions were changed.

One safety fix was necessary: `is_ip_address()` previously passed
non-string input to `ipaddress.ip_address()`, so integers/bools were
misclassified as IPs (`123` → `True`, `0` → `False`). It now returns
`False` for non-string input. String behavior is unchanged (all existing
characterization tests still pass).

Documented existing-helper behaviors (not changed, production must handle
explicitly): out-of-range ports still yield a hostname; embedded newline
is stripped by `urlsplit`; percent-encoded hosts are returned unvalidated.

## Task 4 — Production feature integration: BLOCKED

Not started. Awaiting Eiad's confirmed feature contract (module path,
function interface, feature names/definitions, invalid-URL handling).
`test_production_feature_contract` remains skipped. No alternative
extractor or new feature definitions were created.

## Production security limitations

- The existing helper tests are **not** a substitute for production
  feature validation. Passing them characterizes audit-helper behavior
  only; it does not validate any production extractor.
- Invalid ports, control characters, and percent-encoded hosts need
  **explicit handling** in the production URL extractor. The current
  helpers accept out-of-range port hosts, strip embedded newlines via
  `urlsplit`, and return percent-encoded hosts unvalidated — production
  must reject or normalize these by an agreed policy, not inherit the
  helper behavior accidentally.
- Task 4 stays **BLOCKED** until Eiad confirms the module path, function
  interface, feature definitions, and invalid-URL behavior. No
  production extractor tests are claimed complete before that agreement
  and integration actually happen.

## Verification summary

- `PYTHONPATH=src python -m unittest discover -s tests -v` → 11 passed,
  0 failed, 1 skipped.
- Audit evidence regenerates identically; dataset SHA256 unchanged
  (`ed8d830fba05688b5f57f7e7deacb8f377268898cb6f36da50bde1eebd8d95ec`).
- No dataset/split changes. No merge performed.

## Follow-up verification (feature repro + ablation)

- Latest `main` verified: `38b5e2a` (local `origin/main` ref; `git fetch
  origin` unavailable in sandbox — re-run on a machine with remote
  access before pushing).
- Branch: `shawky/feature-repro-ablation` (based on `main` at `38b5e2a`).
- Command: `PYTHONPATH=src python -m unittest discover -s tests -v`
- Result: **Ran 14 tests — OK (13 passed, 0 failed, 1 skipped)**.
  The 2 new tests are the feature-definitions reproducibility checks
  (known examples + full-dataset zero-mismatch assertion).
- Skipped test: `test_production_feature_contract` — skipped because
  Eiad has not yet confirmed the shared extractor module, interface,
  and feature semantics (Task 4 BLOCKED). No production extractor
  tests are claimed complete.

## PR #8 follow-up verification (ablation fix + cleanup)

- Branch: `shawky/pr8-followup-fixes` (based on `main` at `38b5e2a`).
  Note: the reviewed `main` at `896241e` (after PR #8) is not available
  in this sandbox (`git fetch origin` unavailable); tests were run on
  the branch HEAD below. Re-run on a machine with remote access after
  fetching `896241e` before merging.
- Tested commit: `5877396` (HEAD at verification time; the report-update
  commit follows it).
- Command: `PYTHONPATH=src python -m unittest discover -s tests -v`
- Result: **Ran 14 tests — OK (13 passed, 0 failed, 1 skipped)**.
- Skipped test: `test_production_feature_contract` — skipped because
  Eiad has not yet confirmed the production feature contract (module
  path, function interface, feature definitions, invalid-URL handling).
  Task 4 remains BLOCKED; no production extractor tests are claimed
  complete.
