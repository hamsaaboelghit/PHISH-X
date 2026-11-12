# PHISH-X — Website Completion Report

**Branch:** `shawky/website-completion` (from `origin/main`).
**Scope:** full review of all four pages, URL Investigation integration,
Optimization Lab live experiments, tests. No feature definition or model
contract was changed. No shared file was deleted. No result is mocked.

---

## Completed features

1. **URL Investigation is fully integrated** (`app/main.py`):
   - Production extractor (`phishx.features.url_features`, 16 features)
     → feature adapter (5 baseline features selected **by name** in
     baseline order) → 5-feature logistic regression → prediction,
     confidence, P(Legitimate), per-feature explanation.
   - Security signals + extractor warnings shown as separate diagnostics
     (explicitly labeled "NOT model features and NOT a prediction").
   - Invalid input → no prediction with a clear reason. Opaque schemes
     (`javascript:`, `data:`, `mailto:`) → no prediction (out of
     distribution: training data is http/https only), with reason.
   - The model is trained live once per session on the fixed Group
     Split (StandardScaler fit on train only, NumPy batch Gradient
     Descent — the AI Model Core algorithm). There is no saved weights
     artifact in the repository, so training happens in-app and is
     cached; predictions are real, never mocked.
2. **Optimization Lab shows real experiments**: live Gradient Descent vs
   Newton's Method runs on the fixed Group Split with real loss curves,
   iterations, accuracies, and runtime (GD: 1,000 iters, loss 0.0886,
   test 97.82%; Newton: 11 iters, loss 0.0695, test 97.98%). Sigmoid
   section added with correct label semantics (output = P(Legitimate)).
3. **Dataset Intelligence**: added Correlations tab (Pearson heatmap of
   the 16 features + label) and a 16-vs-5 features clarification card.
   Labels verified: 0 = Phishing, 1 = Legitimate throughout.
4. **New model module** `src/phishx/models/baseline.py`: sigmoid, BCE,
   Gradient Descent, Newton's Method, adapter, training, predict,
   explain, and the `analyze_url` pipeline (offline, deterministic).
5. **CI**: `compileall` now covers `src tests app`.

## Fixed issues

1. URL Investigation previously showed only basic display signals with
   no extractor, model, or prediction — now fully integrated (above).
2. Optimization Lab previously stated experiments were "not connected"
   — now connected to real live runs (above).
3. Dataset Intelligence lacked correlations and the 16-vs-5 explanation
   — added (above).
4. Opaque-scheme URLs previously would have received a confident
   "Legitimate" verdict from degenerate features — now suppressed with
   a reason (training distribution is http/https only; verified 0
   opaque rows in the dataset).
5. CI `compileall` omitted `app/` — fixed.
6. AppTest verification caught a `KeyError` (`has_invalid_port` exists
   only on the unmerged Eyad follow-up branch) — fixed to use fields
   present on `main` (`port_valid`).

## Architecture review (no files deleted)

- `app/main.py` (1,318 lines) keeps its four-page structure
  (Overview / Dataset Intelligence / Optimization Lab / URL
  Investigation) with inline helpers. It was extended, not replaced.
- `app/components/cards.py`, `charts.py`, `theme.py` and
  `app/utils/url_helpers.py` are **not imported anywhere** (`main.py`
  defines identical helpers inline). They were **kept untouched** per
  the preserve-existing-work instruction; deduplication (wiring
  `main.py` to import them) is a future cleanup, not done here to
  avoid behavior changes.
- Overview numbers are data-driven (computed from the loaded CSV, not
  hardcoded); missing dataset / missing `ClassLabel` stop the app with
  a clear error.

## Remaining blockers

1. **No saved model artifact exists** (Norhan's AI Model Core is code on
   `origin/norhan/ai-model-core`, not a weights file). The app trains
   the identical architecture live; if the team wants a persisted
   artifact, training + serialization is a separate reviewed step.
2. **Single agreed contract (names/order/scaling) between Dataset
   Loader, Model, and URL Investigation is still pending** with Norhan
   and Eiad (per `FEATURE_DEFINITIONS.md`). The adapter documents the
   baseline order (which differs from dataset order) and selects by
   name; it does not claim the contract is agreed.
3. **Newton's Method is newly implemented here** (Norhan's code has
   Gradient Descent only). It is standard Hessian-based logistic
   regression, tested on synthetic data, and labeled as such.
4. **`token_count` serving documentation conflict** (see dataset audit
   report): the extractor implements the confirmed formula; the
   `FEATURE_DEFINITIONS.md` UNKNOWN verdict needs a team-agreed update.
5. **Eyad follow-up branch** (`shawky/eyad-followup-fixes`: parser
   opaque fix, `has_invalid_port`, enabled production contract) is not
   yet merged to `main`; this branch builds on `main` without it.
6. **Browser-level E2E** (clicking through a real browser) was verified
   via Streamlit AppTest (all pages render; analyze flow works) and
   `curl` (server serves). A human click-through in a browser is still
   recommended before the demo.

## Test results

- `python -m pytest tests -q` — **211 passed, 1 skipped, 190 subtests**
  (201 baseline + 10 new `test_baseline_model.py` tests; the 1 skip is
  `test_production_feature_contract`, still skipped on `main` pending
  the Eyad PR).
- `python -m compileall -q src tests app` — passed (one pre-existing
  `SyntaxWarning` in `app/main.py`, untouched).
- Streamlit AppTest (headless): all 4 pages render with no exceptions;
  URL Investigation analyze flow returns Phishing 98.8% for an IP URL
  with explanation + warnings; opaque URL yields "No prediction" with
  reason; empty input yields a warning, no crash.
- Live server: `streamlit run app/main.py` serves on port 8501 with no
  exceptions in logs.
