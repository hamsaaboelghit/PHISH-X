# Artifact-backed inference and explanations

## Scope

The inference layer connects the existing URL feature extractor to the already
trained PHISH-X Newton Logistic Regression artifact. It does not introduce a
second classifier or alter the 16-feature legacy extraction contract.

The model consumes exactly these five features, selected by name and order:

1. `url_length`
2. `number_of_digits`
3. `url_entropy`
4. `dot_count`
5. `path_length`

The remaining eleven extracted features are not silently passed to the model.
The feature extractor remains the source of truth for legacy definitions.

## Artifact contract

`load_model_artifact(path)` loads a trusted local Joblib artifact and validates
the minimum supported keys:

- `scaler`: fitted transformer with `transform()`, configured for five inputs
- `weights`: finite vector of five coefficients
- `bias`: finite scalar

Optional metadata:

- `threshold`: defaults to 0.5 and must be strictly between zero and one
- `feature_columns`: defaults to the five-feature contract above and, when
  present, must match it exactly
- `label_mapping`: defaults to `{0: "Phishing", 1: "Legitimate"}`
- `feature_spec_version`: defaults to `1.0-legacy`

Joblib uses pickle internally. Never load an artifact from an untrusted source.

## Prediction flow

1. Validate the artifact contract.
2. Extract all legacy URL features using `extract_features`.
3. Select the five model features by exact feature name.
4. Build a named one-row DataFrame and apply the artifact's fitted scaler.
5. Use the existing `predict_proba` implementation.
6. Apply the artifact threshold and label mapping.
7. Return both class probabilities, extraction warnings, and strict-parser
   security signals.

Security signals are descriptive diagnostics only. They are not appended to
the model vector and do not alter its prediction.

## Explainability

For each standardized model input (z_i), the additive contribution is
(c_i = w_i z_i). The model logit is

`logit = bias + sum(c_i)`.

Positive and negative contributions move the logit toward the positive
(Legitimate, label 1) and negative (Phishing, label 0) classes respectively.
These are additive log-odds contributions, not probabilities and not causal
claims. The bias is returned separately.

## Public API

```python
from phishx.inference import load_model_artifact, predict_url

artifact = load_model_artifact(
    "data/processed/model_artifacts/phishx_newton_model.joblib"
)
result = predict_url("https://example.com/login", artifact)
print(result.as_dict())
```

The artifact must exist locally; it is not committed to this repository by
this change. A failed feature extraction raises `ValueError` rather than
producing a prediction from invalid values.
