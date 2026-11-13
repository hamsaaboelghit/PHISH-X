import numpy as np
import pytest

from phishx.explainability.contributions import explain_logit
from phishx.inference import (
    ArtifactContractError,
    MODEL_FEATURES,
    predict_url,
    validate_artifact,
)


class IdentityScaler:
    n_features_in_ = len(MODEL_FEATURES)

    def transform(self, frame):
        return frame.to_numpy(dtype=float)


def artifact(**overrides):
    value = {
        "scaler": IdentityScaler(),
        "weights": np.array([0.1, -0.2, 0.3, 0.4, -0.5]),
        "bias": -0.25,
        "threshold": 0.5,
        "feature_columns": MODEL_FEATURES,
        "label_mapping": {0: "Phishing", 1: "Legitimate"},
        "feature_spec_version": "1.0-legacy",
    }
    value.update(overrides)
    return value


def test_explain_logit_contributions_sum_to_logit():
    logit, contributions = explain_logit(
        [1.0, 2.0, -1.0],
        [0.5, -0.25, 2.0],
        0.75,
        ["a", "b", "c"],
    )
    assert contributions == {"a": 0.5, "b": -0.5, "c": -2.0}
    assert logit == pytest.approx(-1.25)
    assert sum(contributions.values()) + 0.75 == pytest.approx(logit)


@pytest.mark.parametrize(
    "x, weights, names, bias",
    [
        ([1, 2], [1], ["a", "b"], 0),
        ([1, 2], [1, 2], ["a"], 0),
        ([1, np.nan], [1, 2], ["a", "b"], 0),
        ([1], [1], ["a"], np.inf),
    ],
)
def test_explain_logit_rejects_invalid_inputs(x, weights, names, bias):
    with pytest.raises(ValueError):
        explain_logit(x, weights, bias, names)


def test_validate_artifact_accepts_current_five_feature_contract():
    validated = validate_artifact(artifact())
    assert tuple(validated["feature_columns"]) == MODEL_FEATURES
    assert validated["label_mapping"] == {0: "Phishing", 1: "Legitimate"}


@pytest.mark.parametrize(
    "overrides",
    [
        {"weights": np.zeros(4)},
        {"weights": np.array([0, 0, 0, 0, np.nan])},
        {"bias": np.nan},
        {"threshold": 1.0},
        {"feature_columns": tuple(reversed(MODEL_FEATURES))},
        {"label_mapping": {0: "Legitimate", 1: "Phishing"}},
        {"feature_spec_version": "future"},
        {"scaler": object()},
    ],
)
def test_validate_artifact_rejects_contract_mismatch(overrides):
    with pytest.raises(ArtifactContractError):
        validate_artifact(artifact(**overrides))


def test_prediction_uses_exact_feature_names_and_returns_separate_security_signals():
    result = predict_url("https://example.com/login", artifact())
    assert result.prediction in {"Phishing", "Legitimate"}
    assert 0 <= result.phishing_probability <= 1
    assert 0 <= result.legitimate_probability <= 1
    assert result.phishing_probability + result.legitimate_probability == pytest.approx(1)
    assert tuple(result.model_features) == MODEL_FEATURES
    assert tuple(result.contributions) == MODEL_FEATURES
    assert result.logit == pytest.approx(
        sum(result.contributions.values()) + result.bias_contribution
    )
    assert result.security_signals["parsed"] is True


@pytest.mark.parametrize("bad_url", ["", None, 7, "x" * 9000])
def test_prediction_rejects_failed_feature_extraction(bad_url):
    with pytest.raises(ValueError, match="feature extraction failed"):
        predict_url(bad_url, artifact())
