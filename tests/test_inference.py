import joblib
import numpy as np
import pytest
from sklearn.preprocessing import StandardScaler

from phishx.explainability.contributions import explain_logit
from phishx.inference import (
    ArtifactContractError,
    MODEL_FEATURES,
    load_model_artifact,
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
        {"weights": "not-numeric"},
        {"bias": np.nan},
        {"threshold": -0.1},
        {"threshold": 1.1},
        {"feature_columns": tuple(reversed(MODEL_FEATURES))},
        {"feature_columns": None},
        {"label_mapping": {0: "Legitimate", 1: "Phishing"}},
        {"label_mapping": {"bad": "Phishing", 1: "Legitimate"}},
        {"label_mapping": {False: "Phishing", 1: "Legitimate"}},
        {"feature_spec_version": "future"},
        {"scaler": object()},
    ],
)
def test_validate_artifact_rejects_contract_mismatch(overrides):
    with pytest.raises(ArtifactContractError):
        validate_artifact(artifact(**overrides))


@pytest.mark.parametrize("threshold", [0.0, 1.0])
def test_validate_artifact_accepts_boundary_thresholds(threshold):
    assert validate_artifact(artifact(threshold=threshold))["threshold"] == threshold


def test_prediction_uses_exact_feature_names_and_returns_separate_security_signals():
    result = predict_url("https://example.com/login", artifact())
    assert result.prediction in {"Phishing", "Legitimate"}
    assert result.label == result.prediction
    assert 0 <= result.phishing_probability <= 1
    assert 0 <= result.legitimate_probability <= 1
    assert result.phishing_probability + result.legitimate_probability == pytest.approx(1)
    assert tuple(result.model_features) == MODEL_FEATURES
    assert tuple(result.contributions) == MODEL_FEATURES
    assert result.logit == pytest.approx(
        sum(result.contributions.values()) + result.bias_contribution
    )
    assert result.security_signals["parsed"] is True


def test_joblib_artifact_load_and_standard_scaler_end_to_end(tmp_path):
    training_features = np.array(
        [
            [10, 1, 2.1, 1, 4],
            [40, 5, 3.7, 3, 12],
            [80, 9, 4.2, 5, 30],
            [120, 15, 4.8, 7, 55],
        ],
        dtype=float,
    )
    scaler = StandardScaler().fit(
        __import__("pandas").DataFrame(training_features, columns=MODEL_FEATURES)
    )
    model_artifact = artifact(scaler=scaler)
    path = tmp_path / "model.joblib"
    joblib.dump(model_artifact, path)

    loaded = load_model_artifact(path)
    result = predict_url("https://example.com/login", loaded)

    assert result.prediction in {"Phishing", "Legitimate"}
    assert result.security_signals["parsed"] is True
    assert result.phishing_probability + result.legitimate_probability == pytest.approx(1)
    assert result.logit == pytest.approx(
        result.bias_contribution + sum(result.contributions.values())
    )


def test_load_model_artifact_rejects_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_model_artifact(tmp_path / "missing.joblib")


@pytest.mark.parametrize("bad_url", ["", None, 7, "x" * 9000])
def test_prediction_rejects_failed_feature_extraction(bad_url):
    with pytest.raises(ValueError, match="feature extraction failed"):
        predict_url(bad_url, artifact())


def test_security_assessment_flags_misleading_userinfo_without_overriding_ml():
    result = predict_url(
        "http://example.com@evil.test/login",
        artifact(),
    )
    assessment = result.security_assessment
    assert result.prediction in {"Phishing", "Legitimate"}
    assert assessment["status"] == "warning"
    assert assessment["risk_level"] == "high"
    assert assessment["actual_host"] == "evil.test"
    assert assessment["findings"][0]["code"] == "misleading_userinfo"
    assert assessment["findings"][0]["severity"] == "high"
    assert result.as_dict()["security_assessment"] == assessment


def test_security_assessment_has_no_flags_for_plain_example_url():
    result = predict_url("https://example.com/login", artifact())
    assert result.security_assessment["status"] == "no_structural_flags"
    assert result.security_assessment["risk_level"] == "none"
    assert result.security_assessment["findings"] == []


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "data:text/plain,example",
        "mailto:security@example.com",
        "ftp://example.com/file.txt",
    ],
)
def test_non_http_uri_schemes_are_flagged_as_out_of_scope(url):
    result = predict_url(url, artifact())

    assert result.prediction in {"Phishing", "Legitimate"}
    assert result.phishing_probability + result.legitimate_probability == pytest.approx(1)
    assert result.security_assessment["status"] == "warning"
    assert result.security_assessment["risk_level"] == "medium"
    assert any(
        finding["code"] == "unsupported_uri_scheme"
        for finding in result.security_assessment["findings"]
    )
    assert result.security_assessment["actual_host"] is None or url.startswith("ftp://")



def test_security_assessment_flags_direct_ip_host_without_overriding_ml():
    result = predict_url("http://192.168.1.10/account/verify", artifact())
    assessment = result.security_assessment

    assert result.prediction in {"Phishing", "Legitimate"}
    assert assessment["status"] == "warning"
    assert assessment["risk_level"] == "low"
    assert assessment["actual_host"] == "192.168.1.10"
    assert any(
        finding["code"] == "ip_address_host"
        and finding["severity"] == "low"
        for finding in assessment["findings"]
    )
    assert result.as_dict()["security_assessment"] == assessment
