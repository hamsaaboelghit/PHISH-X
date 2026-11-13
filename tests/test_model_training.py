import numpy as np
import pandas as pd

from phishx.inference import validate_artifact, MODEL_FEATURES
from phishx.models.training import evaluate_model, train_model
from phishx.models import train as train_cli


def test_manual_training_produces_valid_inference_artifact():
    X = np.array(
        [
            [0.0, 0.0, 0.1, 0.0, 0.0],
            [0.2, 0.0, 0.2, 0.0, 0.1],
            [0.1, 1.0, 0.0, 1.0, 0.2],
            [0.3, 1.0, 0.1, 1.0, 0.3],
            [3.0, 4.0, 2.0, 2.0, 3.0],
            [3.2, 5.0, 2.1, 2.0, 3.1],
            [3.1, 4.0, 2.2, 3.0, 3.2],
            [3.3, 5.0, 2.0, 3.0, 3.3],
        ]
    )
    y = np.array([0, 0, 0, 0, 1, 1, 1, 1])

    artifact = train_model(X, y, l2=0.1, max_iterations=100)
    validated = validate_artifact(artifact)

    assert tuple(validated["feature_columns"]) == MODEL_FEATURES
    assert validated["scaler"].__class__.__name__ == "NumericalStandardScaler"
    np.testing.assert_allclose(validated["scaler"].mean_, X.mean(axis=0))
    assert np.isfinite(validated["weights"]).all()
    assert np.isfinite(validated["bias"])
    assert artifact["training"]["final_loss"] <= artifact["training"]["initial_loss"]


def test_evaluation_returns_complete_binary_metrics():
    X_train = np.array(
        [
            [0.0, 0.0, 0.1, 0.0, 0.0],
            [0.2, 0.0, 0.2, 0.0, 0.1],
            [3.0, 4.0, 2.0, 2.0, 3.0],
            [3.2, 5.0, 2.1, 2.0, 3.1],
        ]
    )
    y_train = np.array([0, 0, 1, 1])
    artifact = train_model(X_train, y_train, l2=0.1)

    metrics = evaluate_model(
        artifact,
        X_train,
        y_train,
    )

    assert metrics["samples"] == len(y_train)
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["specificity"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0
    assert metrics["positive_class"] == "Legitimate"
    assert set(metrics["class_metrics"]) == {"phishing", "legitimate"}
    for class_result in metrics["class_metrics"].values():
        assert 0.0 <= class_result["precision"] <= 1.0
        assert 0.0 <= class_result["recall"] <= 1.0
        assert 0.0 <= class_result["f1_score"] <= 1.0
    assert metrics["class_metrics"]["phishing"]["label"] == 0
    assert metrics["class_metrics"]["legitimate"]["label"] == 1
    assert sum(metrics["confusion_matrix"].values()) == len(y_train)


def test_training_cli_uses_raw_group_split_for_train_and_test(monkeypatch, tmp_path):
    raw_train = pd.DataFrame(
        [[10.0, 1.0, 2.0, 1.0, 4.0], [30.0, 3.0, 4.0, 2.0, 8.0]],
        columns=MODEL_FEATURES,
    )
    raw_test = pd.DataFrame(
        [[50.0, 5.0, 6.0, 3.0, 12.0]],
        columns=MODEL_FEATURES,
    )
    y_train = pd.Series([0, 1])
    y_test = pd.Series([1])

    monkeypatch.setattr(
        train_cli,
        "load_group_split",
        lambda: (raw_train, raw_test, y_train, y_test),
    )
    monkeypatch.setattr(train_cli, "ARTIFACT_PATH", tmp_path / "model.joblib")
    monkeypatch.setattr(train_cli, "METRICS_PATH", tmp_path / "metrics.json")

    captured = {}
    fake_artifact = {
        "training": {"method": "test"},
        "feature_columns": MODEL_FEATURES,
        "feature_spec_version": "1.0-legacy",
    }

    def fake_train_model(X, y, **kwargs):
        captured["train"] = np.asarray(X, dtype=float).copy()
        captured["train_labels"] = np.asarray(y).copy()
        return fake_artifact

    def fake_evaluate_model(artifact, X, y):
        captured["test"] = np.asarray(X, dtype=float).copy()
        captured["test_labels"] = np.asarray(y).copy()
        return {"samples": len(y)}

    monkeypatch.setattr(train_cli, "train_model", fake_train_model)
    monkeypatch.setattr(train_cli, "evaluate_model", fake_evaluate_model)

    train_cli.main()

    np.testing.assert_array_equal(captured["train"], raw_train.to_numpy())
    np.testing.assert_array_equal(captured["test"], raw_test.to_numpy())
    np.testing.assert_array_equal(captured["train_labels"], y_train.to_numpy())
    np.testing.assert_array_equal(captured["test_labels"], y_test.to_numpy())
