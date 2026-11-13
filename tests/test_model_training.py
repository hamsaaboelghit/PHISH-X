import numpy as np

from phishx.inference import validate_artifact, MODEL_FEATURES
from phishx.models.training import evaluate_model, train_model


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
    assert sum(metrics["confusion_matrix"].values()) == len(y_train)
