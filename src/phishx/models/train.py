"""Train, evaluate, and save the PHISH-X Newton Logistic Regression artifact.

Run from the repository root:
    python src/phishx/models/train.py
The serialized artifact is written locally and is intentionally not committed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib

SOURCE_ROOT = Path(__file__).resolve().parents[2]
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from phishx.data.dataset import load_group_split
from phishx.models.training import evaluate_model, train_model
from phishx.models.numerical_analysis import (
    evaluate_numerical_model,
    method_demos,
    train_numerical_model,
)

PROJECT_ROOT = Path(__file__).resolve().parents[3]
ARTIFACT_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "model_artifacts"
    / "phishx_newton_model.joblib"
)
METRICS_PATH = (
    PROJECT_ROOT
    / "data"
    / "processed"
    / "model_artifacts"
    / "training_metrics.json"
)


def main() -> None:
    # Keep the source data raw here. train_model fits the numerical scaler
    # on Group Train and stores that exact scaler in the inference artifact.
    # evaluate_model then applies the same scaler once to raw Group Test data.
    X_train, X_test, y_train, y_test = load_group_split()

    artifact = train_model(
        X_train,
        y_train,
        l2=1e-3,
        max_iterations=100,
        damping=1e-8,
        tolerance=1e-7,
    )
    metrics = evaluate_model(artifact, X_test, y_test)

    # Train a separate syllabus-level least-squares baseline on the exact
    # same Group Train / Group Test split. The original ML artifact is unchanged.
    numerical_artifact = train_numerical_model(X_train, y_train, ridge=1e-3)
    numerical_metrics = evaluate_numerical_model(numerical_artifact, X_test, y_test)

    # Persist only the inference contract plus transparent training metadata.
    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, ARTIFACT_PATH)

    report = {
        "training": artifact["training"],
        "evaluation": metrics,
        "dataset_split": "Group Split by Host",
        "feature_columns": list(artifact["feature_columns"]),
        "feature_spec_version": artifact["feature_spec_version"],
        "numerical_analysis": {
            "training": {
                "method": "Straight-line least-squares baseline (normal equations)",
                "linear_system_solver": "Gaussian Elimination with partial pivoting",
                "regularization": 1e-3,
                "scaler": "NumericalStandardScaler fitted on Group Train only",
                "score_interpretation": "Clipped score in [0, 1]; not a calibrated probability.",
            },
            "evaluation": numerical_metrics,
            "syllabus_demonstrations": method_demos(),
        },
        "comparison": {
            "test_samples": int(len(y_test)),
            "split": "Identical Group Split by Host",
            "phishing_metrics": {
                "newton_logistic_regression": {
                    "accuracy": metrics["accuracy"],
                    "precision": metrics["class_metrics"]["phishing"]["precision"],
                    "recall": metrics["class_metrics"]["phishing"]["recall"],
                    "f1_score": metrics["class_metrics"]["phishing"]["f1_score"],
                },
                "gauss_least_squares_baseline": {
                    "accuracy": numerical_metrics["accuracy"],
                    "precision": numerical_metrics["phishing_precision"],
                    "recall": numerical_metrics["phishing_recall"],
                    "f1_score": numerical_metrics["phishing_f1"],
                },
            },
        },
    }
    METRICS_PATH.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("PHISH-X NUMERICAL TRAINING COMPLETED")
    print(f"Artifact: {ARTIFACT_PATH}")
    print(f"Metrics:  {METRICS_PATH}")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
