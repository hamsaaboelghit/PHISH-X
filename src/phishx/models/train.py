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

from phishx.data.preprocessing import prepare_group_data
from phishx.models.training import evaluate_model, train_model

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
    X_train, X_test, y_train, y_test, _ = prepare_group_data()

    artifact = train_model(
        X_train,
        y_train,
        l2=1e-3,
        max_iterations=100,
        damping=1e-8,
        tolerance=1e-7,
    )
    metrics = evaluate_model(artifact, X_test, y_test)

    # Persist only the inference contract plus transparent training metadata.
    ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, ARTIFACT_PATH)

    report = {
        "training": artifact["training"],
        "evaluation": metrics,
        "dataset_split": "Group Split by Host",
        "feature_columns": list(artifact["feature_columns"]),
        "feature_spec_version": artifact["feature_spec_version"],
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
