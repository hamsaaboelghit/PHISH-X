"""End-to-end training and evaluation for the hand-written PHISH-X model.

All model optimization is performed by phishx.models.logistic_regression.
No scikit-learn estimator or optimizer is used here.
"""
from __future__ import annotations

import numpy as np

from phishx.data.preprocessing import NumericalStandardScaler
from phishx.features.url_features import FEATURE_SPEC_VERSION
from phishx.inference import EXPECTED_LABEL_MAPPING, MODEL_FEATURES
from phishx.models.logistic_regression import newton_method, predict_proba


def train_model(
    X_train,
    y_train,
    *,
    l2: float = 1e-3,
    max_iterations: int = 100,
    damping: float = 1e-8,
    tolerance: float = 1e-7,
):
    """Fit scaler on training data and train Newton Logistic Regression."""
    X_train = np.asarray(X_train, dtype=float)
    y_train = np.asarray(y_train, dtype=int)

    if X_train.ndim != 2 or X_train.shape[1] != len(MODEL_FEATURES):
        raise ValueError(
            f"X_train must have exactly {len(MODEL_FEATURES)} columns."
        )
    if X_train.shape[0] == 0 or y_train.shape != (X_train.shape[0],):
        raise ValueError("Training features and labels must be non-empty and aligned.")
    if not np.isfinite(X_train).all():
        raise ValueError("Training features must be finite.")
    if not np.isin(y_train, [0, 1]).all() or np.unique(y_train).size != 2:
        raise ValueError("Training labels must contain both binary classes 0 and 1.")

    scaler = NumericalStandardScaler()
    X_scaled = scaler.fit_transform(X_train)

    weights, bias, loss_history = newton_method(
        X_scaled,
        y_train,
        n_iterations=max_iterations,
        l2=l2,
        damping=damping,
        tolerance=tolerance,
    )

    if not np.isfinite(weights).all() or not np.isfinite(bias):
        raise RuntimeError("Training produced non-finite model parameters.")
    if len(loss_history) < 1 or not np.isfinite(loss_history).all():
        raise RuntimeError("Training produced an invalid loss history.")
    if any(
        later > earlier + 1e-10
        for earlier, later in zip(loss_history, loss_history[1:])
    ):
        raise RuntimeError("Newton training loss increased.")

    return {
        "scaler": scaler,
        "weights": weights,
        "bias": float(bias),
        "threshold": 0.5,
        "feature_columns": MODEL_FEATURES,
        "label_mapping": dict(EXPECTED_LABEL_MAPPING),
        "feature_spec_version": FEATURE_SPEC_VERSION,
        "training": {
            "method": "Newton-Raphson Logistic Regression",
            "l2": float(l2),
            "iterations": len(loss_history) - 1,
            "initial_loss": float(loss_history[0]),
            "final_loss": float(loss_history[-1]),
            "loss_history": [float(value) for value in loss_history],
            "scaler": "NumericalStandardScaler",
        },
    }


def evaluate_model(artifact, X_test, y_test):
    """Evaluate on untouched test data and return binary classification metrics."""
    X_test = np.asarray(X_test, dtype=float)
    y_test = np.asarray(y_test, dtype=int)

    if X_test.ndim != 2 or X_test.shape[1] != len(MODEL_FEATURES):
        raise ValueError(
            f"X_test must have exactly {len(MODEL_FEATURES)} columns."
        )
    if X_test.shape[0] == 0 or y_test.shape != (X_test.shape[0],):
        raise ValueError("Test features and labels must be non-empty and aligned.")
    if not np.isfinite(X_test).all() or not np.isin(y_test, [0, 1]).all():
        raise ValueError("Test data must contain finite features and binary labels.")

    X_scaled = artifact["scaler"].transform(X_test)
    probabilities = predict_proba(
        X_scaled, artifact["weights"], artifact["bias"]
    )
    predictions = (probabilities >= artifact["threshold"]).astype(int)

    tp = int(np.sum((predictions == 1) & (y_test == 1)))
    tn = int(np.sum((predictions == 0) & (y_test == 0)))
    fp = int(np.sum((predictions == 1) & (y_test == 0)))
    fn = int(np.sum((predictions == 0) & (y_test == 1)))

    accuracy = (tp + tn) / len(y_test)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = (
        2.0 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )

    # Labels are fixed by the project contract: 0 = Phishing, 1 = Legitimate.
    # Keep the legacy positive-class metrics for compatibility, but name the
    # class explicitly and report precision/recall/F1 for both classes.
    phishing_precision = tn / (tn + fn) if tn + fn else 0.0
    phishing_recall = tn / (tn + fp) if tn + fp else 0.0
    phishing_f1 = (
        2.0 * phishing_precision * phishing_recall
        / (phishing_precision + phishing_recall)
        if phishing_precision + phishing_recall
        else 0.0
    )

    return {
        "samples": int(len(y_test)),
        "threshold": float(artifact["threshold"]),
        "positive_class": "Legitimate",
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "specificity": float(specificity),
        "f1_score": float(f1),
        "class_metrics": {
            "phishing": {
                "label": 0,
                "precision": float(phishing_precision),
                "recall": float(phishing_recall),
                "f1_score": float(phishing_f1),
            },
            "legitimate": {
                "label": 1,
                "precision": float(precision),
                "recall": float(recall),
                "f1_score": float(f1),
            },
        },
        "confusion_matrix": {
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "true_positive": tp,
        },
    }
