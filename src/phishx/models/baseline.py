"""5-feature baseline logistic regression (training + serving).

Trains the AI Model Core baseline on the fixed Group Split:
StandardScaler fit on train only, then logistic regression with
NumPy batch Gradient Descent (same math as
``origin/norhan/ai-model-core:src/phishx/models/logistic_regression.py``)
or Newton's Method. Labels are used as stored (0 = Phishing,
1 = Legitimate), so the model output is P(Legitimate).

The 5 baseline features are selected BY NAME from the 16-feature
extractor output (``phishx.features.url_features``) in baseline order
(which differs from dataset order). The adapter never reorders or
renames features silently; see ``adapt_features``.

No network access. Training is deterministic (zero initialisation).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from phishx.features.url_features import FEATURE_NAMES, extract_features

__all__ = [
    "BASELINE_FEATURES",
    "BaselineModel",
    "adapt_features",
    "train_baseline",
]

#: Norhan's 5-feature baseline subset, in baseline (model) order.
#: NOTE: this order differs from dataset/FEATURE_NAMES order.
BASELINE_FEATURES: tuple[str, ...] = (
    "url_length",
    "number_of_digits",
    "url_entropy",
    "dot_count",
    "path_length",
)

ROOT = Path(__file__).resolve().parents[3]
CLEANED = ROOT / "data" / "processed" / "cleaned_dataset.csv"
GROUP_TRAIN = ROOT / "data" / "processed" / "splits" / "group_train.csv"
GROUP_TEST = ROOT / "data" / "processed" / "splits" / "group_test.csv"


# ------------------------------------------------------------------ math


def sigmoid(z):
    """Numerically stable sigmoid (same as AI Model Core)."""
    z = np.asarray(z, dtype=float)
    out = np.empty_like(z)
    pos = z >= 0
    out[pos] = 1.0 / (1.0 + np.exp(-z[pos]))
    exp_z = np.exp(z[~pos])
    out[~pos] = exp_z / (1.0 + exp_z)
    return out


def binary_cross_entropy(y_true, y_pred) -> float:
    """Mean binary cross-entropy with clipping (same as AI Model Core)."""
    eps = 1e-15
    y_pred = np.clip(np.asarray(y_pred, dtype=float), eps, 1.0 - eps)
    y_true = np.asarray(y_true, dtype=float)
    return float(
        -np.mean(y_true * np.log(y_pred) + (1.0 - y_true) * np.log(1.0 - y_pred))
    )


def _augment(X: np.ndarray) -> np.ndarray:
    """Append a bias column of ones (last column)."""
    return np.hstack([X, np.ones((X.shape[0], 1))])


def gradient_descent(X, y, *, learning_rate=0.1, n_iterations=1000, l2=0.0):
    """Batch gradient descent. Returns (weights_with_bias, loss_history)."""
    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=float)
    Xa = _augment(X)
    w = np.zeros(Xa.shape[1])
    history: list[float] = []
    for _ in range(n_iterations):
        p = sigmoid(Xa @ w)
        grad = Xa.T @ (p - y) / len(y)
        if l2:
            reg = (l2 / len(y)) * w.copy()
            reg[-1] = 0.0  # do not regularise bias
            grad = grad + reg
        w = w - learning_rate * grad
        history.append(binary_cross_entropy(y, sigmoid(Xa @ w)))
    return w, history


def newtons_method(X, y, *, n_iterations=50, l2=0.0, tol=1e-8):
    """Newton's Method (Hessian-based). Returns (weights_with_bias, history).

    Update: w <- w - H^{-1} g, with
      g = X_a^T (p - y) / m  (+ L2 term),
      H = X_a^T diag(p(1-p)) X_a / m  (+ L2 term).
    Stops early when the gradient norm falls below ``tol``.
    """
    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=float)
    Xa = _augment(X)
    m = len(y)
    w = np.zeros(Xa.shape[1])
    history: list[float] = []
    for _ in range(n_iterations):
        p = sigmoid(Xa @ w)
        grad = Xa.T @ (p - y) / m
        s = p * (1.0 - p)
        hess = (Xa.T * s) @ Xa / m
        if l2:
            reg = (l2 / m) * np.eye(len(w))
            reg[-1, -1] = 0.0
            grad = grad + (l2 / m) * w * np.r_[np.ones(len(w) - 1), 0.0]
            hess = hess + reg
        try:
            step = np.linalg.solve(hess, grad)
        except np.linalg.LinAlgError:
            step = np.linalg.pinv(hess) @ grad
        w = w - step
        history.append(binary_cross_entropy(y, sigmoid(Xa @ w)))
        if np.linalg.norm(grad) < tol:
            break
    return w, history


# --------------------------------------------------------------- adapter


def adapt_features(features: dict[str, float]) -> np.ndarray:
    """Select the 5 baseline features BY NAME, in baseline order.

    Args:
        features: mapping with (at least) the 16 extractor keys.

    Returns:
        1-D float array of length 5 in ``BASELINE_FEATURES`` order.

    Raises:
        KeyError: if a baseline feature is missing (never silently
            reorders or substitutes).
    """
    missing = [f for f in BASELINE_FEATURES if f not in features]
    if missing:
        raise KeyError(f"missing baseline features: {missing}")
    return np.array([float(features[f]) for f in BASELINE_FEATURES], dtype=float)


# ----------------------------------------------------------------- model


@dataclass
class BaselineModel:
    """Trained 5-feature baseline (weights include bias as last element)."""

    weights: np.ndarray  # length 6 (5 features + bias)
    mean: np.ndarray  # scaler mean (train only)
    scale: np.ndarray  # scaler scale (train only)
    optimizer: str = "gradient_descent"
    n_iterations: int = 0
    final_loss: float = float("nan")
    loss_history: list[float] = field(default_factory=list)
    runtime_seconds: float = 0.0
    train_accuracy: float = float("nan")
    test_accuracy: float = float("nan")

    def _scale(self, X: np.ndarray) -> np.ndarray:
        return (np.asarray(X, dtype=float) - self.mean) / self.scale

    def predict_proba_legitimate(self, features: dict[str, float]) -> float:
        """P(Legitimate) for one URL's extracted features (16-key dict)."""
        x = adapt_features(features)
        xs = self._scale(x.reshape(1, -1))
        return float(sigmoid(_augment(xs) @ self.weights)[0])

    def predict(self, features: dict[str, float]) -> tuple[str, float]:
        """Return (predicted_class, confidence).

        Predicted class is "Legitimate" when P(Legitimate) >= 0.5,
        else "Phishing". Confidence is the probability of the
        predicted class.
        """
        p_legit = self.predict_proba_legitimate(features)
        if p_legit >= 0.5:
            return "Legitimate", p_legit
        return "Phishing", 1.0 - p_legit

    def explain(self, features: dict[str, float]) -> list[tuple[str, float]]:
        """Per-feature contributions: weight_i * scaled_value_i.

        Sorted by absolute contribution (largest first). These are the
        linear model's additive terms (plus bias), so they sum with the
        bias to the logit. They explain THIS model's decision only.
        """
        x = adapt_features(features)
        xs = self._scale(x.reshape(1, -1))[0]
        contribs = [
            (name, float(self.weights[i] * xs[i]))
            for i, name in enumerate(BASELINE_FEATURES)
        ]
        return sorted(contribs, key=lambda kv: abs(kv[1]), reverse=True)


def _load_group_split():
    cleaned = pd.read_csv(CLEANED)
    train_m = pd.read_csv(GROUP_TRAIN)
    test_m = pd.read_csv(GROUP_TEST)
    # Manifests already carry ClassLabel/host; keep the cleaned copy as
    # the feature source (same suffix handling as the AI Model Core).
    train = train_m.merge(
        cleaned, on="URL", how="left",
        suffixes=("_manifest", ""), validate="one_to_one",
    )
    test = test_m.merge(
        cleaned, on="URL", how="left",
        suffixes=("_manifest", ""), validate="one_to_one",
    )
    X_train = train[list(BASELINE_FEATURES)].to_numpy(dtype=float)
    X_test = test[list(BASELINE_FEATURES)].to_numpy(dtype=float)
    y_train = train["ClassLabel"].to_numpy(dtype=float)
    y_test = test["ClassLabel"].to_numpy(dtype=float)
    return X_train, X_test, y_train, y_test


def train_baseline(
    optimizer: str = "gradient_descent",
    *,
    learning_rate: float = 0.1,
    n_iterations: int = 1000,
) -> BaselineModel:
    """Train the 5-feature baseline on the fixed Group Split.

    Scaler is fit on train only. Labels are used as stored
    (0 = Phishing, 1 = Legitimate); output is P(Legitimate).
    Deterministic (zero initialisation, no randomness).
    """
    if optimizer not in ("gradient_descent", "newtons_method"):
        raise ValueError(f"unknown optimizer: {optimizer!r}")
    X_train, X_test, y_train, y_test = _load_group_split()
    mean = X_train.mean(axis=0)
    scale = X_train.std(axis=0)
    scale = np.where(scale == 0.0, 1.0, scale)
    Xs_train = (X_train - mean) / scale
    Xs_test = (X_test - mean) / scale

    start = time.perf_counter()
    if optimizer == "gradient_descent":
        w, history = gradient_descent(
            Xs_train, y_train,
            learning_rate=learning_rate, n_iterations=n_iterations,
        )
    else:
        w, history = newtons_method(Xs_train, y_train, n_iterations=50)
    runtime = time.perf_counter() - start

    def _acc(Xs, y):
        p = sigmoid(_augment(Xs) @ w)
        pred = (p >= 0.5).astype(float)
        return float((pred == y).mean())

    return BaselineModel(
        weights=w,
        mean=mean,
        scale=scale,
        optimizer=optimizer,
        n_iterations=len(history),
        final_loss=history[-1] if history else float("nan"),
        loss_history=history,
        runtime_seconds=runtime,
        train_accuracy=_acc(Xs_train, y_train),
        test_accuracy=_acc(Xs_test, y_test),
    )


def analyze_url(url: str, model: BaselineModel) -> dict:
    """Full URL Investigation pipeline for one URL (no network).

    Returns a dict with extraction status, features, warnings, security
    signals, prediction (or None on failure), and explanation.
    Security warnings are diagnostics only — never a prediction.
    """
    from phishx.features.url_signals import analyze_url_security

    result = extract_features(url)
    signals = analyze_url_security(url)
    out: dict = {
        "url": url,
        "extraction_ok": result.ok,
        "extraction_status": result.status,
        "features": dict(result.features) if result.ok else None,
        "warnings": list(result.warnings),
        "signals": signals.as_dict(),
        "prediction": None,
        "confidence": None,
        "explanation": None,
        "no_prediction_reason": None,
    }
    if result.ok and signals.is_opaque_scheme:
        # Opaque schemes (javascript:, data:, mailto:, ...) never occur
        # in the training data (http/https only) and have no host, so
        # the model is out of distribution. Offer no prediction rather
        # than a confident verdict from degenerate features.
        out["no_prediction_reason"] = (
            "Opaque scheme (no host); outside the model's training "
            "distribution (http/https only). No prediction offered."
        )
    elif result.ok:
        cls, conf = model.predict(result.features)
        out["prediction"] = cls
        out["confidence"] = conf
        out["explanation"] = model.explain(result.features)
    else:
        out["no_prediction_reason"] = (
            f"Feature extraction failed (status: {result.status}). "
            "No prediction offered."
        )
    return out
