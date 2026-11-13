"""Additive feature contributions for the PHISH-X logistic model.

Contributions are terms in the model logit (log-odds), not causal
explanations and not probabilities.
"""
from __future__ import annotations

from collections.abc import Sequence

import numpy as np


def explain_logit(
    scaled_features: Sequence[float],
    weights: Sequence[float],
    bias: float,
    feature_names: Sequence[str],
) -> tuple[float, dict[str, float]]:
    """Return the model logit and each feature's additive logit contribution."""
    x = np.asarray(scaled_features, dtype=float)
    w = np.asarray(weights, dtype=float)
    names = tuple(feature_names)

    if x.ndim != 1 or w.ndim != 1 or x.shape != w.shape:
        raise ValueError("scaled_features and weights must be matching 1D vectors.")
    if len(names) != len(x) or len(set(names)) != len(names):
        raise ValueError("feature_names must be unique and match vector length.")
    if not np.isfinite(x).all() or not np.isfinite(w).all():
        raise ValueError("features and weights must be finite.")
    if isinstance(bias, (bool, np.bool_)):
        raise ValueError("bias must be finite.")
    try:
        bias_value = float(bias)
    except (TypeError, ValueError) as exc:
        raise ValueError("bias must be finite.") from exc
    if not np.isfinite(bias_value):
        raise ValueError("bias must be finite.")

    values = x * w
    contributions = {name: float(value) for name, value in zip(names, values)}
    logit = float(bias_value + np.sum(values))
    return logit, contributions
