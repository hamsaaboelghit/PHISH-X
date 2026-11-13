"""Numerical preprocessing for the PHISH-X Logistic Regression model.

Feature standardization is implemented directly from its equations rather
than delegated to scikit-learn:
    mean_j = (1/n) * sum_i x_ij
    variance_j = (1/n) * sum_i (x_ij - mean_j)^2
    z_ij = (x_ij - mean_j) / scale_j
For constant columns, scale_j is set to 1 to avoid division by zero.
"""
from __future__ import annotations

import numpy as np

from phishx.data.dataset import load_group_split


class NumericalStandardScaler:
    """Small StandardScaler-compatible transformer implemented with NumPy."""

    def __init__(self):
        self.mean_ = None
        self.var_ = None
        self.scale_ = None
        self.n_features_in_ = None
        self.n_samples_seen_ = None

    @staticmethod
    def _validate_matrix(X, *, fitting=False):
        try:
            values = np.asarray(X, dtype=float)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("Features must be numeric.") from exc
        if values.ndim != 2 or values.shape[0] == 0 or values.shape[1] == 0:
            raise ValueError("Features must be a non-empty 2D matrix.")
        if not np.isfinite(values).all():
            raise ValueError("Features must contain only finite values.")
        return values

    def fit(self, X):
        """Estimate population means and variances from training data."""
        values = self._validate_matrix(X, fitting=True)
        self.mean_ = np.mean(values, axis=0)
        centered = values - self.mean_
        self.var_ = np.mean(centered * centered, axis=0)
        self.scale_ = np.sqrt(self.var_)

        # StandardScaler convention: constant columns are left unscaled.
        self.scale_ = np.where(self.scale_ == 0.0, 1.0, self.scale_)
        self.n_features_in_ = values.shape[1]
        self.n_samples_seen_ = values.shape[0]
        return self

    def transform(self, X):
        """Apply training-set statistics without refitting."""
        if self.mean_ is None or self.scale_ is None:
            raise RuntimeError("Scaler must be fitted before transform().")
        values = self._validate_matrix(X)
        if values.shape[1] != self.n_features_in_:
            raise ValueError(
                f"Expected {self.n_features_in_} features, got {values.shape[1]}."
            )
        transformed = (values - self.mean_) / self.scale_
        if not np.isfinite(transformed).all():
            raise ValueError("Scaled features contain non-finite values.")
        return transformed

    def fit_transform(self, X):
        """Fit on X and return its standardized representation."""
        return self.fit(X).transform(X)


def prepare_group_data():
    """
    Load Group Split and apply manually implemented feature scaling.

    The scaler is fitted on training data only to prevent data leakage.
    """

    X_train, X_test, y_train, y_test = load_group_split()

    scaler = NumericalStandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    y_train = y_train.to_numpy(dtype=int)
    y_test = y_test.to_numpy(dtype=int)

    if not np.isfinite(X_train_scaled).all():
        raise ValueError("Invalid values found in scaled training data.")
    if not np.isfinite(X_test_scaled).all():
        raise ValueError("Invalid values found in scaled test data.")

    return (
        X_train_scaled,
        X_test_scaled,
        y_train,
        y_test,
        scaler,
    )
