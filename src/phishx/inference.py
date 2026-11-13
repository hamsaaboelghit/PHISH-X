"""Artifact-backed PHISH-X inference pipeline.

The pipeline deliberately reuses the production feature extractor and the
trained Newton Logistic Regression artifact. It does not train a second model.
Security signals are returned separately and never enter the model vector.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import numpy as np
import pandas as pd

from phishx.explainability.contributions import explain_logit
from phishx.features.url_features import FEATURE_SPEC_VERSION, extract_features
from phishx.features.url_signals import analyze_url_security
from phishx.models.logistic_regression import predict_proba

MODEL_FEATURES = (
    "url_length",
    "number_of_digits",
    "url_entropy",
    "dot_count",
    "path_length",
)
EXPECTED_LABEL_MAPPING = {0: "Phishing", 1: "Legitimate"}


class ArtifactContractError(ValueError):
    """Raised when a model artifact does not match the inference contract."""


@dataclass(frozen=True)
class PredictionResult:
    url: str
    prediction: str
    predicted_label: int
    phishing_probability: float
    legitimate_probability: float
    threshold: float
    model_features: dict[str, float]
    contributions: dict[str, float]
    bias_contribution: float
    logit: float
    extraction_warnings: tuple[str, ...]
    security_signals: dict[str, Any]

    @property
    def label(self) -> str:
        """Human-readable predicted class label."""
        return self.prediction

    def as_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "prediction": self.prediction,
            "predicted_label": self.predicted_label,
            "phishing_probability": self.phishing_probability,
            "legitimate_probability": self.legitimate_probability,
            "threshold": self.threshold,
            "model_features": dict(self.model_features),
            "contributions": dict(self.contributions),
            "bias_contribution": self.bias_contribution,
            "logit": self.logit,
            "extraction_warnings": list(self.extraction_warnings),
            "security_signals": dict(self.security_signals),
        }


def _finite_scalar(value: Any, name: str) -> float:
    if isinstance(value, (bool, np.bool_)):
        raise ArtifactContractError(f"{name} must be a finite number.")
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ArtifactContractError(f"{name} must be a finite number.") from exc
    if not np.isfinite(result):
        raise ArtifactContractError(f"{name} must be a finite number.")
    return result


def validate_artifact(artifact: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize the minimum supported joblib artifact schema.

    Required keys: scaler, weights, bias. Optional keys: threshold,
    feature_columns, label_mapping, feature_spec_version.
    """
    if not isinstance(artifact, Mapping):
        raise ArtifactContractError("Model artifact must be a mapping.")

    missing = {"scaler", "weights", "bias"} - set(artifact)
    if missing:
        raise ArtifactContractError(
            "Model artifact is missing required keys: "
            + ", ".join(sorted(missing))
        )

    raw_columns = artifact.get("feature_columns", MODEL_FEATURES)
    if isinstance(raw_columns, (str, bytes)):
        raise ArtifactContractError("feature_columns must be a sequence of feature names.")
    try:
        columns = tuple(raw_columns)
    except TypeError as exc:
        raise ArtifactContractError(
            "feature_columns must be a sequence of feature names."
        ) from exc
    if columns != MODEL_FEATURES:
        raise ArtifactContractError(
            f"Artifact feature_columns must exactly equal {MODEL_FEATURES!r}."
        )

    version = artifact.get("feature_spec_version", FEATURE_SPEC_VERSION)
    if version != FEATURE_SPEC_VERSION:
        raise ArtifactContractError(
            f"Unsupported feature specification version: {version!r}."
        )

    try:
        weights = np.asarray(artifact["weights"], dtype=float)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ArtifactContractError("Artifact weights must be numeric.") from exc
    if weights.shape != (len(MODEL_FEATURES),) or not np.isfinite(weights).all():
        raise ArtifactContractError(
            f"Artifact weights must be a finite vector of length {len(MODEL_FEATURES)}."
        )

    bias = _finite_scalar(artifact["bias"], "bias")
    threshold = _finite_scalar(artifact.get("threshold", 0.5), "threshold")
    if not 0.0 <= threshold <= 1.0:
        raise ArtifactContractError("threshold must be between 0 and 1 inclusive.")

    label_mapping = artifact.get("label_mapping", EXPECTED_LABEL_MAPPING)
    if not isinstance(label_mapping, Mapping):
        raise ArtifactContractError("label_mapping must be a mapping.")
    try:
        normalized_mapping = {}
        for key, value in label_mapping.items():
            if isinstance(key, (bool, np.bool_)):
                raise ValueError("boolean label keys are not supported")
            normalized_key = int(key)
            if normalized_key in normalized_mapping:
                raise ValueError("duplicate normalized label key")
            normalized_mapping[normalized_key] = str(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ArtifactContractError(
            "label_mapping must map 0 to 'Phishing' and 1 to 'Legitimate'."
        ) from exc
    if normalized_mapping != EXPECTED_LABEL_MAPPING:
        raise ArtifactContractError(
            "label_mapping must map 0 to 'Phishing' and 1 to 'Legitimate'."
        )

    scaler = artifact["scaler"]
    if not callable(getattr(scaler, "transform", None)):
        raise ArtifactContractError("Artifact scaler must provide transform().")
    scaler_feature_count = getattr(scaler, "n_features_in_", None)
    if scaler_feature_count is not None and scaler_feature_count != len(MODEL_FEATURES):
        raise ArtifactContractError("Scaler feature count does not match model features.")

    return {
        "scaler": scaler,
        "weights": weights,
        "bias": bias,
        "threshold": threshold,
        "feature_columns": columns,
        "label_mapping": normalized_mapping,
        "feature_spec_version": version,
    }


def load_model_artifact(path: str | Path) -> dict[str, Any]:
    """Load and validate a trusted local joblib artifact.

    Joblib uses pickle internally: only load artifacts from a trusted source.
    """
    try:
        import joblib
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError("joblib is required to load a model artifact.") from exc

    artifact_path = Path(path)
    if not artifact_path.is_file():
        raise FileNotFoundError(f"Model artifact not found: {artifact_path}")
    return validate_artifact(joblib.load(artifact_path))


def predict_url(url: object, artifact: Mapping[str, Any]) -> PredictionResult:
    """Extract, scale, predict, and explain one URL using a validated artifact."""
    model = validate_artifact(artifact)
    extracted = extract_features(url)
    if not extracted.ok:
        raise ValueError(f"URL feature extraction failed: {extracted.status}")

    raw_features = {
        name: float(extracted.features[name]) for name in model["feature_columns"]
    }
    frame = pd.DataFrame(
        [[raw_features[name] for name in model["feature_columns"]]],
        columns=model["feature_columns"],
    )
    try:
        scaled = np.asarray(model["scaler"].transform(frame), dtype=float)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ArtifactContractError("Scaler could not transform the model features.") from exc
    if scaled.shape != (1, len(MODEL_FEATURES)) or not np.isfinite(scaled).all():
        raise ArtifactContractError("Scaler returned an invalid transformed vector.")

    positive_probability = float(
        predict_proba(scaled, model["weights"], model["bias"])[0]
    )
    if not np.isfinite(positive_probability) or not 0.0 <= positive_probability <= 1.0:
        raise ArtifactContractError("Model returned an invalid probability.")

    predicted_label = int(positive_probability >= model["threshold"])
    logit, contributions = explain_logit(
        scaled[0], model["weights"], model["bias"], model["feature_columns"]
    )

    signals = analyze_url_security(url)
    return PredictionResult(
        url=extracted.url,
        prediction=model["label_mapping"][predicted_label],
        predicted_label=predicted_label,
        phishing_probability=1.0 - positive_probability,
        legitimate_probability=positive_probability,
        threshold=model["threshold"],
        model_features=raw_features,
        contributions=contributions,
        bias_contribution=float(model["bias"]),
        logit=logit,
        extraction_warnings=extracted.warnings,
        security_signals=signals.as_dict(),
    )
