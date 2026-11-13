import numpy as np
import pytest

from phishx.models.logistic_regression import predict_proba, predict


def test_predict_proba_returns_positive_class_probability():
    X = np.array([[0.0], [1.0], [-1.0]])
    weights = np.array([1.0])

    result = predict_proba(X, weights, 0.0)

    np.testing.assert_allclose(result, [0.5, 0.73105858, 0.26894142], atol=1e-7)


def test_predict_returns_binary_labels():
    X = np.array([[-2.0], [0.0], [2.0]])
    weights = np.array([1.0])

    result = predict(X, weights, 0.0)

    np.testing.assert_array_equal(result, [0, 1, 1])


def test_predict_respects_custom_threshold():
    X = np.array([[0.0], [1.0]])
    weights = np.array([1.0])

    result = predict(X, weights, 0.0, threshold=0.7)

    np.testing.assert_array_equal(result, [0, 1])


@pytest.mark.parametrize(
    "X, weights, bias",
    [
        (np.array([1.0, 2.0]), np.array([1.0, 1.0]), 0.0),
        (np.empty((0, 1)), np.array([1.0]), 0.0),
        (np.array([[np.nan]]), np.array([1.0]), 0.0),
        (np.array([[1.0]]), np.array([1.0, 2.0]), 0.0),
        (np.array([[1.0]]), np.array([np.inf]), 0.0),
        (np.array([[1.0]]), np.array([1.0]), np.nan),
    ],
)
def test_predict_proba_rejects_invalid_inputs(X, weights, bias):
    with pytest.raises(ValueError):
        predict_proba(X, weights, bias)


@pytest.mark.parametrize("threshold", [-0.1, 1.1, np.nan, np.inf, "0.5"])
def test_predict_rejects_invalid_threshold(threshold):
    with pytest.raises(ValueError):
        predict(np.array([[1.0]]), np.array([1.0]), 0.0, threshold)
