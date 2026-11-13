"""Numerical-method verification against the production Logistic Regression API.

These tests deliberately call the project's implementation rather than
maintaining a second copy of sigmoid, loss, gradient, Hessian, or optimizers.
"""

import numpy as np
import pytest

from phishx.models.logistic_regression import (
    compute_gradient,
    compute_hessian,
    gradient_descent,
    newton_method,
    sigmoid,
    training_loss,
)


@pytest.fixture
def verification_data():
    X = np.array(
        [
            [1.0, 0.5, 1.5],
            [1.0, 1.5, 0.5],
            [1.0, 2.0, 1.0],
            [1.0, 0.5, 2.0],
            [1.0, 2.5, 1.5],
            [1.0, 1.0, 2.5],
        ]
    )
    y = np.array([0, 0, 1, 0, 1, 1])
    return X, y


def _loss_at_parameters(X, y, parameters, l2):
    weights = parameters[:-1]
    bias = parameters[-1]
    probabilities = sigmoid(X @ weights + bias)
    return training_loss(y, probabilities, weights, l2)


def _analytical_gradient(X, y, parameters, l2):
    weights = parameters[:-1]
    bias = parameters[-1]
    dw, db = compute_gradient(X, y, weights, bias, l2)
    return np.append(dw, db)


def _numerical_gradient(X, y, parameters, l2, step):
    result = np.zeros_like(parameters, dtype=float)
    for index in range(parameters.size):
        plus = parameters.copy()
        minus = parameters.copy()
        plus[index] += step
        minus[index] -= step
        result[index] = (
            _loss_at_parameters(X, y, plus, l2)
            - _loss_at_parameters(X, y, minus, l2)
        ) / (2.0 * step)
    return result


def _numerical_hessian(X, y, parameters, l2, step):
    result = np.zeros((parameters.size, parameters.size), dtype=float)
    for column in range(parameters.size):
        plus = parameters.copy()
        minus = parameters.copy()
        plus[column] += step
        minus[column] -= step
        result[:, column] = (
            _analytical_gradient(X, y, plus, l2)
            - _analytical_gradient(X, y, minus, l2)
        ) / (2.0 * step)
    return result


@pytest.mark.parametrize(
    "parameters,l2",
    [
        (np.array([0.0, 0.0, 0.0, 0.0]), 0.0),
        (np.array([0.2, -0.3, 0.1, 0.15]), 0.1),
        (np.array([-0.5, 0.3, 0.25, -0.2]), 0.5),
    ],
)
@pytest.mark.parametrize("step", [1e-4, 1e-5])
def test_analytical_gradient_matches_finite_difference(
    verification_data, parameters, l2, step
):
    X, y = verification_data
    analytical = _analytical_gradient(X, y, parameters, l2)
    numerical = _numerical_gradient(X, y, parameters, l2, step)

    np.testing.assert_allclose(
        analytical, numerical, atol=2e-7, rtol=2e-5
    )


@pytest.mark.parametrize(
    "parameters,l2",
    [
        (np.array([0.0, 0.0, 0.0, 0.0]), 0.0),
        (np.array([0.2, -0.3, 0.1, 0.15]), 0.1),
        (np.array([-0.5, 0.3, 0.25, -0.2]), 0.5),
    ],
)
@pytest.mark.parametrize("step", [1e-4, 1e-5])
def test_analytical_hessian_matches_finite_difference(
    verification_data, parameters, l2, step
):
    X, _ = verification_data
    analytical = compute_hessian(X, parameters[:-1], parameters[-1], l2)
    numerical = _numerical_hessian(
        X, verification_data[1], parameters, l2, step
    )

    np.testing.assert_allclose(
        analytical, numerical, atol=3e-7, rtol=3e-5
    )


def test_hessian_is_symmetric_and_positive_semidefinite(verification_data):
    X, _ = verification_data
    hessian = compute_hessian(
        X, np.array([0.2, -0.3, 0.1]), 0.15, l2=0.1
    )

    np.testing.assert_allclose(hessian, hessian.T, atol=1e-12)
    assert np.linalg.eigvalsh(hessian).min() >= -1e-10


def test_newton_handles_rank_deficient_features():
    # The last two columns are identical, so the undamped Hessian is singular.
    X = np.array(
        [
            [1.0, 1.0, 1.0],
            [1.0, 2.0, 2.0],
            [1.0, 3.0, 3.0],
            [1.0, 4.0, 4.0],
            [1.0, 5.0, 5.0],
            [1.0, 6.0, 6.0],
        ]
    )
    y = np.array([0, 0, 0, 1, 1, 1])

    weights, bias, history = newton_method(
        X, y, n_iterations=100, l2=0.0, damping=1e-8
    )

    assert np.isfinite(weights).all()
    assert np.isfinite(bias)
    assert len(history) > 1
    assert np.isfinite(history).all()
    assert np.all(np.diff(history) <= 1e-12)


def test_gradient_descent_and_newton_both_reduce_the_same_objective(
    verification_data,
):
    X, y = verification_data
    l2 = 0.1
    initial_weights = np.zeros(X.shape[1])
    initial_bias = 0.0
    initial_loss = training_loss(
        y, sigmoid(X @ initial_weights + initial_bias),
        initial_weights, l2
    )

    gd_weights, gd_bias, gd_history = gradient_descent(
        X, y, learning_rate=0.05, n_iterations=5000, l2=l2
    )
    newton_weights, newton_bias, newton_history = newton_method(
        X, y, n_iterations=100, l2=l2
    )

    for weights, bias, history in (
        (gd_weights, gd_bias, gd_history),
        (newton_weights, newton_bias, newton_history),
    ):
        assert np.isfinite(weights).all()
        assert np.isfinite(bias)
        assert np.isfinite(history).all()
        assert history[-1] < initial_loss

    assert np.all(np.diff(newton_history) <= 1e-12)
