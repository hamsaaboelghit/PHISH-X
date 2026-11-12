import numpy as np
import pytest

from phishx.models.logistic_regression import (
    sigmoid,
    binary_cross_entropy,
    training_loss,
    compute_gradient,
    compute_hessian,
    gradient_descent,
    newton_method,
)


X = np.array([
    [1.0, 2.0],
    [2.0, 1.0],
    [3.0, 2.0],
    [1.0, 3.0],
])

y = np.array([0, 0, 1, 1])
weights = np.array([0.2, -0.3])
bias = 0.1
l2 = 0.5


def numerical_gradient(X, y, weights, bias, l2, epsilon=1e-5):
    theta = np.append(weights, bias)
    numerical = np.zeros_like(theta)

    for j in range(len(theta)):
        plus = theta.copy()
        minus = theta.copy()

        plus[j] += epsilon
        minus[j] -= epsilon

        p_plus = sigmoid(X @ plus[:-1] + plus[-1])
        p_minus = sigmoid(X @ minus[:-1] + minus[-1])

        loss_plus = training_loss(y, p_plus, plus[:-1], l2)
        loss_minus = training_loss(y, p_minus, minus[:-1], l2)

        numerical[j] = (loss_plus - loss_minus) / (2 * epsilon)

    return numerical


def test_sigmoid_values():
    result = sigmoid(np.array([0.0, 1.0, -1.0]))

    np.testing.assert_allclose(
        result,
        [0.5, 0.73105858, 0.26894142],
        atol=1e-7,
    )


def test_sigmoid_is_numerically_stable():
    result = sigmoid(np.array([-1000.0, 0.0, 1000.0]))

    assert np.isfinite(result).all()
    assert np.all((result >= 0) & (result <= 1))


def test_binary_cross_entropy():
    result = binary_cross_entropy(
        np.array([0, 1]),
        np.array([0.2, 0.8]),
    )

    assert result == pytest.approx(-np.log(0.8))


def test_training_loss_includes_l2_without_bias():
    probabilities = sigmoid(X @ weights + bias)

    bce = binary_cross_entropy(y, probabilities)
    expected = bce + (l2 / (2 * len(y))) * np.sum(weights ** 2)

    result = training_loss(y, probabilities, weights, l2)

    assert result == pytest.approx(expected)


def test_gradient_matches_numerical_gradient():
    analytical_w, analytical_b = compute_gradient(
        X, y, weights, bias, l2
    )

    analytical = np.append(analytical_w, analytical_b)

    numerical = numerical_gradient(
        X, y, weights, bias, l2
    )

    np.testing.assert_allclose(
        analytical,
        numerical,
        atol=1e-7,
    )


def test_hessian_matches_numerical_gradient_derivative():
    analytical = compute_hessian(X, weights, bias, l2)

    theta = np.append(weights, bias)
    numerical = np.zeros_like(analytical)
    epsilon = 1e-5

    for j in range(len(theta)):
        plus = theta.copy()
        minus = theta.copy()

        plus[j] += epsilon
        minus[j] -= epsilon

        grad_plus = np.append(
            *compute_gradient(X, y, plus[:-1], plus[-1], l2)
        )

        grad_minus = np.append(
            *compute_gradient(X, y, minus[:-1], minus[-1], l2)
        )

        numerical[:, j] = (
            grad_plus - grad_minus
        ) / (2 * epsilon)

    np.testing.assert_allclose(
        analytical,
        numerical,
        atol=1e-7,
    )


def test_hessian_is_symmetric():
    hessian = compute_hessian(X, weights, bias, l2)

    np.testing.assert_allclose(
        hessian,
        hessian.T,
        atol=1e-10,
    )


def test_hessian_is_positive_semidefinite():
    hessian = compute_hessian(X, weights, bias, l2)
    eigenvalues = np.linalg.eigvalsh(hessian)

    assert np.all(eigenvalues >= -1e-10)


@pytest.mark.parametrize(
    "invalid_X, invalid_y",
    [
        (np.array([1, 2, 3, 4]), y),
        (X, np.array([0, 1, 2, 1])),
        (np.array([[1.0], [np.nan], [3.0], [4.0]]), y),
        (X, np.array([0, 1])),
        (np.empty((0, 2)), np.array([])),
    ],
)
def test_gradient_descent_rejects_invalid_training_data(
    invalid_X, invalid_y
):
    with pytest.raises(ValueError):
        gradient_descent(invalid_X, invalid_y)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"learning_rate": -0.1},
        {"learning_rate": 0},
        {"n_iterations": 0},
        {"n_iterations": 1.5},
        {"l2": -0.1},
        {"tolerance": 0},
        {"loss_tolerance": -1},
    ],
)
def test_gradient_descent_rejects_invalid_parameters(kwargs):
    with pytest.raises(ValueError):
        gradient_descent(X, y, **kwargs)


def test_gradient_descent_returns_valid_model():
    result_w, result_b, history = gradient_descent(
        X, y,
        learning_rate=0.1,
        n_iterations=1000,
        l2=0.1,
    )

    assert result_w.shape == (X.shape[1],)
    assert np.isfinite(result_w).all()
    assert np.isfinite(result_b)
    assert len(history) >= 1
    assert np.isfinite(history).all()
    assert history[-1] < history[0]


def test_newton_method_returns_valid_model():
    result_w, result_b, history = newton_method(
        X, y,
        n_iterations=100,
        l2=0.1,
    )

    assert result_w.shape == (X.shape[1],)
    assert np.isfinite(result_w).all()
    assert np.isfinite(result_b)
    assert len(history) >= 1
    assert np.isfinite(history).all()
    assert history[-1] <= history[0]


def test_newton_loss_does_not_increase():
    _, _, history = newton_method(
        X, y,
        n_iterations=100,
        l2=0.1,
    )

    assert np.all(np.diff(history) < 0)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"n_iterations": 0},
        {"n_iterations": 1.5},
        {"l2": -0.1},
        {"damping": 0},
        {"damping": -1},
        {"tolerance": 0},
        {"loss_tolerance": -1},
    ],
)
def test_newton_method_rejects_invalid_parameters(kwargs):
    with pytest.raises(ValueError):
        newton_method(X, y, **kwargs)
