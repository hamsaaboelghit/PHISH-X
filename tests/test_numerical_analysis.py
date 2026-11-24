import numpy as np
import pytest

from phishx.models.numerical_analysis import (
    bisection,
    divided_differences,
    evaluate_numerical_model,
    fit_exponential,
    fit_quadratic,
    fit_straight_line,
    fixed_point,
    gaussian_elimination,
    jacobi,
    lagrange_interpolate,
    newton_backward,
    newton_divided_eval,
    newton_forward,
    newton_root,
    predict_numerical_score,
    secant,
    simpson_one_third,
    train_numerical_model,
    trapezoidal,
)


def test_gaussian_elimination_with_partial_pivoting():
    matrix = np.array([[0.0, 2.0], [1.0, 1.0]])
    expected = np.array([1.0, 2.0])
    np.testing.assert_allclose(gaussian_elimination(matrix, matrix @ expected), expected)


def test_gaussian_elimination_rejects_singular_and_invalid_systems():
    with pytest.raises(ValueError, match="Singular"):
        gaussian_elimination([[1.0, 2.0], [2.0, 4.0]], [3.0, 6.0])
    with pytest.raises(ValueError):
        gaussian_elimination([[1.0, 2.0]], [1.0])
    with pytest.raises(ValueError, match="finite"):
        gaussian_elimination([[np.nan]], [1.0])


def test_jacobi_converges_to_gaussian_solution():
    matrix = np.array([[4.0, 1.0], [2.0, 3.0]])
    vector = np.array([9.0, 13.0])
    solution, iterations = jacobi(matrix, vector)
    np.testing.assert_allclose(solution, [1.4, 3.4], atol=1e-8)
    assert iterations > 0


def test_jacobi_rejects_invalid_matrix_dimensions():
    with pytest.raises(ValueError):
        jacobi([[1.0, 2.0]], [1.0])


@pytest.mark.parametrize(
    "solver,args",
    [
        (bisection, (lambda x: x * x - 2, 1.0, 2.0)),
        (newton_root, (lambda x: x * x - 2, lambda x: 2 * x, 1.5)),
        (secant, (lambda x: x * x - 2, 1.0, 2.0)),
        (fixed_point, (lambda x: 0.5 * (x + 2 / x), 1.5)),
    ],
)
def test_root_finding_methods_approximate_sqrt_two(solver, args):
    root, iterations = solver(*args)
    assert root == pytest.approx(np.sqrt(2), abs=1e-8)
    assert iterations >= 0


def test_bisection_accepts_endpoint_root_and_rejects_unbracketed_interval():
    assert bisection(lambda x: x - 2, 2, 4)[0] == 2
    with pytest.raises(ValueError, match="bracket"):
        bisection(lambda x: x * x + 1, -1, 1)


def test_trapezoidal_and_simpson_integrate_x_squared():
    x = np.linspace(0.0, 1.0, 5)
    y = x**2
    assert trapezoidal(x, y) == pytest.approx(0.34375)
    assert simpson_one_third(x, y) == pytest.approx(1 / 3)


def test_simpson_rejects_uneven_spacing_and_even_point_count():
    with pytest.raises(ValueError, match="equally spaced"):
        simpson_one_third([0, 1, 3], [0, 1, 9])
    with pytest.raises(ValueError, match="odd number"):
        simpson_one_third([0, 1, 2, 3], [0, 1, 4, 9])


def test_curve_fitting_methods_recover_known_coefficients():
    x = np.array([0.0, 1.0, 2.0, 3.0])
    np.testing.assert_allclose(fit_straight_line(x, 1 + 2 * x), [1, 2], atol=1e-9)
    np.testing.assert_allclose(fit_quadratic(x, 1 + 2 * x - 0.5 * x**2), [1, 2, -0.5], atol=1e-9)
    a, b = fit_exponential(x, np.exp(0.5 + 0.2 * x))
    assert a == pytest.approx(np.exp(0.5))
    assert b == pytest.approx(0.2)


def test_exponential_fit_requires_positive_values():
    with pytest.raises(ValueError, match="positive"):
        fit_exponential([0, 1, 2], [1, 0, 2])


def test_lagrange_and_newton_interpolation_agree():
    x = np.array([0.0, 1.0, 2.0, 3.0])
    y = x**2 + 1
    target = 1.5
    expected = target**2 + 1
    assert lagrange_interpolate(x, y, target) == pytest.approx(expected)
    coefficients = divided_differences(x, y)
    assert newton_divided_eval(x, coefficients, target) == pytest.approx(expected)
    assert newton_forward(x, y, target) == pytest.approx(expected)
    assert newton_backward(x, y, target) == pytest.approx(expected)


def test_interpolation_rejects_duplicate_nodes_and_invalid_lengths():
    with pytest.raises(ValueError, match="distinct"):
        lagrange_interpolate([0, 1, 1], [1, 2, 3], 0.5)
    with pytest.raises(ValueError, match="distinct"):
        divided_differences([0, 1, 1], [1, 2, 3])
    with pytest.raises(ValueError, match="same"):
        newton_divided_eval([0, 1], [1], 0.5)


def test_least_squares_baseline_trains_and_evaluates_on_numeric_features():
    X = np.array([
        [0.0, 0.0],
        [0.2, 0.1],
        [0.1, 0.3],
        [2.0, 2.0],
        [2.2, 1.9],
        [1.8, 2.1],
    ])
    y = np.array([0, 0, 0, 1, 1, 1])
    model = train_numerical_model(X, y)
    scores = predict_numerical_score(model, X)
    metrics = evaluate_numerical_model(model, X, y)

    assert scores.shape == (len(y),)
    assert np.isfinite(scores).all()
    assert ((scores >= 0) & (scores <= 1)).all()
    assert metrics["confusion_matrix"]["tp"] + metrics["confusion_matrix"]["fn"] == 3
    assert metrics["confusion_matrix"]["fp"] + metrics["confusion_matrix"]["tn"] == 3
    assert 0 <= metrics["accuracy"] <= 1
    assert 0 <= metrics["roc_auc_trapezoidal"] <= 1
    assert 0 <= metrics["roc_auc_simpson_1_3"] <= 1
    assert "not a calibrated probability" in metrics["score_note"]
