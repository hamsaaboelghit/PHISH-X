import numpy as np
import pytest

from phishx.models.logistic_regression import _solve_linear_system


def test_gaussian_elimination_solves_linear_system():
    matrix = np.array([[3.0, 2.0], [1.0, 2.0]])
    vector = np.array([5.0, 5.0])

    solution = _solve_linear_system(matrix, vector)

    np.testing.assert_allclose(matrix @ solution, vector, atol=1e-12)
    np.testing.assert_allclose(solution, [0.0, 2.5], atol=1e-12)


def test_gaussian_elimination_uses_partial_pivoting():
    matrix = np.array([[0.0, 2.0], [1.0, 1.0]])
    expected = np.array([1.0, 2.0])
    vector = matrix @ expected

    solution = _solve_linear_system(matrix, vector)

    np.testing.assert_allclose(solution, expected, atol=1e-12)


def test_gaussian_elimination_rejects_singular_matrix():
    matrix = np.array([[1.0, 2.0], [2.0, 4.0]])
    vector = np.array([3.0, 6.0])

    with pytest.raises(np.linalg.LinAlgError):
        _solve_linear_system(matrix, vector)


def test_gaussian_elimination_rejects_invalid_dimensions():
    with pytest.raises(ValueError):
        _solve_linear_system(np.ones((2, 3)), np.ones(2))

    with pytest.raises(ValueError):
        _solve_linear_system(np.eye(2), np.ones(3))
