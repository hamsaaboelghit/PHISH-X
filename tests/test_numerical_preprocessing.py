import numpy as np
import pytest

from phishx.data.preprocessing import NumericalStandardScaler


def test_numerical_scaler_matches_population_standardization():
    X = np.array([[1.0, 10.0], [3.0, 10.0], [5.0, 10.0]])
    scaler = NumericalStandardScaler()
    transformed = scaler.fit_transform(X)

    np.testing.assert_allclose(scaler.mean_, [3.0, 10.0])
    np.testing.assert_allclose(scaler.var_, [8.0 / 3.0, 0.0])
    np.testing.assert_allclose(transformed[:, 0], [-np.sqrt(1.5), 0.0, np.sqrt(1.5)])
    np.testing.assert_allclose(transformed[:, 1], [0.0, 0.0, 0.0])
    np.testing.assert_allclose(np.mean(transformed, axis=0), [0.0, 0.0], atol=1e-12)


def test_numerical_scaler_transform_reuses_training_statistics():
    train = np.array([[1.0, 2.0], [3.0, 4.0]])
    test = np.array([[5.0, 6.0]])
    scaler = NumericalStandardScaler().fit(train)

    transformed = scaler.transform(test)

    np.testing.assert_allclose(transformed, [[3.0, 3.0]])


def test_numerical_scaler_requires_fit_before_transform():
    with pytest.raises(RuntimeError):
        NumericalStandardScaler().transform(np.array([[1.0]]))


@pytest.mark.parametrize(
    "values",
    [
        np.array([1.0, 2.0]),
        np.empty((0, 2)),
        np.array([[1.0, np.nan]]),
        np.array([[1.0, np.inf]]),
    ],
)
def test_numerical_scaler_rejects_invalid_input(values):
    with pytest.raises(ValueError):
        NumericalStandardScaler().fit(values)


def test_numerical_scaler_rejects_feature_count_mismatch():
    scaler = NumericalStandardScaler().fit(np.array([[1.0, 2.0], [3.0, 4.0]]))
    with pytest.raises(ValueError):
        scaler.transform(np.array([[1.0, 2.0, 3.0]]))
