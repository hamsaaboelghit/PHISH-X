
import numpy as np


def sigmoid(z):
    z = np.clip(z, -500, 500)
    return 1 / (1 + np.exp(-z))


def compute_hessian(X, y, w):
    m = len(y)

    predictions = sigmoid(X @ w)

    R = predictions * (1 - predictions)

    hessian = (X.T @ (X * R[:, np.newaxis])) / m

    return hessian
X = np.array([
    [1.0, 2.0],
    [1.0, 3.0],
    [1.0, 4.0],
    [1.0, 5.0]
])

y = np.array([0, 0, 1, 1])

w = np.array([0.1, 0.2])

H = compute_hessian(X, y, w)

print("Hessian Matrix:")
print(H)
assert np.allclose(H, H.T, atol=1e-10)
print("Symmetry Test Passed!")

eigenvalues = np.linalg.eigvalsh(H)

print("Eigenvalues:", eigenvalues)

assert np.all(eigenvalues >= -1e-10)
print("Positive Semi-Definite Test Passed!")