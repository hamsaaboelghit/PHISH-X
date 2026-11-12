import numpy as np


def sigmoid(z):
    z = np.clip(z, -500, 500)
    return 1 / (1 + np.exp(-z))


def compute_loss(X, y, w):
    m = len(y)
    predictions = sigmoid(X @ w)

    epsilon = 1e-15
    predictions = np.clip(predictions, epsilon, 1 - epsilon)

    loss = -np.mean(
        y * np.log(predictions)
        + (1 - y) * np.log(1 - predictions)
    )

    return loss


def compute_gradient(X, y, w):
    m = len(y)
    predictions = sigmoid(X @ w)

    gradient = (X.T @ (predictions - y)) / m

    return gradient
def numerical_gradient(X, y, w, h=1e-5):
    grad = np.zeros_like(w)

    for i in range(len(w)):
        w_plus = w.copy()
        w_minus = w.copy()

        w_plus[i] += h
        w_minus[i] -= h

        loss_plus = compute_loss(X, y, w_plus)
        loss_minus = compute_loss(X, y, w_minus)

        grad[i] = (loss_plus - loss_minus) / (2 * h)

    return grad
X = np.array([
    [1.0, 2.0],
    [1.0, 3.0],
    [1.0, 4.0],
    [1.0, 5.0]
])

y = np.array([0, 0, 1, 1])

w = np.array([0.1, 0.2])

analytical = compute_gradient(X, y, w)
numerical = numerical_gradient(X, y, w)

print("Analytical Gradient:", analytical)
print("Numerical Gradient:", numerical)
difference = np.linalg.norm(analytical - numerical)

print("Gradient Difference:", difference)

assert np.allclose(analytical, numerical, atol=1e-5)

print("Gradient Verification Passed!")