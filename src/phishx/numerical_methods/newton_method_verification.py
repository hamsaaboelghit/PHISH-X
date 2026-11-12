import numpy as np


def sigmoid(z):
    z = np.clip(z, -500, 500)
    return 1 / (1 + np.exp(-z))


def compute_loss(X, y, w):
    m = len(y)
    predictions = sigmoid(X @ w)

    epsilon = 1e-15
    predictions = np.clip(predictions, epsilon, 1 - epsilon)

    return -np.mean(
        y * np.log(predictions)
        + (1 - y) * np.log(1 - predictions)
    )


def compute_gradient(X, y, w):
    m = len(y)
    predictions = sigmoid(X @ w)

    return (X.T @ (predictions - y)) / m


def compute_hessian(X, w):
    m = len(X)
    predictions = sigmoid(X @ w)

    R = predictions * (1 - predictions)

    return (X.T @ (X * R[:, np.newaxis])) / m


def newton_method(X, y, w, iterations=100):
    loss_history = []

    for _ in range(iterations):
        gradient = compute_gradient(X, y, w)
        hessian = compute_hessian(X, w)

        delta = np.linalg.solve(hessian, gradient)

        w = w - delta
        loss_history.append(compute_loss(X, y, w))

    return w, loss_history
X = np.array([
    [1.0, 1.0],
    [1.0, 2.0],
    [1.0, 3.0],
    [1.0, 4.0]
])

y = np.array([0, 0, 1, 1])

initial_w = np.zeros(2)

initial_loss = compute_loss(X, y, initial_w)

final_w, loss_history = newton_method(
    X, y, initial_w, iterations=10
)

final_loss = compute_loss(X, y, final_w)

print("Initial Loss:", initial_loss)
print("Final Loss:", final_loss)
print("Final Weights:", final_w)
assert final_loss < initial_loss
assert np.all(np.isfinite(final_w))

print("Newton's Method Test Passed!")
