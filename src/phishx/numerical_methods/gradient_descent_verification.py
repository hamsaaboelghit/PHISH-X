
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

    return (X.T @ (predictions - y)) / m


def gradient_descent(X, y, w, learning_rate, iterations):
    loss_history = []

    for _ in range(iterations):
        gradient = compute_gradient(X, y, w)
        w = w - learning_rate * gradient
        loss_history.append(compute_loss(X, y, w))

    return w, loss_history
X = np.array([
    [1.0, 2.0],
    [1.0, 3.0],
    [1.0, 4.0],
    [1.0, 5.0]
])

y = np.array([0, 0, 1, 1])

initial_w = np.array([0.1, 0.2])

initial_loss = compute_loss(X, y, initial_w)

final_w, loss_history = gradient_descent(
    X, y, initial_w, learning_rate=0.1, iterations=1000
)

final_loss = compute_loss(X, y, final_w)

print("Initial Loss:", initial_loss)
print("Final Loss:", final_loss)
print("Final Weights:", final_w)
assert final_loss < initial_loss
assert np.all(np.isfinite(final_w))

print("Gradient Descent Test Passed!")