
import numpy as np


def sigmoid(z):
    """Calculate sigmoid probabilities safely."""

    z = np.asarray(z, dtype=float)
    probabilities = np.empty_like(z)

    positive_mask = z >= 0

    probabilities[positive_mask] = (
        1 / (1 + np.exp(-z[positive_mask]))
    )

    exp_z = np.exp(z[~positive_mask])

    probabilities[~positive_mask] = (
        exp_z / (1 + exp_z)
    )

    return probabilities


def binary_cross_entropy(y_true, y_pred):
    """Calculate Binary Cross-Entropy Loss."""

    epsilon = 1e-15

    y_pred = np.clip(
        y_pred,
        epsilon,
        1 - epsilon
    )

    loss = -np.mean(
        y_true * np.log(y_pred)
        + (1 - y_true) * np.log(1 - y_pred)
    )

    return loss


def compute_gradient(X, y, weights, bias, l2=0.0):
    """Calculate gradients for weights and bias."""

    n_samples = X.shape[0]

    # Forward propagation
    z = np.dot(X, weights) + bias
    probabilities = sigmoid(z)

    # Calculate errors
    errors = probabilities - y

    # Weight gradients
    dw = np.dot(X.T, errors) / n_samples

    # L2 regularization
    dw += (l2 / n_samples) * weights

    # Bias gradient
    db = np.mean(errors)

    return dw, db


def gradient_descent(
    X,
    y,
    learning_rate=0.01,
    n_iterations=1000,
    l2=0.0,
):
    """Train Logistic Regression using Batch Gradient Descent."""

    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=float)

    n_samples, n_features = X.shape

    # Initialize parameters
    weights = np.zeros(n_features)
    bias = 0.0

    # Store loss at each iteration
    loss_history = []

    for iteration in range(n_iterations):

        dw, db = compute_gradient(
            X, y, weights, bias, l2
        )

        # Update parameters
        weights -= learning_rate * dw
        bias -= learning_rate * db

        # Calculate updated predictions
        probabilities = sigmoid(
            np.dot(X, weights) + bias
        )

        # Calculate loss
        loss = binary_cross_entropy(y, probabilities)
        loss_history.append(loss)

    return weights, bias, loss_history
