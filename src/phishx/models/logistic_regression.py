
import numpy as np


def _validate_binary_vector(values, name):
    """Validate and normalize a binary target/probability vector."""

    try:
        values = np.asarray(values, dtype=float)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must contain numeric values.") from exc

    if values.ndim == 2 and values.shape[1] == 1:
        values = values.ravel()

    if values.ndim != 1:
        raise ValueError(f"{name} must be a 1D array.")

    if values.size == 0:
        raise ValueError(f"{name} cannot be empty.")

    if not np.isfinite(values).all():
        raise ValueError(f"{name} must contain only finite values.")

    return values


def _validate_l2(l2):
    """Validate L2 regularization strength."""

    if isinstance(l2, (bool, np.bool_)):
        raise ValueError("l2 must be a non-negative finite number.")

    if not np.isscalar(l2):
        raise ValueError("l2 must be a scalar.")

    try:
        l2 = float(l2)
    except (TypeError, ValueError) as exc:
        raise ValueError("l2 must be numeric.") from exc

    if not np.isfinite(l2) or l2 < 0:
        raise ValueError("l2 must be non-negative and finite.")

    return l2


def _validate_training_data(X, y):
    """Validate feature matrix and binary target vector."""

    try:
        X = np.asarray(X, dtype=float)
    except (TypeError, ValueError) as exc:
        raise ValueError("X must contain numeric values.") from exc

    y = _validate_binary_vector(y, "y")

    if X.ndim != 2:
        raise ValueError("X must be a 2D array.")

    if X.shape[0] == 0 or X.shape[1] == 0:
        raise ValueError("X cannot be empty.")

    if not np.isfinite(X).all():
        raise ValueError("X must contain only finite values.")

    if X.shape[0] != len(y):
        raise ValueError("X and y must have the same number of samples.")

    if not np.isin(y, [0, 1]).all():
        raise ValueError("y must contain only binary labels (0 and 1).")

    return X, y


def sigmoid(z):
    """Calculate sigmoid probabilities safely."""

    try:
        z = np.asarray(z, dtype=float)
    except (TypeError, ValueError) as exc:
        raise ValueError("z must contain numeric values.") from exc

    if not np.isfinite(z).all():
        raise ValueError("z must contain only finite values.")

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

    y_true = _validate_binary_vector(y_true, "y_true")
    y_pred = _validate_binary_vector(y_pred, "y_pred")

    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have the same length.")

    if not np.isin(y_true, [0, 1]).all():
        raise ValueError("y_true must contain only 0 and 1.")

    if np.any((y_pred < 0) | (y_pred > 1)):
        raise ValueError("y_pred must contain probabilities between 0 and 1.")

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


def training_loss(y_true, y_pred, weights, l2=0.0):
    """Calculate BCE + L2 regularization penalty."""

    l2 = _validate_l2(l2)

    weights = np.asarray(weights, dtype=float)

    if weights.ndim != 1 or weights.size == 0:
        raise ValueError("weights must be a non-empty 1D array.")

    if not np.isfinite(weights).all():
        raise ValueError("weights must contain only finite values.")

    y_true = _validate_binary_vector(y_true, "y_true")

    n_samples = len(y_true)

    loss = binary_cross_entropy(y_true, y_pred)

    regularization = (
        l2 / (2 * n_samples)
    ) * np.sum(weights ** 2)

    return loss + regularization


def compute_gradient(X, y, weights, bias, l2=0.0):
    """Calculate gradients for weights and bias."""

    X, y = _validate_training_data(X, y)
    l2 = _validate_l2(l2)

    weights = np.asarray(weights, dtype=float)

    if weights.ndim != 1 or len(weights) != X.shape[1]:
        raise ValueError("weights must match the number of features.")

    if not np.isfinite(weights).all():
        raise ValueError("weights must contain only finite values.")

    if isinstance(bias, (bool, np.bool_)):
        raise ValueError("bias must be a finite scalar.")

    try:
        bias = float(bias)
    except (TypeError, ValueError) as exc:
        raise ValueError("bias must be a finite scalar.") from exc

    if not np.isfinite(bias):
        raise ValueError("bias must be finite.")

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

    # Bias gradient (bias is not regularized)
    db = np.mean(errors)

    return dw, db


def gradient_descent(
    X,
    y,
    learning_rate=0.01,
    n_iterations=1000,
    l2=0.0,
    tolerance=1e-6,
    loss_tolerance=1e-12,
):
    """
    Train Logistic Regression using Batch Gradient Descent.

    Stops when the gradient norm or loss improvement
    reaches the specified tolerance.
    """

    X, y = _validate_training_data(X, y)
    l2 = _validate_l2(l2)

    if isinstance(learning_rate, (bool, np.bool_)):
        raise ValueError("learning_rate must be positive and finite.")

    try:
        learning_rate = float(learning_rate)
    except (TypeError, ValueError) as exc:
        raise ValueError("learning_rate must be numeric.") from exc

    if not np.isfinite(learning_rate) or learning_rate <= 0:
        raise ValueError("learning_rate must be positive and finite.")

    if (
        isinstance(n_iterations, (bool, np.bool_))
        or not isinstance(n_iterations, (int, np.integer))
        or n_iterations <= 0
    ):
        raise ValueError("n_iterations must be a positive integer.")

    for name, value in [
        ("tolerance", tolerance),
        ("loss_tolerance", loss_tolerance),
    ]:
        if isinstance(value, (bool, np.bool_)):
            raise ValueError(f"{name} must be finite and non-negative.")

        try:
            value = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be numeric.") from exc

        if not np.isfinite(value) or value < 0:
            raise ValueError(f"{name} must be finite and non-negative.")

        if name == "tolerance":
            tolerance = value
        else:
            loss_tolerance = value

    if tolerance == 0:
        raise ValueError("tolerance must be greater than zero.")

    n_samples, n_features = X.shape

    # Initialize parameters
    weights = np.zeros(n_features)
    bias = 0.0

    # Record initial loss before any parameter updates
    probabilities = sigmoid(X @ weights + bias)

    previous_loss = training_loss(
        y, probabilities, weights, l2
    )

    loss_history = [previous_loss]

    for iteration in range(n_iterations):

        dw, db = compute_gradient(
            X, y, weights, bias, l2
        )

        gradient = np.append(dw, db)

        # Stop if the gradient is sufficiently small
        if np.linalg.norm(gradient) <= tolerance:
            break

        # Update parameters
        weights -= learning_rate * dw
        bias -= learning_rate * db

        # Calculate updated predictions
        probabilities = sigmoid(X @ weights + bias)

        # Calculate updated regularized training loss
        current_loss = training_loss(
            y, probabilities, weights, l2
        )

        loss_history.append(current_loss)

        # Stop if loss improvement is sufficiently small
        loss_improvement = previous_loss - current_loss

        if 0 <= loss_improvement <= loss_tolerance:
            break

        previous_loss = current_loss

    return weights, bias, loss_history


def compute_hessian(X, weights, bias, l2=0.0):
    """Calculate the Hessian matrix for Logistic Regression."""

    try:
        X = np.asarray(X, dtype=float)
        weights = np.asarray(weights, dtype=float)
    except (TypeError, ValueError) as exc:
        raise ValueError("X and weights must contain numeric values.") from exc

    l2 = _validate_l2(l2)

    if X.ndim != 2 or X.shape[0] == 0 or X.shape[1] == 0:
        raise ValueError("X must be a non-empty 2D array.")

    if not np.isfinite(X).all():
        raise ValueError("X must contain only finite values.")

    if weights.ndim != 1 or len(weights) != X.shape[1]:
        raise ValueError("weights must match the number of features.")

    if not np.isfinite(weights).all():
        raise ValueError("weights must contain only finite values.")

    if isinstance(bias, (bool, np.bool_)):
        raise ValueError("bias must be a finite scalar.")

    try:
        bias = float(bias)
    except (TypeError, ValueError) as exc:
        raise ValueError("bias must be a finite scalar.") from exc

    if not np.isfinite(bias):
        raise ValueError("bias must be finite.")

    n_samples, n_features = X.shape

    probabilities = sigmoid(X @ weights + bias)

    # Calculate p * (1 - p) for each sample
    sample_weights = probabilities * (1 - probabilities)

    # Add a bias column to the feature matrix
    X_with_bias = np.column_stack(
        (X, np.ones(n_samples))
    )

    # Calculate Hessian
    weighted_X = X_with_bias * sample_weights[:, np.newaxis]

    hessian = (
        X_with_bias.T @ weighted_X
    ) / n_samples

    # Add L2 regularization to feature weights only
    regularization_matrix = np.zeros(
        (n_features + 1, n_features + 1)
    )

    regularization_matrix[:n_features, :n_features] = (
        l2 / n_samples
    ) * np.eye(n_features)

    hessian += regularization_matrix

    return hessian


def newton_method(
    X,
    y,
    n_iterations=100,
    l2=0.0,
    damping=1e-8,
    tolerance=1e-6,
    loss_tolerance=1e-12,
):
    """
    Train Logistic Regression using Newton's Method.

    Stops when the gradient norm, parameter step norm,
    or loss improvement reaches the specified tolerance.
    """

    X, y = _validate_training_data(X, y)
    l2 = _validate_l2(l2)

    if (
        isinstance(n_iterations, (bool, np.bool_))
        or not isinstance(n_iterations, (int, np.integer))
        or n_iterations <= 0
    ):
        raise ValueError("n_iterations must be a positive integer.")

    for name, value in [
        ("damping", damping),
        ("tolerance", tolerance),
        ("loss_tolerance", loss_tolerance),
    ]:
        if isinstance(value, (bool, np.bool_)):
            raise ValueError(f"{name} must be finite and non-negative.")

        try:
            value = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be numeric.") from exc

        if not np.isfinite(value) or value < 0:
            raise ValueError(f"{name} must be finite and non-negative.")

        if name == "damping":
            damping = value
        elif name == "tolerance":
            tolerance = value
        else:
            loss_tolerance = value

    if damping == 0:
        raise ValueError("damping must be greater than zero.")

    if tolerance == 0:
        raise ValueError("tolerance must be greater than zero.")

    n_samples, n_features = X.shape

    # Initialize parameters
    weights = np.zeros(n_features)
    bias = 0.0

    # Record initial loss
    probabilities = sigmoid(X @ weights + bias)

    previous_loss = training_loss(
        y, probabilities, weights, l2
    )

    loss_history = [previous_loss]

    for iteration in range(n_iterations):

        dw, db = compute_gradient(
            X, y, weights, bias, l2
        )

        gradient = np.append(dw, db)

        # Stop if the gradient is sufficiently small
        if np.linalg.norm(gradient) <= tolerance:
            break

        hessian = compute_hessian(
            X, weights, bias, l2
        )

        # Damping improves numerical stability
        hessian += damping * np.eye(n_features + 1)

        try:
            direction = np.linalg.solve(hessian, gradient)
        except np.linalg.LinAlgError:
            direction = np.linalg.pinv(hessian) @ gradient

        if not np.isfinite(direction).all():
            raise ValueError("Newton direction contains non-finite values.")

        # Backtracking line search
        step_size = 1.0
        accepted = False

        parameters = np.append(weights, bias)

        for _ in range(30):

            candidate = parameters - step_size * direction

            candidate_weights = candidate[:-1]
            candidate_bias = candidate[-1]

            candidate_probabilities = sigmoid(
                X @ candidate_weights + candidate_bias
            )

            candidate_loss = training_loss(
                y,
                candidate_probabilities,
                candidate_weights,
                l2,
            )

            if candidate_loss < previous_loss:
                accepted = True
                break

            step_size *= 0.5

        # Stop if no improving step can be found
        if not accepted:
            break

        weights = candidate_weights
        bias = candidate_bias

        # Record loss after the accepted update
        loss_history.append(candidate_loss)

        # Stop if loss improvement is sufficiently small
        loss_improvement = previous_loss - candidate_loss

        if loss_improvement <= loss_tolerance:
            break

        # Stop if parameter update is sufficiently small
        if np.linalg.norm(step_size * direction) <= tolerance:
            break

        previous_loss = candidate_loss

    return weights, bias, loss_history

def predict_proba(X, weights, bias):
    """Return the probability of the positive class (label 1)."""
    X = np.asarray(X, dtype=float)
    weights = np.asarray(weights, dtype=float)

    if X.ndim != 2 or X.shape[0] == 0:
        raise ValueError("X must be a non-empty 2D array.")

    if weights.ndim != 1 or weights.shape[0] != X.shape[1]:
        raise ValueError("weights must match the number of features.")

    if not np.isfinite(X).all():
        raise ValueError("X must contain only finite values.")

    if not np.isfinite(weights).all() or not np.isfinite(bias):
        raise ValueError("Model parameters must be finite.")

    return sigmoid(X @ weights + bias)


def predict(X, weights, bias, threshold=0.5):
    """Predict binary labels using a configurable threshold."""
    if (
        isinstance(threshold, (bool, np.bool_))
        or not isinstance(threshold, (int, float, np.integer, np.floating))
        or not np.isfinite(threshold)
        or not 0 <= threshold <= 1
    ):
        raise ValueError("threshold must be a finite number between 0 and 1.")

    probabilities = predict_proba(X, weights, bias)
    return (probabilities >= threshold).astype(int)
