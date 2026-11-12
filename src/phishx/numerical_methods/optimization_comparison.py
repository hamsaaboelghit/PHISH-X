
import numpy as np
import time


def sigmoid(z):
    z = np.clip(z, -500, 500)
    return 1 / (1 + np.exp(-z))


def compute_loss(X, y, w):
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


def gradient_descent(
    X, y, initial_w,
    learning_rate=0.1,
    max_iterations=10000,
    tolerance=1e-6
):
    w = initial_w.copy()
    loss_history = [compute_loss(X, y, w)]
    converged = False

    for iteration in range(1, max_iterations + 1):
        gradient = compute_gradient(X, y, w)
        gradient_norm = np.linalg.norm(gradient)

        if gradient_norm < tolerance:
            converged = True
            break

        new_w = w - learning_rate * gradient

        if not np.all(np.isfinite(new_w)):
            break

        new_loss = compute_loss(X, y, new_w)

        if not np.isfinite(new_loss):
            break

        w = new_w
        loss_history.append(new_loss)

    gradient_norm = np.linalg.norm(compute_gradient(X, y, w))

    if gradient_norm < tolerance:
        converged = True

    return w, loss_history, iteration, converged, gradient_norm


def newton_method(
    X, y, initial_w,
    max_iterations=100,
    tolerance=1e-6
):
    w = initial_w.copy()
    loss_history = [compute_loss(X, y, w)]
    converged = False
    damping_used = False

    for iteration in range(1, max_iterations + 1):
        gradient = compute_gradient(X, y, w)
        gradient_norm = np.linalg.norm(gradient)

        if gradient_norm < tolerance:
            converged = True
            break

        hessian = compute_hessian(X, w)
        direction = None

        for damping in [0.0, 1e-8, 1e-6, 1e-4, 1e-2, 1.0]:
            try:
                regularized_hessian = (
                    hessian + damping * np.eye(len(w))
                )

                candidate = np.linalg.solve(
                    regularized_hessian, gradient
                )

                if (
                    np.all(np.isfinite(candidate))
                    and np.dot(gradient, candidate) > 0
                ):
                    direction = candidate

                    if damping > 0:
                        damping_used = True

                    break

            except np.linalg.LinAlgError:
                continue

        if direction is None:
            break

        current_loss = compute_loss(X, y, w)
        step_size = 1.0
        accepted = False

        for _ in range(50):
            new_w = w - step_size * direction

            if np.all(np.isfinite(new_w)):
                new_loss = compute_loss(X, y, new_w)

                if (
                    np.isfinite(new_loss)
                    and new_loss <= current_loss
                    - 1e-4 * step_size * np.dot(gradient, direction)
                ):
                    accepted = True
                    break

            step_size *= 0.5

        if not accepted:
            break

        w = new_w
        loss_history.append(new_loss)

    gradient_norm = np.linalg.norm(compute_gradient(X, y, w))

    if gradient_norm < tolerance:
        converged = True

    return (
        w, loss_history, iteration,
        converged, gradient_norm, damping_used
    )


# Same dataset and initial weights for both methods.
X = np.array([
    [1.0, 1.0],
    [1.0, 2.0],
    [1.0, 3.0],
    [1.0, 4.0]
])

y = np.array([0, 0, 1, 1])
initial_w = np.zeros(2)

tolerance = 1e-6

print("=" * 75)
print("GRADIENT DESCENT VS NEWTON METHOD")
print("=" * 75)

initial_loss = compute_loss(X, y, initial_w)

# Gradient Descent
start_time = time.perf_counter()

gd_w, gd_losses, gd_iterations, gd_converged, gd_gradient = (
    gradient_descent(
        X, y, initial_w,
        learning_rate=0.1,
        max_iterations=10000,
        tolerance=tolerance
    )
)

gd_time = time.perf_counter() - start_time

# Newton Method
start_time = time.perf_counter()

(
    newton_w,
    newton_losses,
    newton_iterations,
    newton_converged,
    newton_gradient,
    newton_damping
) = newton_method(
    X, y, initial_w,
    max_iterations=100,
    tolerance=tolerance
)

newton_time = time.perf_counter() - start_time

# Results
print("\nInitial Loss:", initial_loss)

print("\n--- Gradient Descent ---")
print("Final Loss:", gd_losses[-1])
print("Final Weights:", gd_w)
print("Iterations:", gd_iterations)
print("Runtime (seconds):", gd_time)
print("Final Gradient Norm:", gd_gradient)
print("Converged:", gd_converged)

print("\n--- Newton Method ---")
print("Final Loss:", newton_losses[-1])
print("Final Weights:", newton_w)
print("Iterations:", newton_iterations)
print("Runtime (seconds):", newton_time)
print("Final Gradient Norm:", newton_gradient)
print("Converged:", newton_converged)
print("Damping Used:", newton_damping)

# Fairness and stability checks
assert np.array_equal(initial_w, np.zeros(2))
assert np.isfinite(gd_losses[-1])
assert np.isfinite(newton_losses[-1])
assert np.all(np.isfinite(gd_w))
assert np.all(np.isfinite(newton_w))

assert all(
    gd_losses[i + 1] <= gd_losses[i] + 1e-12
    for i in range(len(gd_losses) - 1)
)

assert all(
    newton_losses[i + 1] <= newton_losses[i] + 1e-12
    for i in range(len(newton_losses) - 1)
)

assert gd_losses[-1] < initial_loss
assert newton_losses[-1] < initial_loss

print("\n" + "=" * 75)
print("COMPARISON VERIFICATION PASSED")
print("=" * 75)
