
import numpy as np


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


def newton_method(
    X, y, initial_w,
    max_iterations=100,
    tolerance=1e-6
):
    w = initial_w.copy()
    loss_history = [compute_loss(X, y, w)]
    converged = False
    reason = "Maximum iterations reached"
    damping_used = False

    for iteration in range(1, max_iterations + 1):

        gradient = compute_gradient(X, y, w)
        gradient_norm = np.linalg.norm(gradient)

        if gradient_norm < tolerance:
            converged = True
            reason = "Gradient tolerance reached"
            break

        hessian = compute_hessian(X, w)

        # Try solving with increasing damping if needed.
        damping_values = [
            0.0, 1e-8, 1e-6, 1e-4, 1e-2, 1.0
        ]

        direction = None

        for damping in damping_values:
            try:
                regularized_hessian = (
                    hessian + damping * np.eye(len(w))
                )

                candidate = np.linalg.solve(
                    regularized_hessian, gradient
                )

                # Newton direction must be a descent direction.
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
            reason = "Could not find a valid Newton direction"
            break

        # Backtracking line search (Armijo condition).
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
            reason = "Line search could not find a decreasing step"
            break

        w = new_w
        loss_history.append(new_loss)

    final_gradient_norm = np.linalg.norm(
        compute_gradient(X, y, w)
    )

    if final_gradient_norm < tolerance:
        converged = True
        reason = "Gradient tolerance reached"

    return (
        w,
        loss_history,
        iteration,
        converged,
        final_gradient_norm,
        damping_used,
        reason
    )


datasets = {
    "Dataset 1": (
        np.array([
            [1.0, 1.0],
            [1.0, 2.0],
            [1.0, 3.0],
            [1.0, 4.0]
        ]),
        np.array([0, 0, 1, 1]),
        [
            np.zeros(2),
            np.array([0.1, 0.2])
        ]
    ),

    "Dataset 2": (
        np.array([
            [1.0, 1.0],
            [1.0, 2.0],
            [1.0, 3.0],
            [1.0, 4.0],
            [1.0, 5.0]
        ]),
        np.array([0, 0, 0, 1, 1]),
        [
            np.zeros(2),
            np.array([0.1, 0.2])
        ]
    ),

    "Dataset 3 - Singular Hessian": (
        np.array([
            [1.0, 1.0, 1.0],
            [1.0, 2.0, 2.0],
            [1.0, 3.0, 3.0],
            [1.0, 4.0, 4.0]
        ]),
        np.array([0, 0, 1, 1]),
        [
            np.zeros(3),
            np.array([0.1, 0.2, 0.2])
        ]
    )
}


total_tests = 0
passed_tests = 0

print("=" * 75)
print("NEWTON METHOD VERIFICATION")
print("=" * 75)

for dataset_name, (X, y, initial_weights) in datasets.items():

    for weight_index, initial_w in enumerate(initial_weights, start=1):

        initial_loss = compute_loss(X, y, initial_w)

        (
            final_w,
            loss_history,
            iterations,
            converged,
            gradient_norm,
            damping_used,
            reason
        ) = newton_method(X, y, initial_w)

        final_loss = loss_history[-1]

        loss_decreased = final_loss < initial_loss

        loss_stable = all(
            loss_history[i + 1] <= loss_history[i] + 1e-12
            for i in range(len(loss_history) - 1)
        )

        finite_weights = np.all(np.isfinite(final_w))
        finite_loss = np.all(np.isfinite(loss_history))
        finite_gradient = np.isfinite(gradient_norm)

        passed = (
            loss_decreased
            and loss_stable
            and finite_weights
            and finite_loss
            and finite_gradient
        )

        total_tests += 1
        passed_tests += int(passed)

        print(f"\n{dataset_name} | Weights {weight_index}")
        print("Initial Loss:", initial_loss)
        print("Final Loss:", final_loss)
        print("Final Weights:", final_w)
        print("Iterations:", iterations)
        print("Final Gradient Norm:", gradient_norm)
        print("Converged:", converged)
        print("Damping Used:", damping_used)
        print("Loss Decreased:", loss_decreased)
        print("Loss Stable:", loss_stable)
        print("Finite Values:", finite_weights and finite_loss and finite_gradient)
        print("Stopping Reason:", reason)
        print("Result:", "PASSED" if passed else "FAILED")

print("\n" + "=" * 75)
print(f"Total Tests: {total_tests}")
print(f"Passed Tests: {passed_tests}")
print(f"Failed Tests: {total_tests - passed_tests}")
print("=" * 75)

assert passed_tests == total_tests, "Some Newton Method tests failed!"

print("All Newton Method Tests Passed!")
