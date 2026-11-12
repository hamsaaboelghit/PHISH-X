
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


def gradient_descent(
    X, y, initial_w, learning_rate,
    max_iterations=10000, tolerance=1e-6
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

    final_gradient_norm = np.linalg.norm(compute_gradient(X, y, w))

    if final_gradient_norm < tolerance:
        converged = True

    return w, loss_history, iteration, converged, final_gradient_norm


datasets = {
    "Dataset 1": (
        np.array([
            [1.0, 2.0],
            [1.0, 3.0],
            [1.0, 4.0],
            [1.0, 5.0]
        ]),
        np.array([0, 0, 1, 1])
    ),

    "Dataset 2": (
        np.array([
            [1.0, 1.0],
            [1.0, 2.0],
            [1.0, 3.0],
            [1.0, 4.0],
            [1.0, 5.0]
        ]),
        np.array([0, 0, 0, 1, 1])
    ),

    "Dataset 3": (
        np.array([
            [1.0, 0.5],
            [1.0, 1.5],
            [1.0, 2.5],
            [1.0, 3.5],
            [1.0, 4.5],
            [1.0, 5.5]
        ]),
        np.array([0, 0, 0, 1, 1, 1])
    )
}

learning_rates = [0.01, 0.05, 0.1]
initial_w = np.array([0.1, 0.2])

total_tests = 0
passed_tests = 0

print("=" * 75)
print("GRADIENT DESCENT VERIFICATION")
print("=" * 75)

for dataset_name, (X, y) in datasets.items():

    for learning_rate in learning_rates:

        initial_loss = compute_loss(X, y, initial_w)

        final_w, loss_history, iterations, converged, gradient_norm = (
            gradient_descent(
                X, y, initial_w, learning_rate
            )
        )

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

        print(f"\n{dataset_name} | Learning Rate = {learning_rate}")
        print("Initial Loss:", initial_loss)
        print("Final Loss:", final_loss)
        print("Final Weights:", final_w)
        print("Iterations:", iterations)
        print("Final Gradient Norm:", gradient_norm)
        print("Converged:", converged)
        print("Loss Decreased:", loss_decreased)
        print("Loss Stable:", loss_stable)
        print("Finite Values:", finite_weights and finite_loss and finite_gradient)
        print("Result:", "PASSED" if passed else "FAILED")

print("\n" + "=" * 75)
print(f"Total Tests: {total_tests}")
print(f"Passed Tests: {passed_tests}")
print(f"Failed Tests: {total_tests - passed_tests}")
print("=" * 75)

assert passed_tests == total_tests, "Some Gradient Descent tests failed!"

print("All Gradient Descent Tests Passed!")
