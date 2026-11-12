
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


def numerical_gradient(X, y, w, h):
    grad = np.zeros_like(w, dtype=float)

    for i in range(len(w)):
        w_plus = w.copy()
        w_minus = w.copy()

        w_plus[i] += h
        w_minus[i] -= h

        loss_plus = compute_loss(X, y, w_plus)
        loss_minus = compute_loss(X, y, w_minus)

        grad[i] = (loss_plus - loss_minus) / (2 * h)

    return grad


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

initial_weights = [
    np.array([0.0, 0.0]),
    np.array([0.1, 0.2]),
    np.array([-0.5, 0.3])
]

step_sizes = [1e-3, 1e-5, 1e-7]

total_tests = 0
passed_tests = 0

print("=" * 75)
print("ANALYTICAL VS NUMERICAL GRADIENT VERIFICATION")
print("=" * 75)

for dataset_name, (X, y) in datasets.items():

    for weight_index, w in enumerate(initial_weights, start=1):

        analytical = compute_gradient(X, y, w)

        for h in step_sizes:

            numerical = numerical_gradient(X, y, w, h)

            difference = np.linalg.norm(analytical - numerical)

            passed = np.allclose(
                analytical, numerical, atol=1e-5, rtol=1e-4
            )

            total_tests += 1
            passed_tests += int(passed)

            print(f"\n{dataset_name} | Weights {weight_index} | h = {h}")
            print("Analytical Gradient:", analytical)
            print("Numerical Gradient: ", numerical)
            print("Gradient Difference:", difference)
            print("Result:", "PASSED" if passed else "FAILED")

print("\n" + "=" * 75)
print(f"Total Tests: {total_tests}")
print(f"Passed Tests: {passed_tests}")
print(f"Failed Tests: {total_tests - passed_tests}")
print("=" * 75)

assert passed_tests == total_tests, "Some gradient tests failed!"

print("All Gradient Verification Tests Passed!")
