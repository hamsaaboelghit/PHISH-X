
import numpy as np


def sigmoid(z):
    z = np.clip(z, -500, 500)
    return 1 / (1 + np.exp(-z))


def compute_gradient(X, y, w):
    m = len(y)
    predictions = sigmoid(X @ w)
    return (X.T @ (predictions - y)) / m


def compute_hessian(X, y, w):
    m = len(y)
    predictions = sigmoid(X @ w)

    R = predictions * (1 - predictions)

    return (X.T @ (X * R[:, np.newaxis])) / m


def numerical_hessian(X, y, w, h):
    n = len(w)
    H = np.zeros((n, n))

    for j in range(n):
        w_plus = w.copy()
        w_minus = w.copy()

        w_plus[j] += h
        w_minus[j] -= h

        grad_plus = compute_gradient(X, y, w_plus)
        grad_minus = compute_gradient(X, y, w_minus)

        H[:, j] = (grad_plus - grad_minus) / (2 * h)

    return H


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

step_sizes = [1e-3, 1e-5]

total_tests = 0
passed_tests = 0

print("=" * 75)
print("ANALYTICAL VS NUMERICAL HESSIAN VERIFICATION")
print("=" * 75)

for dataset_name, (X, y) in datasets.items():

    for weight_index, w in enumerate(initial_weights, start=1):

        analytical = compute_hessian(X, y, w)

        for h in step_sizes:

            numerical = numerical_hessian(X, y, w, h)

            difference = np.linalg.norm(analytical - numerical)

            analytical_symmetric = np.allclose(
                analytical, analytical.T, atol=1e-10
            )

            numerical_symmetric = np.allclose(
                numerical, numerical.T, atol=1e-7
            )

            eigenvalues = np.linalg.eigvalsh(analytical)
            psd_check = np.all(eigenvalues >= -1e-9)

            comparison = np.allclose(
                analytical, numerical, atol=1e-5, rtol=1e-4
            )

            passed = (
                analytical_symmetric
                and numerical_symmetric
                and psd_check
                and comparison
            )

            total_tests += 1
            passed_tests += int(passed)

            print(f"\n{dataset_name} | Weights {weight_index} | h = {h}")
            print("Analytical Hessian:")
            print(analytical)
            print("Numerical Hessian:")
            print(numerical)
            print("Hessian Difference:", difference)
            print("Eigenvalues:", eigenvalues)
            print("Analytical Symmetry:", analytical_symmetric)
            print("Numerical Symmetry:", numerical_symmetric)
            print("Positive Semi-Definite:", psd_check)
            print("Comparison:", comparison)
            print("Result:", "PASSED" if passed else "FAILED")

print("\n" + "=" * 75)
print(f"Total Tests: {total_tests}")
print(f"Passed Tests: {passed_tests}")
print(f"Failed Tests: {total_tests - passed_tests}")
print("=" * 75)

assert passed_tests == total_tests, "Some Hessian tests failed!"

print("All Hessian Verification Tests Passed!")
