import numpy as np


def sigmoid(z):
    z = np.clip(z, -500, 500)
    return 1 / (1 + np.exp(-z))
test_values = np.array([-2, 0, 2])

results = sigmoid(test_values)

print("Input:", test_values)
print("Sigmoid Output:", results)
assert np.all(results >= 0) and np.all(results <= 1)

print("Test Passed: All sigmoid outputs are between 0 and 1.")
large_values = np.array([-1000, 1000])

large_results = sigmoid(large_values)

print("Large Inputs:", large_values)
print("Large Outputs:", large_results)

assert np.all(np.isfinite(large_results))

print("Stability Test Passed!")