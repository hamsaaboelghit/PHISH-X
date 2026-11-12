import numpy as np


def binary_cross_entropy(y_true, y_pred):
    epsilon = 1e-15
    y_pred = np.clip(y_pred, epsilon, 1 - epsilon)

    loss = -np.mean(
        y_true * np.log(y_pred)
        + (1 - y_true) * np.log(1 - y_pred)
    )

    return loss
y_true = np.array([1, 0, 1, 0])
y_pred = np.array([0.9, 0.1, 0.8, 0.2])

loss = binary_cross_entropy(y_true, y_pred)

print("Binary Cross-Entropy Loss:", loss)

assert loss >= 0
print("Loss Test Passed!")
better_pred = np.array([0.99, 0.01, 0.95, 0.05])

better_loss = binary_cross_entropy(y_true, better_pred)

print("Original Loss:", loss)
print("Better Loss:", better_loss)

assert better_loss < loss

print("Improvement Test Passed!")
