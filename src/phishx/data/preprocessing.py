
import numpy as np
from sklearn.preprocessing import StandardScaler

from phishx.data.dataset import load_group_split


def prepare_group_data():
    """
    Load Group Split and apply feature scaling.

    The scaler is fitted on training data only
    to prevent data leakage.
    """

    # Load original Group Split
    X_train, X_test, y_train, y_test = load_group_split()

    # Initialize scaler
    scaler = StandardScaler()

    # Fit on training data only
    X_train_scaled = scaler.fit_transform(X_train)

    # Apply the same transformation to test data
    X_test_scaled = scaler.transform(X_test)

    # Convert labels to NumPy arrays
    y_train = y_train.to_numpy(dtype=int)
    y_test = y_test.to_numpy(dtype=int)

    # Validate scaled data
    if not np.isfinite(X_train_scaled).all():
        raise ValueError("Invalid values found in scaled training data.")

    if not np.isfinite(X_test_scaled).all():
        raise ValueError("Invalid values found in scaled test data.")

    return (
        X_train_scaled,
        X_test_scaled,
        y_train,
        y_test,
        scaler,
    )
