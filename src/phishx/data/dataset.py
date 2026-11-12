
from pathlib import Path

import pandas as pd


# Project root directory
PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Dataset paths
CLEANED_DATA_PATH = PROJECT_ROOT / "data" / "processed" / "cleaned_dataset.csv"
GROUP_TRAIN_PATH = PROJECT_ROOT / "data" / "processed" / "splits" / "group_train.csv"
GROUP_TEST_PATH = PROJECT_ROOT / "data" / "processed" / "splits" / "group_test.csv"


# Initial baseline features
FEATURE_COLUMNS = [
    "url_length",
    "number_of_digits",
    "url_entropy",
    "dot_count",
    "path_length",
]


TARGET_COLUMN = "ClassLabel"


def load_group_split():
    """
    Load the cleaned dataset and reconstruct Group Train/Test
    using the original URL-based split manifests.
    """

    # Check that required files exist
    required_paths = [
        CLEANED_DATA_PATH,
        GROUP_TRAIN_PATH,
        GROUP_TEST_PATH,
    ]

    for path in required_paths:
        if not path.exists():
            raise FileNotFoundError(f"Required dataset file not found: {path}")

    # Load datasets
    cleaned_df = pd.read_csv(CLEANED_DATA_PATH)
    train_manifest = pd.read_csv(GROUP_TRAIN_PATH)
    test_manifest = pd.read_csv(GROUP_TEST_PATH)

    # Validate required columns
    required_cleaned_columns = ["URL", TARGET_COLUMN] + FEATURE_COLUMNS
    required_manifest_columns = ["URL", "host", TARGET_COLUMN]

    for column in required_cleaned_columns:
        if column not in cleaned_df.columns:
            raise ValueError(f"Missing column in cleaned dataset: {column}")

    for column in required_manifest_columns:
        if column not in train_manifest.columns:
            raise ValueError(f"Missing column in group train: {column}")

        if column not in test_manifest.columns:
            raise ValueError(f"Missing column in group test: {column}")

    # Validate URL uniqueness
    if cleaned_df["URL"].duplicated().any():
        raise ValueError("Duplicate URLs found in cleaned dataset.")

    if train_manifest["URL"].duplicated().any():
        raise ValueError("Duplicate URLs found in group train.")

    if test_manifest["URL"].duplicated().any():
        raise ValueError("Duplicate URLs found in group test.")

    # Ensure train and test do not overlap
    if set(train_manifest["URL"]) & set(test_manifest["URL"]):
        raise ValueError("URL overlap found between group train and group test.")

    # Reconstruct train and test using URL
    train_df = train_manifest.merge(
        cleaned_df,
        on="URL",
        how="left",
        suffixes=("_manifest", ""),
        validate="one_to_one",
    )

    test_df = test_manifest.merge(
        cleaned_df,
        on="URL",
        how="left",
        suffixes=("_manifest", ""),
        validate="one_to_one",
    )

    # Check missing records after merging
    if train_df[FEATURE_COLUMNS + [TARGET_COLUMN]].isna().any().any():
        raise ValueError("Missing feature or target values found in group train.")

    if test_df[FEATURE_COLUMNS + [TARGET_COLUMN]].isna().any().any():
        raise ValueError("Missing feature or target values found in group test.")

    # Verify labels match the original manifests
    if not (train_df[f"{TARGET_COLUMN}_manifest"] == train_df[TARGET_COLUMN]).all():
        raise ValueError("Group train labels do not match cleaned dataset.")

    if not (test_df[f"{TARGET_COLUMN}_manifest"] == test_df[TARGET_COLUMN]).all():
        raise ValueError("Group test labels do not match cleaned dataset.")

    # Verify host separation
    train_hosts = set(train_manifest["host"].dropna())
    test_hosts = set(test_manifest["host"].dropna())

    if train_hosts & test_hosts:
        raise ValueError("Host overlap found in Group Split.")

    # Extract model inputs and labels
    X_train = train_df[FEATURE_COLUMNS].copy()
    y_train = train_df[TARGET_COLUMN].astype(int).copy()

    X_test = test_df[FEATURE_COLUMNS].copy()
    y_test = test_df[TARGET_COLUMN].astype(int).copy()

    return X_train, X_test, y_train, y_test
