
from pathlib import Path

import numpy as np
import pandas as pd

from phishx.evaluation.create_dataset_split import extract_host

# ============================================================
# PHISH-X | DATASET LOADER AND VALIDATION
# ============================================================

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


def validate_manifest_hosts(manifest, split_name):
    """
    Ensure manifest hosts match the actual hostnames extracted from URLs.
    """

    expected_hosts = manifest["URL"].apply(extract_host)

    actual_hosts = (
        manifest["host"]
        .astype("string")
        .str.strip()
        .str.lower()
    )

    invalid_hosts = (
        expected_hosts.isna()
        | actual_hosts.isna()
        | actual_hosts.eq("")
        | (expected_hosts != actual_hosts)
    )

    if invalid_hosts.any():
        examples = manifest.loc[
            invalid_hosts, ["URL", "host"]
        ].head(5)

        raise ValueError(
            f"Invalid or mismatched hosts found in {split_name} manifest:\n"
            f"{examples.to_string(index=False)}"
        )


def validate_numeric_features(frame, split_name):
    """
    Ensure all model features are numeric and contain only finite values.
    """

    features = frame[FEATURE_COLUMNS].copy()

    for column in FEATURE_COLUMNS:
        try:
            features[column] = pd.to_numeric(
                features[column],
                errors="raise"
            )
        except (ValueError, TypeError):
            raise ValueError(
                f"Non-numeric values found in feature "
                f"'{column}' in {split_name}."
            ) from None

    values = features.to_numpy(dtype=float)

    if not np.isfinite(values).all():
        invalid_mask = ~np.isfinite(values)

        invalid_columns = [
            FEATURE_COLUMNS[index]
            for index in range(len(FEATURE_COLUMNS))
            if invalid_mask[:, index].any()
        ]

        raise ValueError(
            f"Non-finite values found in {split_name} "
            f"features: {invalid_columns}"
        )

    return features


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
            raise FileNotFoundError(
                f"Required dataset file not found: {path}"
            )

    # Load datasets
    cleaned_df = pd.read_csv(CLEANED_DATA_PATH)
    train_manifest = pd.read_csv(GROUP_TRAIN_PATH)
    test_manifest = pd.read_csv(GROUP_TEST_PATH)

    # Validate required columns
    required_cleaned_columns = ["URL", TARGET_COLUMN] + FEATURE_COLUMNS
    required_manifest_columns = ["URL", "host", TARGET_COLUMN]

    for column in required_cleaned_columns:
        if column not in cleaned_df.columns:
            raise ValueError(
                f"Missing column in cleaned dataset: {column}"
            )

    for column in required_manifest_columns:
        if column not in train_manifest.columns:
            raise ValueError(
                f"Missing column in group train: {column}"
            )

        if column not in test_manifest.columns:
            raise ValueError(
                f"Missing column in group test: {column}"
            )

    # Validate missing and blank URLs
    for name, frame in [
        ("cleaned dataset", cleaned_df),
        ("group train", train_manifest),
        ("group test", test_manifest),
    ]:
        invalid_urls = (
            frame["URL"].isna()
            | frame["URL"].astype("string").str.strip().eq("")
        )

        if invalid_urls.any():
            raise ValueError(
                f"Missing or blank URLs found in {name}."
            )

    # Validate URL uniqueness
    if cleaned_df["URL"].duplicated().any():
        raise ValueError(
            "Duplicate URLs found in cleaned dataset."
        )

    if train_manifest["URL"].duplicated().any():
        raise ValueError(
            "Duplicate URLs found in group train."
        )

    if test_manifest["URL"].duplicated().any():
        raise ValueError(
            "Duplicate URLs found in group test."
        )

    # Ensure train and test do not overlap
    if set(train_manifest["URL"]) & set(test_manifest["URL"]):
        raise ValueError(
            "URL overlap found between group train and group test."
        )

    # Validate manifest hosts against actual URL hostnames
    validate_manifest_hosts(train_manifest, "group train")
    validate_manifest_hosts(test_manifest, "group test")

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
        raise ValueError(
            "Missing feature or target values found in group train."
        )

    if test_df[FEATURE_COLUMNS + [TARGET_COLUMN]].isna().any().any():
        raise ValueError(
            "Missing feature or target values found in group test."
        )

    # Verify labels match the original manifests
    if not (
        train_df[f"{TARGET_COLUMN}_manifest"]
        == train_df[TARGET_COLUMN]
    ).all():
        raise ValueError(
            "Group train labels do not match cleaned dataset."
        )

    if not (
        test_df[f"{TARGET_COLUMN}_manifest"]
        == test_df[TARGET_COLUMN]
    ).all():
        raise ValueError(
            "Group test labels do not match cleaned dataset."
        )

    # Verify host separation
    train_hosts = set(train_manifest["host"].str.strip().str.lower())
    test_hosts = set(test_manifest["host"].str.strip().str.lower())

    if train_hosts & test_hosts:
        raise ValueError(
            "Host overlap found in Group Split."
        )

    # Validate numeric and finite features
    X_train = validate_numeric_features(train_df, "group train")
    X_test = validate_numeric_features(test_df, "group test")

    # Extract labels
    y_train = train_df[TARGET_COLUMN].astype(int).copy()
    y_test = test_df[TARGET_COLUMN].astype(int).copy()

    return X_train, X_test, y_train, y_test
