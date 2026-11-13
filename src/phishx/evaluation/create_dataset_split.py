
from pathlib import Path
import json
from urllib.parse import urlsplit

import pandas as pd
from sklearn.model_selection import train_test_split, GroupShuffleSplit


# ============================================================
# PHISH-X | REPRODUCIBLE DATASET SPLITTING
# ============================================================

ROOT = Path(__file__).resolve().parents[3]

DATA_PATH = ROOT / "data" / "processed" / "cleaned_dataset.csv"
OUTPUT_DIR = ROOT / "data" / "processed" / "splits"

RANDOM_STATE = 42
TEST_SIZE = 0.20


def extract_host(url):
    """Extract a normalized hostname from a URL."""

    if not isinstance(url, str):
        return None

    value = url.strip()

    if not value or value.lower() in {"none", "nan", "null"}:
        return None

    if "://" not in value:
        value = "//" + value

    try:
        parsed = urlsplit(value)
        host = parsed.hostname

        if not host:
            return None

        host = host.lower()

        if "." not in host and host != "localhost":
            return None

        return host

    except (ValueError, AttributeError):
        return None


def print_split_summary(name, train_df, test_df):

    train_hosts = set(train_df["host"])
    test_hosts = set(test_df["host"])

    overlap = train_hosts.intersection(test_hosts)

    print(f"\n[{name}]")
    print("-" * 55)

    print(f"Training records: {len(train_df):,}")
    print(f"Testing records:  {len(test_df):,}")

    print(f"Training unique hosts: {len(train_hosts):,}")
    print(f"Testing unique hosts:  {len(test_hosts):,}")

    print(f"Shared hosts: {len(overlap):,}")

    print("\nTraining class distribution:")
    print(
        train_df["ClassLabel"]
        .map({0: "Phishing", 1: "Legitimate"})
        .value_counts()
    )

    print("\nTesting class distribution:")
    print(
        test_df["ClassLabel"]
        .map({0: "Phishing", 1: "Legitimate"})
        .value_counts()
    )

    return len(overlap)


def save_split(name, train_df, test_df):

    train_path = OUTPUT_DIR / f"{name}_train.csv"
    test_path = OUTPUT_DIR / f"{name}_test.csv"

    train_df.to_csv(train_path, index=False)
    test_df.to_csv(test_path, index=False)

    print(f"\nSaved training file: {train_path}")
    print(f"Saved testing file:  {test_path}")


def main():

    print("=" * 65)
    print("PHISH-X | REPRODUCIBLE DATASET SPLITTING")
    print("=" * 65)

    # --------------------------------------------------------
    # 1. Load cleaned dataset
    # --------------------------------------------------------

    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Cleaned dataset not found: {DATA_PATH}"
        )

    df = pd.read_csv(DATA_PATH)

    print(f"\n[1] Dataset records: {len(df):,}")

    required_columns = {"URL", "ClassLabel"}

    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    df["ClassLabel"] = pd.to_numeric(
        df["ClassLabel"], errors="coerce"
    )

    if df["ClassLabel"].isna().any():
        raise ValueError("Missing labels detected.")

    df["ClassLabel"] = df["ClassLabel"].astype(int)

    if not df["ClassLabel"].isin([0, 1]).all():
        raise ValueError("Unexpected class labels detected.")

    # --------------------------------------------------------
    # 2. Extract and validate hosts
    # --------------------------------------------------------

    df["host"] = df["URL"].apply(extract_host)

    missing_hosts = int(df["host"].isna().sum())

    print("\n[2] Host extraction")
    print(f"Missing hosts: {missing_hosts:,}")
    print(f"Unique hosts: {df['host'].nunique():,}")

    if missing_hosts > 0:
        raise ValueError(
            "Some URLs have no extractable host. "
            "Resolve them before splitting."
        )

    # --------------------------------------------------------
    # 3. Prepare output directory
    # --------------------------------------------------------

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Keep only the information needed to identify each split.
    # Original dataset features remain untouched.
    manifest = df[["URL", "host", "ClassLabel"]].copy()

    # --------------------------------------------------------
    # 4. Random stratified split
    # --------------------------------------------------------

    random_train, random_test = train_test_split(
        manifest,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=manifest["ClassLabel"]
    )

    random_overlap = print_split_summary(
        "RANDOM STRATIFIED SPLIT",
        random_train,
        random_test
    )

    save_split(
        "random",
        random_train,
        random_test
    )

    # --------------------------------------------------------
    # 5. Group split by host
    # --------------------------------------------------------

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE
    )

    train_indices, test_indices = next(
        splitter.split(
            manifest,
            manifest["ClassLabel"],
            groups=manifest["host"]
        )
    )

    group_train = manifest.iloc[train_indices].copy()
    group_test = manifest.iloc[test_indices].copy()

    group_overlap = print_split_summary(
        "GROUP SPLIT BY HOST",
        group_train,
        group_test
    )

    if group_overlap != 0:
        raise AssertionError(
            "Group split contains shared hosts!"
        )

    save_split(
        "group",
        group_train,
        group_test
    )

    # --------------------------------------------------------
    # 6. Validate saved split logic
    # --------------------------------------------------------

    print("\n[6] Split validation")

    assert len(random_train) + len(random_test) == len(df)
    assert len(group_train) + len(group_test) == len(df)

    assert set(random_train["URL"]).isdisjoint(
        set(random_test["URL"])
    )

    assert set(group_train["URL"]).isdisjoint(
        set(group_test["URL"])
    )

    assert set(group_train["host"]).isdisjoint(
        set(group_test["host"])
    )

    print("Random split URL overlap: 0")
    print("Group split URL overlap: 0")
    print("Group split host overlap: 0")
    print("All records accounted for in both split strategies.")

    # --------------------------------------------------------
    # 7. Save split metadata
    # --------------------------------------------------------

    metadata = {
        "dataset": "cleaned_dataset.csv",
        "total_records": len(df),
        "test_size_requested": TEST_SIZE,
        "random_state": RANDOM_STATE,
        "target_column": "ClassLabel",
        "label_mapping": {
            "0": "Phishing",
            "1": "Legitimate"
        },
        "primary_evaluation_strategy": "Group Split by Host",
        "comparison_strategy": "Random Stratified Split",
        "random_split": {
            "train_records": len(random_train),
            "test_records": len(random_test),
            "shared_hosts": random_overlap
        },
        "group_split": {
            "train_records": len(group_train),
            "test_records": len(group_test),
            "shared_hosts": group_overlap
        }
    }

    metadata_path = OUTPUT_DIR / "split_metadata.json"

    with open(metadata_path, "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=4)

    print(f"\nSaved split metadata: {metadata_path}")

    # --------------------------------------------------------
    # 8. Final report
    # --------------------------------------------------------

    print("\n" + "=" * 65)
    print("DATASET SPLITTING COMPLETED")
    print("=" * 65)

    print(f"Total records: {len(df):,}")
    print(f"Random split test size: {len(random_test):,}")
    print(f"Group split test size: {len(group_test):,}")

    print("\nPrimary strategy: Group Split by Host")
    print("Random split: Comparison only")

    print("\nOriginal and cleaned datasets were not modified.")
    print("Splits are reproducible using the fixed random state.")

    print("=" * 65)


if __name__ == "__main__":
    main()
