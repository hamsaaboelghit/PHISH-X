
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
from sklearn.model_selection import train_test_split, GroupShuffleSplit


# ============================================================
# PHISH-X | HOST LEAKAGE & SPLIT AUDIT
# ============================================================

ROOT = Path(__file__).resolve().parents[3]
DATA_PATH = ROOT / "data" / "processed" / "cleaned_dataset.csv"


def extract_host(url):

    value = str(url).strip()

    if "://" not in value:
        value = "//" + value

    try:
        return urlsplit(value).hostname.lower()
    except (ValueError, AttributeError):
        return None


def show_class_distribution(name, y):

    counts = y.value_counts().sort_index()

    print(f"\n{name}")
    print(f"Phishing:   {counts.get(0, 0):,}")
    print(f"Legitimate: {counts.get(1, 0):,}")

    print("\nClass percentages:")
    print((y.value_counts(normalize=True).sort_index() * 100).round(2))


def main():

    print("=" * 65)
    print("PHISH-X | HOST LEAKAGE & SPLIT AUDIT")
    print("=" * 65)

    # 1. Load data

    df = pd.read_csv(DATA_PATH)

    print(f"\n[1] Total records: {len(df):,}")

    df["ClassLabel"] = df["ClassLabel"].astype(int)

    # 2. Extract hosts

    df["host"] = df["URL"].apply(extract_host)

    missing_hosts = df["host"].isna().sum()

    print("\n[2] Host extraction")
    print("Missing hosts:", missing_hosts)
    print("Unique hosts:", df["host"].nunique())

    if missing_hosts > 0:
        raise ValueError("Missing hosts detected. Investigate before splitting.")

    X = df.drop(columns=["ClassLabel"])
    y = df["ClassLabel"]
    groups = df["host"]

    # 3. Random stratified split

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    train_hosts = set(X_train["host"])
    test_hosts = set(X_test["host"])

    random_overlap = train_hosts.intersection(test_hosts)

    print("\n[3] Random Stratified Split")
    print("Training records:", len(X_train))
    print("Testing records:", len(X_test))
    print("Training unique hosts:", len(train_hosts))
    print("Testing unique hosts:", len(test_hosts))
    print("Hosts appearing in BOTH sets:", len(random_overlap))

    if random_overlap:
        print("\nTop overlapping hosts:")
        overlap_counts = (
            df[df["host"].isin(random_overlap)]["host"]
            .value_counts()
            .head(10)
        )
        print(overlap_counts)

    show_class_distribution("Random training class distribution", y_train)
    show_class_distribution("Random testing class distribution", y_test)

    # 4. Group split by host

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.20,
        random_state=42
    )

    train_idx, test_idx = next(
        splitter.split(X, y, groups=groups)
    )

    X_group_train = X.iloc[train_idx]
    X_group_test = X.iloc[test_idx]

    y_group_train = y.iloc[train_idx]
    y_group_test = y.iloc[test_idx]

    group_train_hosts = set(X_group_train["host"])
    group_test_hosts = set(X_group_test["host"])

    group_overlap = group_train_hosts.intersection(
        group_test_hosts
    )

    print("\n[4] Group Split by Host")
    print("Training records:", len(X_group_train))
    print("Testing records:", len(X_group_test))
    print("Training unique hosts:", len(group_train_hosts))
    print("Testing unique hosts:", len(group_test_hosts))
    print("Hosts appearing in BOTH sets:", len(group_overlap))

    show_class_distribution(
        "Group training class distribution",
        y_group_train
    )

    show_class_distribution(
        "Group testing class distribution",
        y_group_test
    )

    # 5. Final comparison

    print("\n[5] SPLIT COMPARISON")
    print("-" * 65)
    print("Random split host overlap:", len(random_overlap))
    print("Group split host overlap:", len(group_overlap))
    print("Group split test size:", f"{len(X_group_test) / len(df):.2%}")

    print("\n" + "=" * 65)
    print("HOST LEAKAGE AUDIT COMPLETED")
    print("NO DATASET MODIFICATIONS WERE MADE")
    print("=" * 65)


if __name__ == "__main__":
    main()
