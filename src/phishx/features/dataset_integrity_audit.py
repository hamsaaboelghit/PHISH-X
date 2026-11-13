
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[3]
DATA_PATH = ROOT / "data" / "raw" / "url_features_extracted1.csv"

REQUIRED_COLUMNS = {"URL", "ClassLabel"}
ALLOWED_LABELS = {0, 1}

def main():
    print("=" * 65)
    print("PHISH-X | DATASET INTEGRITY AUDIT")
    print("=" * 65)

    if not DATA_PATH.exists():
        print(f"\nERROR: Dataset not found: {DATA_PATH}")
        return

    df = pd.read_csv(DATA_PATH)

    print(f"\n[1] Dataset shape: {df.shape}")
    print(f"[2] Total columns: {len(df.columns)}")

    # Required columns validation
    missing_columns = REQUIRED_COLUMNS - set(df.columns)

    print("\n[3] Required columns:")
    print("Missing:", sorted(missing_columns) if missing_columns else "None")

    if missing_columns:
        print("\nERROR: Cannot continue audit.")
        print("Required columns are missing.")
        return

    # Missing values
    print("\n[4] Missing values:")
    missing = df.isna().sum()
    missing = missing[missing > 0]
    print(missing if not missing.empty else "None")

    # Label distribution and validation
    print("\n[5] Label distribution:")
    print(df["ClassLabel"].value_counts(dropna=False))

    numeric_labels = pd.to_numeric(
        df["ClassLabel"],
        errors="coerce"
    )

    missing_or_invalid_labels = numeric_labels.isna()
    non_integer_labels = (
        numeric_labels.notna()
        & (numeric_labels != numeric_labels.round())
    )

    unexpected_labels = (
        numeric_labels.notna()
        & ~numeric_labels.isin(ALLOWED_LABELS)
    )

    print("\n[6] Label validation:")
    print(
        "Missing or non-numeric labels:",
        int(missing_or_invalid_labels.sum())
    )
    print(
        "Non-integer labels:",
        int(non_integer_labels.sum())
    )
    print(
        "Unexpected labels:",
        sorted(numeric_labels[unexpected_labels].unique().tolist())
    )

    labels_valid = (
        not missing_or_invalid_labels.any()
        and not non_integer_labels.any()
        and not unexpected_labels.any()
    )

    print("Label validation:", "PASSED" if labels_valid else "FAILED")

    # URL duplicate analysis
    print("\n[7] Duplicate URL analysis:")

    url_series = df["URL"]
    valid_string_urls = url_series.map(lambda value: isinstance(value, str))
    normalized_urls = url_series.where(valid_string_urls).str.strip()

    duplicate_rows = int(
        normalized_urls.duplicated(keep="first").sum()
    )

    duplicate_groups = int(
        normalized_urls[normalized_urls.notna()]
        .value_counts()
        .gt(1)
        .sum()
    )

    print("Duplicate rows:", duplicate_rows)
    print("Duplicate URL groups:", duplicate_groups)
    print("Unique non-empty URLs:", int(normalized_urls[
        normalized_urls.ne("")
    ].nunique()))

    # Conflicting labels
    print("\n[8] Conflicting labels:")

    conflict_data = pd.DataFrame({
        "URL": normalized_urls,
        "ClassLabel": numeric_labels,
    })

    conflict_data = conflict_data.dropna(
        subset=["URL", "ClassLabel"]
    )

    conflicts = (
        conflict_data.groupby("URL")["ClassLabel"]
        .nunique()
    )

    conflicts = conflicts[conflicts > 1]

    print("Conflicting URLs:", len(conflicts))

    if not conflicts.empty:
        print("Examples:")
        print(conflicts.head(10))

    # Invalid URL records
    print("\n[9] Invalid URL records:")

    missing_urls = int(url_series.isna().sum())

    blank_urls = int(
        (
            valid_string_urls
            & url_series.map(
                lambda value: value.strip() == ""
                if isinstance(value, str)
                else False
            )
        ).sum()
    )

    non_string_urls = int(
        (~valid_string_urls & ~url_series.isna()).sum()
    )

    print("Missing URLs:", missing_urls)
    print("Blank URLs:", blank_urls)
    print("Non-string URLs:", non_string_urls)

    # Numeric feature audit
    print("\n[10] Numeric feature audit:")

    excluded_columns = {"URL", "ClassLabel"}

    feature_columns = [
        column for column in df.columns
        if column not in excluded_columns
    ]

    numeric_data = df[feature_columns].apply(
        pd.to_numeric,
        errors="coerce"
    )

    non_numeric_counts = {}

    for column in feature_columns:
        invalid_mask = (
            df[column].notna()
            & numeric_data[column].isna()
        )

        invalid_count = int(invalid_mask.sum())

        if invalid_count > 0:
            non_numeric_counts[column] = invalid_count

    print("Feature columns:", len(feature_columns))
    print("Non-numeric feature values:")

    if non_numeric_counts:
        print(pd.Series(non_numeric_counts))
    else:
        print("None")

    numeric_columns = numeric_data.select_dtypes(
        include="number"
    ).columns.tolist()

    print("Numeric feature columns:", len(numeric_columns))

    if numeric_columns:
        print("\nInfinite values:")

        infinite_counts = (
            numeric_data[numeric_columns]
            .isin([float("inf"), float("-inf")])
            .sum()
        )

        infinite_counts = infinite_counts[infinite_counts > 0]

        print(
            infinite_counts
            if not infinite_counts.empty
            else "None"
        )

    print("\n" + "=" * 65)
    print("AUDIT COMPLETED - RAW DATASET WAS NOT MODIFIED")
    print("=" * 65)

if __name__ == "__main__":
    main()