
from pathlib import Path
import pandas as pd

from phishx.evaluation.create_dataset_split import extract_host


# ============================================================
# PHISH-X | DATA CLEANING & PREPARATION
# ============================================================

ROOT = Path(__file__).resolve().parents[3]

RAW_PATH = ROOT / "data" / "raw" / "url_features_extracted1.csv"
OUTPUT_PATH = ROOT / "data" / "processed" / "cleaned_dataset.csv"


def main():

    print("=" * 65)
    print("PHISH-X | DATA CLEANING PIPELINE")
    print("=" * 65)

    # --------------------------------------------------------
    # 1. Load raw dataset
    # --------------------------------------------------------

    if not RAW_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {RAW_PATH}")

    df = pd.read_csv(RAW_PATH)

    original_count = len(df)

    print(f"\n[1] Original records: {original_count:,}")

    # --------------------------------------------------------
    # 2. Validate required columns
    # --------------------------------------------------------

    required_columns = {"URL", "ClassLabel"}

    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    # --------------------------------------------------------
    # 3. Normalize target labels
    # --------------------------------------------------------

    df["ClassLabel"] = pd.to_numeric(
        df["ClassLabel"],
        errors="coerce"
    )

    missing_labels = int(df["ClassLabel"].isna().sum())

    print("\n[2] Missing or invalid labels:", missing_labels)

    before_label_filter = len(df)

    df = df[df["ClassLabel"].isin([0, 1])].copy()

    removed_invalid_labels = before_label_filter - len(df)

    print("Removed invalid-label records:", removed_invalid_labels)

    # --------------------------------------------------------
    # 4. Remove missing, blank, and invalid URLs
    # --------------------------------------------------------

    before_url_filter = len(df)

    valid_urls = (
        df["URL"].notna()
        & df["URL"].astype(str).str.strip().ne("")
        & df["URL"].apply(
            lambda url: extract_host(url) is not None
        )
    )

    df = df[valid_urls].copy()

    removed_invalid_urls = before_url_filter - len(df)

    print(
        "\n[3] Removed missing, blank, or invalid URLs:",
        removed_invalid_urls
    )

    # --------------------------------------------------------
    # 5. Check conflicting labels before deduplication
    # --------------------------------------------------------

    label_counts = (
        df.groupby("URL")["ClassLabel"]
        .nunique()
    )

    conflicting_urls = label_counts[label_counts > 1]

    print("\n[4] Conflicting URL labels:", len(conflicting_urls))

    if len(conflicting_urls) > 0:
        print("\nExamples:")
        print(conflicting_urls.head(10))

        raise ValueError(
            "Conflicting labels detected. "
            "Resolve them before removing duplicate URLs."
        )

    # --------------------------------------------------------
    # 6. Remove duplicate URLs
    # --------------------------------------------------------

    before_deduplication = len(df)

    df = df.drop_duplicates(
        subset=["URL"],
        keep="first"
    ).copy()

    removed_duplicates = before_deduplication - len(df)

    print("\n[5] Removed duplicate URL records:", removed_duplicates)

    # --------------------------------------------------------
    # 7. Final validation
    # --------------------------------------------------------

    print("\n[6] Final validation")

    assert df["URL"].notna().all()
    assert df["URL"].astype(str).str.strip().ne("").all()
    assert df["URL"].apply(
        lambda url: extract_host(url) is not None
    ).all()
    assert df["ClassLabel"].notna().all()
    assert df["ClassLabel"].isin([0, 1]).all()
    assert not df["URL"].duplicated().any()

    print("Missing URLs:", df["URL"].isna().sum())
    print("Missing labels:", df["ClassLabel"].isna().sum())
    print("Duplicate URLs:", df["URL"].duplicated().sum())

    # --------------------------------------------------------
    # 8. Save processed dataset
    # --------------------------------------------------------

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    df.to_csv(
        OUTPUT_PATH,
        index=False
    )

    # --------------------------------------------------------
    # 9. Final report
    # --------------------------------------------------------

    print("\n" + "=" * 65)
    print("CLEANING SUMMARY")
    print("=" * 65)

    print(f"Original records:       {original_count:,}")
    print(f"Removed invalid labels: {removed_invalid_labels:,}")
    print(f"Removed invalid URLs:   {removed_invalid_urls:,}")
    print(f"Removed duplicates:     {removed_duplicates:,}")
    print("-" * 65)
    print(f"Final records:          {len(df):,}")
    print(f"Final columns:          {len(df.columns)}")

    print("\nFinal class distribution:")

    print(
        df["ClassLabel"]
        .value_counts()
        .sort_index()
        .rename(index={
            0: "Phishing",
            1: "Legitimate"
        })
    )

    print("\nSaved to:")
    print(OUTPUT_PATH)

    print("\nRAW DATASET WAS NOT MODIFIED")
    print("CLEANING PIPELINE COMPLETED")
    print("=" * 65)


if __name__ == "__main__":
    main()

