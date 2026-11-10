
from pathlib import Path
import pandas as pd

ROOT = Path(__file__).resolve().parents[3]
DATA_PATH = ROOT / "data" / "raw" / "url_features_extracted1.csv"


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

    required = {"URL", "ClassLabel"}
    missing_columns = required - set(df.columns)

    print("\n[3] Required columns:")
    print("Missing:", missing_columns if missing_columns else "None")

    print("\n[4] Missing values:")
    missing = df.isna().sum()
    print(missing[missing > 0] if missing.any() else "None")

    print("\n[5] Label distribution:")
    print(df["ClassLabel"].value_counts(dropna=False))

    print("\n[6] Duplicate URL analysis:")
    print("Duplicate rows:", df["URL"].duplicated().sum())
    print("Unique URLs:", df["URL"].nunique())

    print("\n[7] Conflicting labels:")
    conflicts = (
        df.dropna(subset=["ClassLabel"])
        .groupby("URL")["ClassLabel"]
        .nunique()
    )
    conflicts = conflicts[conflicts > 1]
    print("Conflicting URLs:", len(conflicts))

    print("\n[8] Invalid URL records:")
    empty_urls = df["URL"].isna().sum()
    blank_urls = df["URL"].astype(str).str.strip().eq("").sum()
    print("Missing URLs:", empty_urls)
    print("Blank URLs:", blank_urls)

    print("\n[9] Unexpected labels:")
    labels = set(df["ClassLabel"].dropna().unique())
    unexpected = labels - {0, 1}
    print(unexpected if unexpected else "None")

    print("\n[10] Numeric feature audit:")
    numeric = df.select_dtypes(include="number").columns.tolist()
    print("Numeric columns:", len(numeric))

    if numeric:
        print("\nInfinite values:")
        print(
            df[numeric]
            .isin([float("inf"), float("-inf")])
            .sum()
            .loc[lambda x: x > 0]
        )

    print("\n" + "=" * 65)
    print("AUDIT COMPLETED - RAW DATASET WAS NOT MODIFIED")
    print("=" * 65)


if __name__ == "__main__":
    main()
