
import pandas as pd

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)

print("=" * 60)
print("PHISH-X | TLD POPULARITY AUDIT")
print("=" * 60)

print("\n[1] Overall statistics:")
print(df["tld_popularity"].describe())

print("\n[2] Unique values:")
print("Number of unique values:", df["tld_popularity"].nunique())
print(df["tld_popularity"].value_counts().head(20))

print("\n[3] Values by class:")
print(
    df.groupby("ClassLabel")["tld_popularity"]
    .agg(["count", "mean", "std", "min", "median", "max"])
)

print("\n[4] Correlation with class label:")
print(df[["tld_popularity", "ClassLabel"]].corr())

print("\n[5] Missing values:")
print(df["tld_popularity"].isna().sum())

print("\nAudit completed.")
