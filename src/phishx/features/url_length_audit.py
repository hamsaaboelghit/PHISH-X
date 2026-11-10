
import pandas as pd

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)

print("=" * 60)
print("PHISH-X | URL LENGTH AUDIT")
print("=" * 60)

df["calculated_url_length"] = (
    df["URL"].astype(str).str.len()
)

df["length_mismatch"] = (
    df["url_length"] != df["calculated_url_length"]
)

print("\n[1] Stored URL length statistics:")
print(df["url_length"].describe())

print("\n[2] Calculated URL length statistics:")
print(df["calculated_url_length"].describe())

print("\n[3] Mismatch count:")
print(df["length_mismatch"].sum())

print("\n[4] Mismatch percentage:")
print(
    round(df["length_mismatch"].mean() * 100, 2),
    "%"
)

print("\n[5] Mismatch examples:")

print(
    df[df["length_mismatch"]][
        ["URL", "url_length", "calculated_url_length"]
    ].head(15).to_string(index=False)
)

print("\nAudit completed.")
