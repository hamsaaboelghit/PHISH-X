
import pandas as pd

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)

df["calculated_digits"] = (
    df["URL"].astype(str).str.count(r"\d")
)

df["digit_mismatch"] = (
    df["number_of_digits"] != df["calculated_digits"]
)

print("=" * 60)
print("PHISH-X | NUMBER OF DIGITS AUDIT")
print("=" * 60)

print("\n[1] Stored feature statistics:")
print(df["number_of_digits"].describe())

print("\n[2] Calculated feature statistics:")
print(df["calculated_digits"].describe())

print("\n[3] Mismatches:")
print(df["digit_mismatch"].sum())

print("\n[4] Mismatch percentage:")
print(round(df["digit_mismatch"].mean() * 100, 4), "%")

print("\n[5] Mismatch examples:")

print(
    df[df["digit_mismatch"]][
        ["URL", "number_of_digits", "calculated_digits"]
    ].head(15).to_string(index=False)
)

print("\nAudit completed.")
