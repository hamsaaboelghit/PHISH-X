
import pandas as pd

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)

df["calculated_percentage"] = (
    df["number_of_digits"] / df["url_length"] * 100
)

df["difference"] = abs(
    df["percentage_numeric_chars"] - df["calculated_percentage"]
)

df["mismatch"] = df["difference"] > 0.001

print("=" * 60)
print("PHISH-X | PERCENTAGE NUMERIC CHARS AUDIT")
print("=" * 60)

print("\n[1] Stored feature statistics:")
print(df["percentage_numeric_chars"].describe())

print("\n[2] Calculated feature statistics:")
print(df["calculated_percentage"].describe())

print("\n[3] Mismatches:")
print(df["mismatch"].sum())

print("\n[4] Mismatch percentage:")
print(round(df["mismatch"].mean() * 100, 4), "%")

print("\n[5] Maximum difference:")
print(df["difference"].max())

print("\n[6] Mismatch examples:")
print(
    df[df["mismatch"]][
        [
            "URL",
            "number_of_digits",
            "url_length",
            "percentage_numeric_chars",
            "calculated_percentage",
        ]
    ].head(10).to_string(index=False)
)

print("\nAudit completed.")
