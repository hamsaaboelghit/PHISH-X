
import pandas as pd
from urllib.parse import urlsplit

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)

def calculate_path_length(url):
    try:
        parsed = urlsplit(str(url))
        return len(parsed.path)
    except Exception:
        return None


df["calculated_path_length"] = df["URL"].apply(
    calculate_path_length
)

df["path_mismatch"] = (
    df["path_length"] != df["calculated_path_length"]
)

print("=" * 60)
print("PHISH-X | PATH LENGTH AUDIT")
print("=" * 60)

print("\n[1] Stored statistics:")
print(df["path_length"].describe())

print("\n[2] Calculated statistics:")
print(df["calculated_path_length"].describe())

print("\n[3] Mismatches:")
print(df["path_mismatch"].sum())

print("\n[4] Mismatch percentage:")
print(round(df["path_mismatch"].mean() * 100, 4), "%")

print("\n[5] Mismatch examples:")
print(
    df[df["path_mismatch"]][
        ["URL", "path_length", "calculated_path_length"]
    ].head(15).to_string(index=False)
)

print("\nAudit completed.")
