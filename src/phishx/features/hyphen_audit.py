
import pandas as pd
from urllib.parse import urlsplit

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)

def calculate_hyphen(url):
    try:
        parsed = urlsplit(str(url))
        hostname = parsed.hostname

        if hostname is None:
            return None

        return int("-" in hostname)

    except Exception:
        return None


df["calculated_hyphen"] = df["URL"].apply(
    calculate_hyphen
)

valid = df["calculated_hyphen"].notna()

df_valid = df[valid].copy()

df_valid["mismatch"] = (
    df_valid["has_hyphen_in_domain"]
    != df_valid["calculated_hyphen"]
)

print("=" * 60)
print("PHISH-X | HYPHEN IN DOMAIN AUDIT")
print("=" * 60)

print("\n[1] Stored distribution:")
print(df["has_hyphen_in_domain"].value_counts())

print("\n[2] Calculated distribution:")
print(df_valid["calculated_hyphen"].value_counts())

print("\n[3] Valid URLs:")
print(len(df_valid))

print("\n[4] Mismatches:")
print(df_valid["mismatch"].sum())

print("\n[5] Mismatch percentage:")
print(round(df_valid["mismatch"].mean() * 100, 4), "%")

print("\n[6] Mismatch examples:")
print(
    df_valid[df_valid["mismatch"]][
        ["URL", "has_hyphen_in_domain", "calculated_hyphen"]
    ].head(15).to_string(index=False)
)

print("\nAudit completed.")
