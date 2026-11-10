
import pandas as pd
import re

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)

def calculate_token_count(url):
    # Split URL into tokens using common URL separators
    tokens = re.split(r"[/?:&=._\-#]", str(url))
    tokens = [token for token in tokens if token]
    return len(tokens)


df["calculated_tokens"] = df["URL"].apply(calculate_token_count)

df["token_mismatch"] = (
    df["token_count"] != df["calculated_tokens"]
)

print("=" * 60)
print("PHISH-X | TOKEN COUNT AUDIT")
print("=" * 60)

print("\n[1] Stored feature statistics:")
print(df["token_count"].describe())

print("\n[2] Calculated feature statistics:")
print(df["calculated_tokens"].describe())

print("\n[3] Mismatches:")
print(df["token_mismatch"].sum())

print("\n[4] Mismatch percentage:")
print(round(df["token_mismatch"].mean() * 100, 4), "%")

print("\n[5] Mismatch examples:")
print(
    df[df["token_mismatch"]][
        ["URL", "token_count", "calculated_tokens"]
    ].head(15).to_string(index=False)
)

print("\nAudit completed.")
