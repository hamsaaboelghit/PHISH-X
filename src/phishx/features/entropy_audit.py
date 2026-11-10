
import pandas as pd
import math
from collections import Counter

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)


def calculate_entropy(url):
    if not isinstance(url, str) or len(url) == 0:
        return None

    counts = Counter(url)
    total = len(url)

    entropy = 0

    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy


df["calculated_entropy"] = df["URL"].apply(
    calculate_entropy
)

valid = df.dropna(subset=["calculated_entropy"]).copy()

valid["entropy_difference"] = (
    valid["url_entropy"] - valid["calculated_entropy"]
).abs()

print("=" * 60)
print("PHISH-X | URL ENTROPY AUDIT")
print("=" * 60)

print("\n[1] Stored entropy statistics:")
print(df["url_entropy"].describe())

print("\n[2] Calculated entropy statistics:")
print(valid["calculated_entropy"].describe())

print("\n[3] Mean absolute difference:")
print(valid["entropy_difference"].mean())

print("\n[4] Maximum difference:")
print(valid["entropy_difference"].max())

print("\n[5] Records matching within tolerance 0.001:")
print(
    (valid["entropy_difference"] < 0.001).sum(),
    "out of",
    len(valid)
)

print("\n[6] Examples with largest differences:")
print(
    valid.nlargest(10, "entropy_difference")[
        ["URL", "url_entropy", "calculated_entropy",
         "entropy_difference"]
    ].to_string(index=False)
)

print("\nAudit completed.")
