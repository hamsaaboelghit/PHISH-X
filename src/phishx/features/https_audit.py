
import pandas as pd
from urllib.parse import urlsplit

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)


def detect_https(url):
    if not isinstance(url, str) or url.strip().lower() == "offline":
        return None

    value = url.strip()

    try:
        if "://" not in value and not value.startswith("//"):
            value = "//" + value

        parsed = urlsplit(value)

        return int(parsed.scheme.lower() == "https")

    except ValueError:
        return None


df["calculated_https"] = df["URL"].apply(detect_https)

valid = df.dropna(subset=["calculated_https"]).copy()

valid["https_mismatch"] = (
    valid["https_flag"] != valid["calculated_https"]
)

print("=" * 60)
print("PHISH-X | HTTPS AUDIT")
print("=" * 60)

print("\n[1] Stored feature distribution:")
print(df["https_flag"].value_counts(dropna=False))

print("\n[2] Calculated feature distribution:")
print(valid["calculated_https"].value_counts())

print("\n[3] Compared records:", len(valid))

print("\n[4] Mismatches:", valid["https_mismatch"].sum())

print("\n[5] Mismatch percentage:")
print(round(valid["https_mismatch"].mean() * 100, 2), "%")

print("\n[6] Mismatch examples:")

print(
    valid[valid["https_mismatch"]][
        ["URL", "https_flag", "calculated_https"]
    ].head(15).to_string(index=False)
)

print("\nAudit completed.")
