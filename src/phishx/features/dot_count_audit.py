
import pandas as pd
from urllib.parse import urlsplit

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)


def extract_hostname(url):
    if not isinstance(url, str) or url.strip().lower() == "offline":
        return None

    value = url.strip()

    try:
        if "://" not in value and not value.startswith("//"):
            value = "//" + value

        return urlsplit(value).hostname

    except ValueError:
        return None


df["calculated_dots_full_url"] = (
    df["URL"].astype(str).str.count(r"\.")
)

df["hostname"] = df["URL"].apply(extract_hostname)

df["calculated_dots_hostname"] = (
    df["hostname"].str.count(r"\.")
)

valid = df.dropna(subset=["calculated_dots_hostname"]).copy()

valid["full_url_mismatch"] = (
    valid["dot_count"] != valid["calculated_dots_full_url"]
)

valid["hostname_mismatch"] = (
    valid["dot_count"] != valid["calculated_dots_hostname"]
)

print("=" * 60)
print("PHISH-X | DOT COUNT AUDIT")
print("=" * 60)

print("\n[1] Stored dot_count distribution:")
print(df["dot_count"].value_counts().sort_index())

print("\n[2] Full URL comparison:")
print("Mismatches:", valid["full_url_mismatch"].sum())
print(
    "Mismatch percentage:",
    round(valid["full_url_mismatch"].mean() * 100, 2),
    "%"
)

print("\n[3] Hostname comparison:")
print("Mismatches:", valid["hostname_mismatch"].sum())
print(
    "Mismatch percentage:",
    round(valid["hostname_mismatch"].mean() * 100, 2),
    "%"
)

print("\n[4] Examples where full URL count differs:")

print(
    valid[valid["full_url_mismatch"]][
        ["URL", "dot_count", "calculated_dots_full_url"]
    ].head(10).to_string(index=False)
)

print("\n[5] Examples where hostname count differs:")

print(
    valid[valid["hostname_mismatch"]][
        ["URL", "hostname", "dot_count", "calculated_dots_hostname"]
    ].head(10).to_string(index=False)
)

print("\nAudit completed.")
