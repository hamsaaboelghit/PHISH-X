
import pandas as pd
import ipaddress
from urllib.parse import urlsplit

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)


def detect_ip_address(url):
    if not isinstance(url, str) or url.strip().lower() == "offline":
        return None

    value = url.strip()

    try:
        if "://" not in value and not value.startswith("//"):
            value = "//" + value

        parsed = urlsplit(value)
        hostname = parsed.hostname

        if not hostname:
            return None

        try:
            ipaddress.ip_address(hostname)
            return 1
        except ValueError:
            return 0

    except ValueError:
        return None


df["calculated_ip"] = df["URL"].apply(detect_ip_address)

valid = df.dropna(subset=["calculated_ip"]).copy()

valid["ip_mismatch"] = (
    valid["has_ip_address"] != valid["calculated_ip"]
)

print("=" * 60)
print("PHISH-X | IP ADDRESS AUDIT")
print("=" * 60)

print("\n[1] Stored feature distribution:")
print(df["has_ip_address"].value_counts(dropna=False))

print("\n[2] Calculated feature distribution:")
print(valid["calculated_ip"].value_counts())

print("\n[3] Compared records:", len(valid))

print("\n[4] Mismatches:", valid["ip_mismatch"].sum())

print("\n[5] Mismatch percentage:")
print(round(valid["ip_mismatch"].mean() * 100, 2), "%")

print("\n[6] Mismatch examples:")

print(
    valid[valid["ip_mismatch"]][
        ["URL", "has_ip_address", "calculated_ip"]
    ].head(15).to_string(index=False)
)

print("\nAudit completed.")
