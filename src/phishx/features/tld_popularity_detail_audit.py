
import pandas as pd
from urllib.parse import urlsplit

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)

def extract_tld(url):
    try:
        url = str(url).strip()

        if "://" not in url:
            url = "//" + url

        hostname = urlsplit(url).hostname

        if not hostname:
            return None

        hostname = hostname.lower().rstrip(".")

        # Remove port is handled by urlsplit.
        # This extracts the final label only, not the full public suffix.
        if hostname.replace(".", "").isdigit():
            return "IP_ADDRESS"

        return hostname.split(".")[-1]

    except Exception:
        return None


df["extracted_tld"] = df["URL"].apply(extract_tld)

valid = df.dropna(subset=["extracted_tld"]).copy()

print("=" * 65)
print("PHISH-X | TLD POPULARITY DETAILED AUDIT")
print("=" * 65)

print("\n[1] Successfully extracted TLD:")
print(len(valid), "out of", len(df))

print("\n[2] Most common TLDs:")
print(valid["extracted_tld"].value_counts().head(25))

print("\n[3] TLD vs Popularity:")
print(
    pd.crosstab(
        valid["extracted_tld"],
        valid["tld_popularity"],
        margins=True
    ).sort_values(by=1, ascending=False).head(30)
)

print("\n[4] Popularity rate by TLD:")

tld_summary = (
    valid.groupby("extracted_tld")
    .agg(
        total=("tld_popularity", "size"),
        popularity_rate=("tld_popularity", "mean"),
        phishing_count=("ClassLabel", lambda x: (x == 0).sum()),
        legitimate_count=("ClassLabel", lambda x: (x == 1).sum())
    )
    .sort_values("total", ascending=False)
)

print(tld_summary.head(30).to_string())

print("\n[5] TLDs with at least 20 records:")
print(
    tld_summary[tld_summary["total"] >= 20]
    .sort_values("popularity_rate")
    .head(20)
    .to_string()
)

print("\nAudit completed.")
