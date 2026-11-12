
from pathlib import Path
from urllib.parse import urlsplit
from collections import Counter
import ipaddress

import pandas as pd

# =========================================================
# PHISH-X | SUBDOMAIN FEATURE AUDIT
# =========================================================

ROOT = Path(__file__).resolve().parents[3]

DATA_PATH = ROOT / "data" / "processed" / "cleaned_dataset.csv"

LABEL_MAP = {
    0: "Phishing",
    1: "Legitimate"
}

# =========================================================
# 1. URL PARSING
# =========================================================

def parse_hostname(url):
    """
    Extract hostname safely from a URL.

    Supports:
    - URLs with schemes
    - URLs without schemes
    - Protocol-relative URLs
    - Invalid and offline values
    """

    if not isinstance(url, str):
        return None

    value = url.strip()

    if not value or value.lower() == "offline":
        return None

    try:
        if value.startswith("//"):
            parsed = urlsplit(value)

        elif "://" not in value:
            parsed = urlsplit("//" + value)

        else:
            parsed = urlsplit(value)

        hostname = parsed.hostname

        if not hostname:
            return None

        return hostname.lower().rstrip(".")

    except (ValueError, TypeError):
        return None

# =========================================================
# 2. IP ADDRESS DETECTION
# =========================================================

def is_ip_address(hostname):
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True

    except ValueError:
        return False

# =========================================================
# 3. INDEPENDENT SUBDOMAIN CALCULATION
# =========================================================

def analyze_subdomain(url):
    """
    Calculate a preliminary subdomain count.

    IMPORTANT:
    This is a simple hostname-label calculation.
    It does NOT use the Public Suffix List.

    Therefore, it is an audit hypothesis,
    not the confirmed original dataset definition.
    """

    hostname = parse_hostname(url)

    if not hostname:
        return None

    if is_ip_address(hostname):
        return 0

    parts = hostname.split(".")

    if len(parts) <= 2:
        return 0

    return len(parts) - 2

# =========================================================
# 4. DATASET DISTRIBUTION
# =========================================================

def inspect_dataset_distribution(df):

    print("\n" + "=" * 65)
    print("[1] ORIGINAL DATASET SUBDOMAIN DISTRIBUTION")
    print("=" * 65)

    print(
        df["subdomain_count"]
        .value_counts(dropna=False)
        .sort_index()
        .to_string()
    )

    print("\nNegative values:")

    print(
        (df["subdomain_count"] < 0).sum()
    )

# =========================================================
# 5. INDEPENDENT CALCULATED DISTRIBUTION
# =========================================================

def inspect_calculated_distribution(df):

    print("\n" + "=" * 65)
    print("[2] INDEPENDENTLY CALCULATED DISTRIBUTION")
    print("=" * 65)

    df["calculated_subdomain"] = (
        df["URL"].apply(analyze_subdomain)
    )

    print(
        df["calculated_subdomain"]
        .value_counts(dropna=False)
        .sort_index()
        .to_string()
    )

    print("\nMissing calculated values:")

    print(
        df["calculated_subdomain"].isna().sum()
    )

# =========================================================
# 6. DATASET VS CALCULATED COMPARISON
# =========================================================

def compare_subdomain_values(df):

    print("\n" + "=" * 65)
    print("[3] DATASET VS CALCULATED COMPARISON")
    print("=" * 65)

    valid = df["calculated_subdomain"].notna()

    comparison = df.loc[valid].copy()

    comparison["match"] = (
        comparison["subdomain_count"]
        == comparison["calculated_subdomain"]
    )

    matches = comparison["match"].sum()
    mismatches = (~comparison["match"]).sum()

    total = len(comparison)

    print(f"Comparable records: {total:,}")
    print(f"Exact matches: {matches:,}")
    print(f"Mismatches: {mismatches:,}")

    if total:
        print(
            f"Mismatch percentage: "
            f"{mismatches / total * 100:.2f}%"
        )

    print("\nMismatch examples:")

    print(
        comparison.loc[
            ~comparison["match"],
            [
                "URL",
                "subdomain_count",
                "calculated_subdomain"
            ]
        ]
        .head(20)
        .to_string(index=False)
    )

# =========================================================
# 7. SUBDOMAIN COUNT VS CLASS LABEL
# =========================================================

def inspect_subdomain_by_label(df):

    print("\n" + "=" * 65)
    print("[4] SUBDOMAIN COUNT VS CLASS LABEL")
    print("=" * 65)

    print("\nClass distribution:")

    print(
        df.groupby("ClassLabel")["subdomain_count"]
        .agg(["count", "mean", "min", "max"])
        .rename(index=LABEL_MAP)
        .to_string()
    )

    print("\nNegative values by class:")

    negative = df[df["subdomain_count"] < 0]

    print(
        negative["ClassLabel"]
        .value_counts()
        .rename(index=LABEL_MAP)
        .to_string()
    )

# =========================================================
# 8. INVESTIGATE ANOMALOUS RECORDS
# =========================================================

def investigate_anomalies(df):

    print("\n" + "=" * 65)
    print("[5] INVESTIGATING ANOMALOUS RECORDS")
    print("=" * 65)

    anomaly = df[
        (df["subdomain_count"] < 0)
        | (df["tld_length"] == 0)
        | (df["domain_name_length"] == 0)
    ].copy()

    print(f"Anomalous records: {len(anomaly):,}")

    print("\nCombined anomaly patterns:")

    print(
        anomaly.groupby(
            [
                "subdomain_count",
                "tld_length",
                "domain_name_length"
            ],
            dropna=False
        )
        .size()
        .sort_values(ascending=False)
        .to_string()
    )

    print("\nFirst 30 anomalous URLs:")

    print(
        anomaly[
            [
                "URL",
                "ClassLabel",
                "subdomain_count",
                "tld_length",
                "domain_name_length"
            ]
        ]
        .head(30)
        .to_string(index=False)
    )

# =========================================================
# 9. DEEP HOSTNAME INVESTIGATION
# =========================================================

def deep_hostname_investigation(df):

    print("\n" + "=" * 65)
    print("[6] DEEP HOSTNAME INVESTIGATION")
    print("=" * 65)

    df["hostname"] = df["URL"].apply(parse_hostname)

    df["hostname_status"] = df["hostname"].apply(
        lambda host:
            "Missing hostname" if host is None
            else "IP address" if is_ip_address(host)
            else "Valid hostname"
    )

    print("\nHostname status distribution:")

    print(
        df["hostname_status"]
        .value_counts()
        .to_string()
    )

    print("\nHostname status for negative subdomain records:")

    negative = df[df["subdomain_count"] < 0]

    print(
        negative["hostname_status"]
        .value_counts()
        .to_string()
    )

    print("\nNegative records with extracted hostname:")

    print(
        negative[
            [
                "URL",
                "hostname",
                "ClassLabel",
                "subdomain_count",
                "tld_length",
                "domain_name_length"
            ]
        ]
        .head(25)
        .to_string(index=False)
    )

# =========================================================
# 10. HOSTNAME DOT COUNT INVESTIGATION
# =========================================================

def investigate_hostname_patterns(df):

    print("\n" + "=" * 65)
    print("[7] HOSTNAME DOT COUNT INVESTIGATION")
    print("=" * 65)

    sample = df[
        ["URL", "subdomain_count"]
    ].copy()

    sample["hostname"] = sample["URL"].apply(
        parse_hostname
    )

    sample["hostname_dot_count"] = (
        sample["hostname"]
        .fillna("")
        .apply(lambda host: host.count("."))
    )

    sample["hostname_label_count"] = (
        sample["hostname"]
        .fillna("")
        .apply(
            lambda host:
                len(host.split(".")) if host else 0
        )
    )

    sample["difference"] = (
        sample["subdomain_count"]
        - sample["hostname_dot_count"]
    )

    print("\n[7.1] Dataset value vs hostname dot count")

    print(
        sample.groupby("subdomain_count")[
            "hostname_dot_count"
        ]
        .agg(["count", "mean", "min", "max"])
        .to_string()
    )

    valid = sample["hostname"].notna()

    print("\n[7.2] Exact matches")

    print(
        "Matches with hostname dot count:",
        (
            sample.loc[valid, "subdomain_count"]
            == sample.loc[valid, "hostname_dot_count"]
        ).sum()
    )

    print(
        "Matches with label count - 2:",
        (
            sample.loc[valid, "subdomain_count"]
            == sample.loc[valid, "hostname_label_count"] - 2
        ).sum()
    )

    print("\n[7.3] Representative examples")

    print(
        sample[
            [
                "URL",
                "hostname",
                "subdomain_count",
                "hostname_dot_count",
                "hostname_label_count"
            ]
        ]
        .sample(
            min(30, len(sample)),
            random_state=42
        )
        .to_string(index=False)
    )

# =========================================================
# 11. MAIN
# =========================================================

def main():

    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATA_PATH}"
        )

    df = pd.read_csv(DATA_PATH)

    required_columns = [
        "URL",
        "subdomain_count",
        "tld_length",
        "domain_name_length",
        "ClassLabel"
    ]

    missing_columns = [
        col for col in required_columns
        if col not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    print("=" * 65)
    print("PHISH-X | SUBDOMAIN FEATURE AUDIT")
    print("=" * 65)

    print(f"Dataset records: {len(df):,}")

    inspect_dataset_distribution(df)

    inspect_calculated_distribution(df)

    compare_subdomain_values(df)

    inspect_subdomain_by_label(df)

    investigate_anomalies(df)

    deep_hostname_investigation(df)

    investigate_hostname_patterns(df)

    print("\n" + "=" * 65)
    print("SUBDOMAIN AUDIT COMPLETED")
    print("=" * 65)

if __name__ == "__main__":
    main()