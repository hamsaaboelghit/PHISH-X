
import pandas as pd
from urllib.parse import urlsplit

DATA_PATH = "data/raw/url_features_extracted1.csv"

df = pd.read_csv(DATA_PATH)


def analyze_subdomain(url):
    if not isinstance(url, str) or url.strip().lower() == "offline":
        return None

    try:
        value = url.strip()

        if "://" not in value and not value.startswith("//"):
            value = "//" + value

        parsed = urlsplit(value)

        hostname = parsed.hostname

        if not hostname:
            return None

        hostname = hostname.lower().rstrip(".")

        if hostname.replace(".", "").isdigit():
            return 0

        parts = hostname.split(".")

        if len(parts) <= 2:
            return 0

        return len(parts) - 2

    except ValueError:
        return None


df["calculated_subdomain_count"] = df["URL"].apply(
    analyze_subdomain
)

print("=" * 60)
print("PHISH-X | SUBDOMAIN AUDIT")
print("=" * 60)

print("\n[1] Dataset distribution")
print(df["subdomain_count"].value_counts().sort_index())

print("\n[2] Negative values")
negative = df[df["subdomain_count"] < 0]

print("Count:", len(negative))

print("\n[3] Independently calculated distribution")
print(
    df["calculated_subdomain_count"]
    .value_counts(dropna=False)
    .sort_index()
)

print("\n[4] Negative value examples")

print(
    negative[
        ["URL", "subdomain_count", "calculated_subdomain_count"]
    ].head(20).to_string(index=False)
)

print("\n[5] Dataset vs calculated comparison")

valid = df.dropna(subset=["calculated_subdomain_count"]).copy()

valid["subdomain_mismatch"] = (
    valid["subdomain_count"]
    != valid["calculated_subdomain_count"]
)

print("Compared URLs:", len(valid))
print("Mismatches:", valid["subdomain_mismatch"].sum())

print(
    "Mismatch percentage:",
    round(valid["subdomain_mismatch"].mean() * 100, 2),
    "%"
)

print("\nAudit completed.")




print("\n[6] Investigating negative subdomain records")

from urllib.parse import urlsplit
from collections import Counter

negative = df[df["subdomain_count"] < 0].copy()


def inspect_url(url):
    if not isinstance(url, str):
        return "not_string", None

    if url.strip().lower() == "offline":
        return "offline", None

    try:
        value = url.strip()

        if "://" not in value and not value.startswith("//"):
            value = "//" + value

        parsed = urlsplit(value)
        hostname = parsed.hostname

        if not hostname:
            return "missing_hostname", None

        return "hostname_found", hostname

    except ValueError:
        return "parsing_error", None


results = negative["URL"].apply(inspect_url)

negative["parse_status"] = results.apply(lambda x: x[0])
negative["extracted_hostname"] = results.apply(lambda x: x[1])

print("\nParsing status:")
print(negative["parse_status"].value_counts())

print("\nExamples where hostname was found:")
print(
    negative[negative["parse_status"] == "hostname_found"][
        ["URL", "extracted_hostname", "subdomain_count"]
    ].head(15).to_string(index=False)
)

print("\nExamples with parsing problems:")
print(
    negative[negative["parse_status"] != "hostname_found"][
        ["URL", "parse_status", "subdomain_count"]
    ].head(15).to_string(index=False)
)



print("\n[7] Subdomain count vs class label")

negative = df[df["subdomain_count"] < 0].copy()

print("\nNegative values by class:")
print(
    negative["ClassLabel"]
    .value_counts(dropna=False)
)

print("\nClass distribution for all records:")
print(
    df["ClassLabel"]
    .value_counts(dropna=False)
)

print("\nNegative values percentage within each class:")

for label in sorted(df["ClassLabel"].dropna().unique()):
    class_data = df[df["ClassLabel"] == label]

    negative_count = (class_data["subdomain_count"] < 0).sum()

    percentage = (
        negative_count / len(class_data)
    ) * 100

    print(
        f"Class {label}: "
        f"{negative_count} / {len(class_data)} "
        f"({percentage:.2f}%)"
    )

print("\nSubdomain distribution by class:")

print(
    df.groupby("ClassLabel")["subdomain_count"]
    .describe()
    .round(3)
)

print("\nAudit completed.")



print("\n[8] Checking domain feature relationship")

negative = df[df["subdomain_count"] < 0].copy()

print("\nTLD length distribution for negative records:")
print(negative["tld_length"].value_counts(dropna=False))

print("\nDomain name length distribution for negative records:")
print(negative["domain_name_length"].value_counts(dropna=False))

print("\nHow many negative records have both values equal to zero?")

both_zero = (
    (negative["tld_length"] == 0)
    & (negative["domain_name_length"] == 0)
)

print("Both zero:", both_zero.sum())
print("Total negative:", len(negative))

print("\nCross-check all records:")

print(
    pd.crosstab(
        df["subdomain_count"] < 0,
        [
            df["tld_length"] == 0,
            df["domain_name_length"] == 0
        ]
    )
)

print("\nAudit completed.")


print("\n[9] Investigating the 8 exceptional records")

exceptional = df[
    (df["subdomain_count"] < 0)
    & (
        (df["tld_length"] != 0)
        | (df["domain_name_length"] != 0)
    )
]

print("Exceptional records:", len(exceptional))

print(
    exceptional[
        [
            "URL",
            "subdomain_count",
            "tld_length",
            "domain_name_length",
            "ClassLabel"
        ]
    ].to_string(index=False)
)

print("\nAudit completed.")

print("\n[10] Inspecting the 1300 anomalous URLs")

anomalies = df[
    (df["subdomain_count"] == -1)
    & (df["tld_length"] == 0)
    & (df["domain_name_length"] == 0)
].copy()

print("\nTotal anomalous records:", len(anomalies))

print("\nClass distribution:")
print(anomalies["ClassLabel"].value_counts(dropna=False))

urls = anomalies["URL"].astype(str)

print("\nURL pattern analysis:")

print("Starts with http://:", urls.str.startswith("http://").sum())
print("Starts with https://:", urls.str.startswith("https://").sum())
print("Contains repeated http://:", urls.str.count("http://").gt(1).sum())
print("Contains spaces:", urls.str.contains(" ", regex=False).sum())
print("Contains Offline:", urls.str.lower().eq("offline").sum())

print("\nFirst 30 anomalous URLs:")
for url in urls.head(30):
    print(url)

print("\nAudit completed.")




import ipaddress
from urllib.parse import urlsplit

print("\n[11] Deep hostname investigation")

def inspect_hostname(url):
    if not isinstance(url, str) or url.strip().lower() == "offline":
        return "offline_or_invalid", None

    value = url.strip()

    try:
        if "://" not in value and not value.startswith("//"):
            value = "//" + value

        parsed = urlsplit(value)
        hostname = parsed.hostname

        if not hostname:
            return "no_hostname", None

        hostname = hostname.lower().rstrip(".")

        try:
            ipaddress.ip_address(hostname)
            return "ip_address", hostname
        except ValueError:
            pass

        if "." in hostname:
            return "domain_with_dots", hostname

        return "hostname_without_dots", hostname

    except ValueError:
        return "parsing_error", None


results = anomalies["URL"].apply(inspect_hostname)

anomalies["hostname_status"] = results.apply(lambda x: x[0])
anomalies["extracted_hostname"] = results.apply(lambda x: x[1])

print("\nHostname status distribution:")
print(anomalies["hostname_status"].value_counts())

print("\nExamples by status:")

for status in anomalies["hostname_status"].unique():
    print(f"\n--- {status} ---")

    print(
        anomalies[anomalies["hostname_status"] == status][
            ["URL", "extracted_hostname"]
        ].head(5).to_string(index=False)
    )

print("\nAudit completed.")



print("\n[12] Full domain feature anomaly analysis")

conditions = {
    "subdomain_negative": df["subdomain_count"] < 0,
    "tld_zero": df["tld_length"] == 0,
    "domain_length_zero": df["domain_name_length"] == 0,
}

print("\nIndividual anomaly counts:")

for name, condition in conditions.items():
    print(f"{name}: {condition.sum()}")

print("\nCombined anomaly patterns:")

anomaly_table = pd.DataFrame(conditions)

print(
    anomaly_table.value_counts(dropna=False)
    .to_string()
)

print("\nRecords with only one abnormal feature:")

for name in conditions:
    other_names = [key for key in conditions if key != name]

    only_this = (
        conditions[name]
        & ~conditions[other_names[0]]
        & ~conditions[other_names[1]]
    )

    print(f"{name} only: {only_this.sum()}")

print("\nAll three abnormal:")

all_three = (
    conditions["subdomain_negative"]
    & conditions["tld_zero"]
    & conditions["domain_length_zero"]
)

print(all_three.sum())

print("\nAudit completed.")
