
from pathlib import Path
from urllib.parse import urlsplit
from collections import Counter
import ipaddress

import pandas as pd


ROOT = Path(__file__).resolve().parents[3]

DATA_PATH = ROOT / "data" / "processed" / "cleaned_dataset.csv"


def extract_host(url):

    try:
        value = str(url).strip()

        if not value:
            return None

        if "://" not in value:
            value = "//" + value

        return urlsplit(value).hostname

    except (ValueError, TypeError):
        return None


def is_ip(host):

    if not host:
        return False

    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def main():

    print("=" * 65)
    print("PHISH-X | DOMAIN DISTRIBUTION AUDIT")
    print("=" * 65)

    df = pd.read_csv(DATA_PATH)

    df["host"] = df["URL"].apply(extract_host)

    print("\n[1] Host extraction")

    print("Total records:", len(df))
    print("Extracted hosts:", df["host"].notna().sum())
    print("Missing hosts:", df["host"].isna().sum())
    print("Unique hosts:", df["host"].nunique())

    # --------------------------------------------------------
    # 2. Host frequency
    # --------------------------------------------------------

    print("\n[2] Top 20 most frequent hosts")

    print(
        df["host"]
        .value_counts()
        .head(20)
        .to_string()
    )

    # --------------------------------------------------------
    # 3. Host distribution by class
    # --------------------------------------------------------

    print("\n[3] Host distribution by class")

    host_class = pd.crosstab(
        df["host"],
        df["ClassLabel"]
    )

    host_class.columns = ["Phishing", "Legitimate"]

    print("\nHosts appearing in both classes:")

    both_classes = host_class[
        (host_class["Phishing"] > 0)
        & (host_class["Legitimate"] > 0)
    ]

    print("Count:", len(both_classes))

    if len(both_classes) > 0:
        print(
            both_classes
            .sort_values(
                by=["Phishing", "Legitimate"],
                ascending=False
            )
            .head(20)
            .to_string()
        )

    # --------------------------------------------------------
    # 4. IP versus hostname analysis
    # --------------------------------------------------------

    df["is_ip"] = df["host"].apply(is_ip)

    print("\n[4] IP versus hostname distribution")

    print(
        df.groupby(["ClassLabel", "is_ip"])
        .size()
        .unstack(fill_value=0)
        .rename(index={
            0: "Phishing",
            1: "Legitimate"
        })
        .rename(columns={
            False: "Domain",
            True: "IP Address"
        })
        .to_string()
    )

    # --------------------------------------------------------
    # 5. Host concentration
    # --------------------------------------------------------

    print("\n[5] Host concentration")

    host_counts = df["host"].value_counts()

    for percentage in [1, 5, 10]:

        number_of_hosts = max(
            1,
            int(len(host_counts) * percentage / 100)
        )

        records = host_counts.head(number_of_hosts).sum()

        ratio = records / len(df) * 100

        print(
            f"Top {percentage}% of hosts account for "
            f"{ratio:.2f}% of records"
        )

    # --------------------------------------------------------
    # 6. Repeated hosts
    # --------------------------------------------------------

    print("\n[6] Repeated host statistics")

    print(
        "Hosts with more than 1 URL:",
        int((host_counts > 1).sum())
    )

    print(
        "Hosts with more than 10 URLs:",
        int((host_counts > 10).sum())
    )

    print(
        "Hosts with more than 100 URLs:",
        int((host_counts > 100).sum())
    )

    print("\n" + "=" * 65)
    print("DOMAIN DISTRIBUTION AUDIT COMPLETED")
    print("=" * 65)


if __name__ == "__main__":
    main()
