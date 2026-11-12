"""Read-only security cohort audit. No network access or dataset writes.
Run: PYTHONPATH=src python -m phishx.security_dataset_audit
"""
import hashlib
import json
from pathlib import Path

import pandas as pd
from phishx.features.subdomain_audit import parse_hostname, is_ip_address

ROOT = Path(__file__).resolve().parents[2]


def summarize(df):
    hosts = df.URL.map(parse_hostname)
    urls = df.URL
    # Structural indicators are not validity judgments or phishing labels.
    masks = {
        "negative_subdomain": df.subdomain_count.eq(-1),
        "ip_host": hosts.map(is_ip_address),
        "single_label_host": hosts.fillna("").map(lambda h: bool(h) and "." not in h and ":" not in h),
        "missing_host": hosts.isna(),
        "userinfo_marker": urls.str.contains("@", regex=False),
        "percent_encoding": urls.str.contains(r"%[0-9A-Fa-f]{2}", regex=True),
        "non_ascii": urls.map(lambda u: not u.isascii()),
        "backslash": urls.str.contains("\\", regex=False),
        "whitespace": urls.str.contains(r"\s", regex=True),
        "query_marker": urls.str.contains("?", regex=False),
        "deep_host_5plus_labels": hosts.fillna("").map(lambda h: not is_ip_address(h) and len(h.split('.')) >= 5),
        "url_200plus_chars": urls.str.len().ge(200),
        "hostname_hyphen": hosts.fillna("").str.contains("-", regex=False),
    }
    cohorts = {}
    for name, mask in masks.items():
        cohorts[name] = {str(label): {"count": int((mask & df.ClassLabel.eq(label)).sum()),
                                    "class_percent": round(100 * mask[df.ClassLabel.eq(label)].mean(), 4)}
                         for label in (0, 1)}
    neg = df.subdomain_count.eq(-1)
    concentration = {}
    for label in (0, 1):
        counts = hosts[df.ClassLabel.eq(label)].value_counts()
        concentration[str(label)] = {
            "unique_hosts": len(counts),
            "top10_rows": int(counts.head(10).sum()),
            "top10_percent": round(100 * counts.head(10).sum() / df.ClassLabel.eq(label).sum(), 4),
            "top10_hosts": counts.head(10).to_dict(),
        }
    return {
        "rows": len(df), "labels": df.ClassLabel.value_counts().to_dict(),
        "cohorts": cohorts, "host_concentration": concentration,
        "negative_subdomain_details": {
            "count": int(neg.sum()),
            "single_label_hosts": int((neg & masks['single_label_host']).sum()),
            "missing_hosts": int((neg & masks['missing_host']).sum()),
            "zero_tld_length": int((neg & df.tld_length.eq(0)).sum()),
            "zero_domain_name_length": int((neg & df.domain_name_length.eq(0)).sum()),
            "top_hosts": hosts[neg].value_counts().head(10).to_dict(),
        },
        "notes": "0=phishing; 1=legitimate. Indicators may overlap. Host parser is existing subdomain_audit.parse_hostname; it is not a URL validator. No source provenance column exists.",
    }


def main():
    path = ROOT / 'data/processed/cleaned_dataset.csv'
    result = summarize(pd.read_csv(path))
    result['dataset_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
