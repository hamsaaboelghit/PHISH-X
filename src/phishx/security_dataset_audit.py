"""Read-only security cohort audit. No network access or dataset writes.
Run: PYTHONPATH=src python -m phishx.security_dataset_audit

Validation: required columns and labels are checked before the audit runs
and raise a clear ValueError if violated. Missing / non-string URLs are
counted in ``url_type_audit`` and handled safely (treated as missing host /
empty text for string markers) instead of raising an exception.
"""
import hashlib
import json
from pathlib import Path

import pandas as pd
from phishx.features.subdomain_audit import parse_hostname, is_ip_address

ROOT = Path(__file__).resolve().parents[2]

REQUIRED_COLUMNS = [
    "URL",
    "ClassLabel",
    "subdomain_count",
    "tld_length",
    "domain_name_length",
    "has_ip_address",
]

ALLOWED_LABELS = {0, 1}


def validate_dataframe(df):
    """Validate required columns, labels and URL types.

    Returns a ``url_type_audit`` dict describing URL column types.
    Raises ValueError for missing columns or unexpected labels.
    Missing / non-string URLs do NOT raise; they are reported and handled
    safely downstream.
    """
    missing_columns = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}. "
            f"Required: {REQUIRED_COLUMNS}."
        )

    # Labels: allow int 0/1 and float 0.0/1.0 as read from CSV.
    # NaN / any other value is unexpected and must be surfaced, not hidden.
    observed = df["ClassLabel"].dropna().unique().tolist()
    observed_set = set()
    for value in observed:
        # Normalize 0.0 -> 0, 1.0 -> 1 for comparison; keep original for report.
        try:
            if float(value) in (0.0, 1.0):
                observed_set.add(int(float(value)))
                continue
        except (TypeError, ValueError):
            pass
        observed_set.add(value)
    unexpected = sorted(
        [v for v in observed_set if v not in ALLOWED_LABELS],
        key=lambda v: str(v),
    )
    if unexpected:
        raise ValueError(
            f"Unexpected ClassLabel values: {unexpected}. "
            f"Allowed labels are 0 (phishing) and 1 (legitimate)."
        )
    if int(df["ClassLabel"].isna().sum()) > 0:
        raise ValueError(
            f"ClassLabel contains {int(df['ClassLabel'].isna().sum())} "
            "missing (NaN) values; audit requires complete labels."
        )

    # URL types: report only, never raise here.
    url_series = df["URL"]
    is_string = url_series.map(lambda u: isinstance(u, str))
    is_missing = url_series.isna()
    return {
        "total_rows": int(len(df)),
        "string_count": int(is_string.sum()),
        "missing_count": int(is_missing.sum()),
        "non_string_non_missing_count": int((~is_string & ~is_missing).sum()),
        "empty_or_whitespace_string_count": int(
            url_series[is_string].map(lambda u: not u.strip()).sum()
        ),
    }


def summarize(df):
    url_type_audit = validate_dataframe(df)

    hosts = df.URL.map(parse_hostname)
    # Safe text view: non-string / missing URLs become "" so string
    # operations below never raise (AttributeError / TypeError).
    url_text = df.URL.map(lambda u: u if isinstance(u, str) else "")
    parsed_ip = hosts.map(is_ip_address)

    # Structural indicators are not validity judgments or phishing labels.
    masks = {
        "negative_subdomain": df.subdomain_count.eq(-1),
        "ip_host": parsed_ip,
        "single_label_host": hosts.fillna("").map(lambda h: bool(h) and "." not in h and ":" not in h),
        "missing_host": hosts.isna(),
        "userinfo_marker": url_text.str.contains("@", regex=False),
        "percent_encoding": url_text.str.contains(r"%[0-9A-Fa-f]{2}", regex=True),
        "non_ascii": url_text.map(lambda u: not u.isascii()),
        "backslash": url_text.str.contains("\\", regex=False),
        "whitespace": url_text.str.contains(r"\s", regex=True),
        "query_marker": url_text.str.contains("?", regex=False),
        "deep_host_5plus_labels": hosts.fillna("").map(lambda h: not is_ip_address(h) and len(h.split('.')) >= 5),
        "url_200plus_chars": url_text.str.len().ge(200),
        "hostname_hyphen": hosts.fillna("").str.contains("-", regex=False),
    }
    cohorts = {}
    for name, mask in masks.items():
        cohorts[name] = {str(label): {"count": int((mask & df.ClassLabel.eq(label)).sum()),
                                    "class_percent": round(100 * mask[df.ClassLabel.eq(label)].mean(), 4)}
                         for label in (0, 1)}

    neg = df.subdomain_count.eq(-1)
    zero_tld = df.tld_length.eq(0)
    zero_domain = df.domain_name_length.eq(0)

    # Stored flag vs strict parsed hostname (row-level, reproducible).
    # has_ip_address is a dataset column; parsed IP is strict
    # ipaddress.ip_address() applied to parse_hostname(URL).
    # The two definitions are NOT interchangeable.
    stored_ip = df.has_ip_address.eq(1)
    both_ip = stored_ip & parsed_ip
    stored_only = stored_ip & ~parsed_ip
    parsed_only = ~stored_ip & parsed_ip

    def _by_label(mask):
        return {
            str(label): int((mask & df.ClassLabel.eq(label)).sum())
            for label in (0, 1)
        }

    ip_flag_vs_parsed = {
        "stored_has_ip_address_1": {
            "total": int(stored_ip.sum()),
            "by_label": _by_label(stored_ip),
        },
        "parsed_strict_ip": {
            "total": int(parsed_ip.sum()),
            "by_label": _by_label(parsed_ip),
        },
        "both": int(both_ip.sum()),
        "stored_only": int(stored_only.sum()),
        "parsed_only": int(parsed_only.sum()),
        "stored_only_by_label": _by_label(stored_only),
        "parsed_only_by_label": _by_label(parsed_only),
        "discrepancy_records": int(stored_only.sum() + parsed_only.sum()),
        "note": (
            "Stored flag (has_ip_address==1) vs strict parsed hostname "
            "(is_ip_address(parse_hostname(URL))). Row-level counts above "
            "make the discrepancy reproducible; aggregate difference alone "
            "does not establish row-level disagreement."
        ),
    }

    concentration = {}
    for label in (0, 1):
        class_mask = df.ClassLabel.eq(label)
        class_rows = int(class_mask.sum())
        counts = hosts[class_mask].value_counts()
        parsed_host_rows = int(hosts[class_mask].notna().sum())
        top10_rows = int(counts.head(10).sum())
        concentration[str(label)] = {
            "unique_hosts": len(counts),
            "top10_rows": top10_rows,
            # Denominator for top10_percent is ALL rows in the class,
            # including rows whose host could not be parsed.
            "denominator": "all rows in class (including missing-host rows)",
            "class_rows": class_rows,
            "rows_with_parsed_host": parsed_host_rows,
            "rows_missing_host": int(class_rows - parsed_host_rows),
            "top10_percent": round(100 * top10_rows / class_rows, 4) if class_rows else 0.0,
            "top10_percent_of_parsed_host_rows": (
                round(100 * top10_rows / parsed_host_rows, 4) if parsed_host_rows else 0.0
            ),
            "top10_hosts": counts.head(10).to_dict(),
        }

    return {
        "rows": len(df),
        "labels": df.ClassLabel.value_counts().to_dict(),
        "url_type_audit": url_type_audit,
        "cohorts": cohorts,
        "host_concentration": concentration,
        "ip_flag_vs_parsed": ip_flag_vs_parsed,
        "zero_length_bundle": {
            "zero_tld_length": int(zero_tld.sum()),
            "zero_domain_name_length": int(zero_domain.sum()),
            "both_zero": int((zero_tld & zero_domain).sum()),
            "either_zero": int((zero_tld | zero_domain).sum()),
        },
        "negative_subdomain_details": {
            "count": int(neg.sum()),
            "single_label_hosts": int((neg & masks['single_label_host']).sum()),
            "missing_hosts": int((neg & masks['missing_host']).sum()),
            "strict_ip_hosts": int((neg & parsed_ip).sum()),
            "zero_tld_length": int((neg & zero_tld).sum()),
            "zero_domain_name_length": int((neg & zero_domain).sum()),
            "zero_tld_and_zero_domain_name_length": int((neg & zero_tld & zero_domain).sum()),
            "top_hosts": hosts[neg].value_counts().head(10).to_dict(),
        },
        "notes": (
            "0=phishing; 1=legitimate. Indicators may overlap. "
            "Host parser is existing subdomain_audit.parse_hostname; "
            "it is not a URL validator. No source provenance column exists. "
            "Host concentration percentages use all rows in the class as "
            "denominator (see host_concentration.denominator); "
            "top10_percent_of_parsed_host_rows is provided for comparison. "
            "Stored has_ip_address flag and strict parsed IP are distinct "
            "definitions (see ip_flag_vs_parsed). "
            "Missing/non-string URLs are counted in url_type_audit and "
            "treated as missing host / empty text, never as valid URLs."
        ),
    }


def main():
    path = ROOT / 'data/processed/cleaned_dataset.csv'
    result = summarize(pd.read_csv(path))
    result['dataset_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
