"""Read-only reproducibility check for FEATURE_DEFINITIONS.md.

Recomputes the CONFIRMED formulas from docs/FEATURE_DEFINITIONS.md and
compares them to the stored values on all 100,872 cleaned records,
printing the mismatch count per feature. This is an AUDIT script, not a
production extractor: it must not be used for serving predictions.

Run: PYTHONPATH=src python -m phishx.features.feature_definitions_repro
No network access or dataset writes.
"""
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

ROOT = Path(__file__).resolve().parents[3]
DATA_PATH = ROOT / "data" / "processed" / "cleaned_dataset.csv"

POPULAR_TLDS = {"com", "org", "net", "edu", "gov"}
SUSPICIOUS_SUFFIXES = ("exe", "zip", "bin", "apk", "cmd", "js")
IPV4_LIKE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")


def _netloc(url):
    """urlsplit netloc with userinfo stripped; None for missing/Offline."""
    if not isinstance(url, str):
        return None
    value = url.strip()
    if not value or value.lower() == "offline":
        return None
    try:
        if "://" not in value and not value.startswith("//"):
            value = "//" + value
        parsed = urlsplit(value)
        if not parsed.netloc:
            return None
        return parsed.netloc.split("@")[-1]
    except ValueError:
        return None


def _parts(url):
    netloc = _netloc(url)
    return netloc.split(".") if netloc else []


def recompute_query_param_count(url):
    if not isinstance(url, str):
        return 1
    if "?" not in url:
        return 1
    return url.split("?", 1)[1].count("&") + 1


def recompute_subdomain_count(url):
    parts = _parts(url)
    return len(parts) - 2 if parts else -2


def recompute_has_ip_address(url):
    if not isinstance(url, str):
        return 0
    return int(bool(IPV4_LIKE.search(url)))


def recompute_tld_popularity(url, subdomain_count):
    parts = _parts(url)
    final = parts[-1] if parts else None
    return int(final in POPULAR_TLDS and subdomain_count != -1)


def recompute_suspicious_file_extension(url):
    if not isinstance(url, str):
        return 0
    path = url.split("?", 1)[0].split("#", 1)[0].lower()
    return int(any(path.endswith(s) for s in SUSPICIOUS_SUFFIXES))


def recompute_tld_length(url):
    parts = _parts(url)
    return len(parts[-1]) if parts else 0


def recompute_domain_name_length(url):
    parts = _parts(url)
    return len(parts[-2]) if len(parts) >= 2 else 0


def recompute_token_count_audit_hypothesis(url):
    """Audit hypothesis from token_count_audit.py (REJECTED, for evidence)."""
    tokens = re.split(r"[/?:&=._\-#]", str(url))
    return len([t for t in tokens if t])


def reproduce(df):
    """Compare recomputed vs stored values; return mismatch counts."""
    non_sentinel = df["subdomain_count"] != -1

    def mismatches(stored, recomputed, mask=None):
        if mask is None:
            mask = pd.Series(True, index=df.index)
        return int((stored[mask] != recomputed[mask]).sum())

    recomputed = {
        "query_param_count": df["URL"].map(recompute_query_param_count),
        "subdomain_count": df["URL"].map(recompute_subdomain_count),
        "has_ip_address": df["URL"].map(recompute_has_ip_address),
        "tld_popularity": df.apply(
            lambda r: recompute_tld_popularity(r["URL"], r["subdomain_count"]),
            axis=1,
        ),
        "suspicious_file_extension": df["URL"].map(
            recompute_suspicious_file_extension
        ),
        "tld_length": df["URL"].map(recompute_tld_length),
        "domain_name_length": df["URL"].map(recompute_domain_name_length),
        "token_count (audit hypothesis, UNKNOWN)": df["URL"].map(
            recompute_token_count_audit_hypothesis
        ),
    }
    # Sentinel cohort is excluded for subdomain/lengths (documented bundle).
    sentinel_excluded = {
        "subdomain_count",
        "tld_length",
        "domain_name_length",
    }
    result = {}
    for feature, values in recomputed.items():
        mask = non_sentinel if feature in sentinel_excluded else None
        total = int(mask.sum()) if mask is not None else int(len(df))
        result[feature] = {
            "mismatches": mismatches(df[feature.split(" ")[0]], values, mask),
            "total_compared": total,
        }
    result["_sentinel_rows"] = int((~non_sentinel).sum())
    return result


def main():
    df = pd.read_csv(DATA_PATH)
    result = reproduce(df)
    result["dataset_sha256"] = hashlib.sha256(DATA_PATH.read_bytes()).hexdigest()
    result["rows"] = int(len(df))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
