"""
PHISH-X | URL feature extractor (model contract).

Reproduces, from a single URL string, the 16 numerical features stored in
``data/raw/url_features_extracted1.csv`` (LegitPhish dataset).

The definitions implemented here were reverse-engineered from the dataset
and verified on every row (see ``tests/test_dataset_parity.py`` and
``docs/URL_SECURITY_AND_FEATURE_SPECIFICATION.md``). They are the
**legacy** definitions: they are NOT changed or "improved" here, because
the trained model must see the same definitions the dataset was built with.
Known weaknesses are surfaced through ``UrlFeatures.warnings`` instead.

Safety properties
-----------------
* Pure string processing. No network access, no DNS, no file access.
* Never raises for bad input; returns a result with ``ok=False``.
* Output structure is always identical: the same 16 keys in the same order.
* Input is bounded (``max_length``) so hostile input cannot cause
  unbounded work.

Typical use::

    from phishx.features.url_features import extract_features

    result = extract_features("http://192.168.0.1:8080/login.exe")
    if result.ok:
        vector = result.to_vector()
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field

from .url_parser import UrlParseError, legacy_split, parse_url

__all__ = [
    "FEATURE_NAMES",
    "FEATURE_SPEC_VERSION",
    "MAX_URL_LENGTH",
    "POPULAR_TLDS",
    "SUSPICIOUS_EXTENSION_SUFFIXES",
    "FeatureExtractionError",
    "UrlFeatures",
    "extract_features",
    "extract_features_batch",
]

FEATURE_SPEC_VERSION = "1.0-legacy"

#: Dataset column order. The model MUST consume features in this order.
FEATURE_NAMES: tuple[str, ...] = (
    "url_length",
    "has_ip_address",
    "dot_count",
    "https_flag",
    "url_entropy",
    "token_count",
    "subdomain_count",
    "query_param_count",
    "tld_length",
    "path_length",
    "has_hyphen_in_domain",
    "number_of_digits",
    "tld_popularity",
    "suspicious_file_extension",
    "domain_name_length",
    "percentage_numeric_chars",
)

#: Hard upper bound on accepted input length (characters).
MAX_URL_LENGTH = 8192

#: Exact list recovered from the dataset (value 1 only for these).
POPULAR_TLDS = frozenset({"com", "org", "net", "edu", "gov"})

#: Exact suffixes recovered from the dataset. NOTE: no leading dot - the
#: original check is ``path.lower().endswith(...)`` on the bare strings,
#: so ``/bin`` and ``...-for-js`` also match.
SUSPICIOUS_EXTENSION_SUFFIXES: tuple[str, ...] = (
    "exe", "zip", "bin", "apk", "cmd", "js",
)

#: Four dotted decimal groups anywhere in the URL (legacy has_ip_address).
_IPV4_ANYWHERE_RE = re.compile(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}")

#: Characters counted by legacy token_count (token = piece between them).
_TOKEN_SEPARATORS = "./?=&"

STATUS_OK = "ok"
STATUS_INVALID_TYPE = "invalid_type"
STATUS_EMPTY = "empty"
STATUS_TOO_LONG = "too_long"
STATUS_MALFORMED = "malformed"


class FeatureExtractionError(ValueError):
    """Raised by ``UrlFeatures.to_vector`` when the extraction failed."""


@dataclass(frozen=True)
class UrlFeatures:
    """Result of :func:`extract_features`.

    Attributes:
        url: the stripped input (``repr`` of the object when the input
            was not a string; truncated when ``too_long``).
        status: ``ok`` | ``invalid_type`` | ``empty`` | ``too_long`` |
            ``malformed``.
        features: always the 16 keys of :data:`FEATURE_NAMES`, in order.
            When ``status != "ok"`` every value is ``nan``.
        warnings: reliability notes for an ``ok`` result (see
            :data:`WARNING_CODES`). A warning does not change a value.
    """

    url: str
    status: str
    features: dict[str, float]
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK

    def to_vector(self) -> list[float]:
        """Feature values in :data:`FEATURE_NAMES` order.

        Raises:
            FeatureExtractionError: when ``ok`` is ``False``, so a failed
                extraction can never be fed to the model by accident.
        """
        if not self.ok:
            raise FeatureExtractionError(
                f"feature extraction failed: status={self.status}"
            )
        return [self.features[name] for name in FEATURE_NAMES]

    def as_dict(self) -> dict[str, object]:
        """JSON-friendly representation (``nan`` becomes ``None``)."""
        return {
            "url": self.url,
            "status": self.status,
            "ok": self.ok,
            "warnings": list(self.warnings),
            "features": {
                k: (None if isinstance(v, float) and math.isnan(v) else v)
                for k, v in self.features.items()
            },
        }


#: Documentation of warning codes (also rendered in the specification).
WARNING_CODES: dict[str, str] = {
    "no_authority": (
        "URL has no '//' authority (typically no scheme). Legacy parsing "
        "gives an empty host, so subdomain_count=-1, tld_length=0, "
        "domain_name_length=0, tld_popularity=0, has_hyphen_in_domain=0."
    ),
    "host_contains_port": (
        "Host carries a ':port'. Legacy tld_length / domain_name_length / "
        "tld_popularity include the port text in the last label."
    ),
    "host_contains_userinfo": (
        "Host carries 'user@'. Legacy host-derived features include the "
        "user-info text."
    ),
    "ip_pattern_outside_host": (
        "An IPv4-looking pattern was found but the netloc is not an IP "
        "address (path, query, version number, or userinfo)."
    ),
    "ipv6_not_detected": (
        "Host is an IPv6 literal. Legacy has_ip_address only recognises "
        "dotted IPv4 patterns, so it reports 0."
    ),
    "obfuscated_ipv4_not_detected": (
        "Host is a decimal/hex/octal IPv4 form accepted by browsers. "
        "Legacy has_ip_address reports 0."
    ),
    "single_label_host": (
        "Host has a single label; legacy subdomain_count is -1 and "
        "domain_name_length equals tld_length."
    ),
}


def _nan_features() -> dict[str, float]:
    return {name: float("nan") for name in FEATURE_NAMES}


def _failure(url: object, status: str) -> UrlFeatures:
    return UrlFeatures(
        url=url if isinstance(url, str) else repr(url),
        status=status,
        features=_nan_features(),
        warnings=(),
    )


def _shannon_entropy(text: str) -> float:
    """Shannon entropy (bits per character, log base 2) of ``text``."""
    if not text:
        return 0.0
    total = len(text)
    return -sum(
        (n / total) * math.log2(n / total) for n in Counter(text).values()
    )


def extract_features(url: object, *, max_length: int = MAX_URL_LENGTH) -> UrlFeatures:
    """Extract the 16 model features from one URL, safely.

    Leading / trailing whitespace is stripped first (the dataset contains
    none, and pasted URLs often carry some). Everything else is processed
    exactly as given.

    Args:
        url: the URL string. Any other type yields ``invalid_type``.
        max_length: reject inputs longer than this many characters.

    Returns:
        :class:`UrlFeatures`. This function does not raise.
    """
    if not isinstance(url, str):
        return _failure(url, STATUS_INVALID_TYPE)

    text = url.strip()
    if not text:
        return _failure(url, STATUS_EMPTY)
    if len(text) > max_length:
        return _failure(text[:64] + "...", STATUS_TOO_LONG)

    try:
        parts = legacy_split(text)
    except UrlParseError:
        return _failure(text, STATUS_MALFORMED)

    netloc = parts.netloc
    labels = netloc.split(".")
    last_label = labels[-1]
    digits = sum(1 for c in text if c.isdigit())
    ip_match = _IPV4_ANYWHERE_RE.search(text) is not None

    features: dict[str, float] = {
        "url_length": len(text),
        "has_ip_address": int(ip_match),
        "dot_count": text.count("."),
        "https_flag": int(parts.scheme == "https"),
        "url_entropy": _shannon_entropy(text),
        "token_count": 1 + sum(text.count(c) for c in _TOKEN_SEPARATORS),
        "subdomain_count": len(labels) - 2,
        "query_param_count": len(parts.query.split("&")),
        "tld_length": len(last_label),
        "path_length": len(parts.path),
        "has_hyphen_in_domain": int("-" in netloc),
        "number_of_digits": digits,
        "tld_popularity": int(last_label.lower() in POPULAR_TLDS),
        "suspicious_file_extension": int(
            parts.path.lower().endswith(SUSPICIOUS_EXTENSION_SUFFIXES)
        ),
        "domain_name_length": len(labels[-2] if len(labels) >= 2 else last_label),
        "percentage_numeric_chars": digits / len(text) * 100.0,
    }

    return UrlFeatures(
        url=text,
        status=STATUS_OK,
        features=features,
        warnings=_collect_warnings(text, netloc, ip_match),
    )


def _collect_warnings(text: str, netloc: str, ip_match: bool) -> tuple[str, ...]:
    warnings: list[str] = []
    if not netloc:
        warnings.append("no_authority")
    else:
        if "@" in netloc:
            warnings.append("host_contains_userinfo")
        hostport = netloc.rsplit("@", 1)[-1]
        if not hostport.startswith("[") and ":" in hostport:
            warnings.append("host_contains_port")
        if "." not in netloc and not hostport.startswith("["):
            warnings.append("single_label_host")

    try:
        strict = parse_url(text)
    except UrlParseError:
        return tuple(warnings)

    if strict.host_kind == "ipv6":
        warnings.append("ipv6_not_detected")
    elif strict.host_kind == "ipv4_obfuscated":
        warnings.append("obfuscated_ipv4_not_detected")
    elif ip_match and strict.host_kind != "ipv4":
        warnings.append("ip_pattern_outside_host")
    return tuple(warnings)


def extract_features_batch(urls: Iterable[object]) -> list[UrlFeatures]:
    """Apply :func:`extract_features` to many URLs, preserving order."""
    return [extract_features(u) for u in urls]
