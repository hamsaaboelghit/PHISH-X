"""
PHISH-X | Advisory URL security signals.

IMPORTANT - these are NOT model features.
-----------------------------------------
The model contract lives in ``url_features.py`` and must stay identical to
the dataset definitions. The signals below are *descriptive facts* about a
URL computed with the STRICT parser (``url_parser.parse_url``). They are
intended for the URL Investigation page, for explanations and for future
feature proposals that must first be approved by the team (see
``docs/URL_SECURITY_AND_FEATURE_SPECIFICATION.md``, section 9).

No thresholds, brand lists or reputation data are used: every signal is a
plain structural fact, so none of them can silently drift from a dataset
definition. No network access is performed.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from .url_parser import (
    ParsedURL,
    UrlParseError,
    default_port_for,
    normalize_url_text,
    parse_url,
)

__all__ = ["UrlSecuritySignals", "analyze_url_security"]

_SCHEME_IN_TEXT_RE = re.compile(r"(?i)\b(?:https?|ftp)://")
_DOUBLE_SCHEME_RE = re.compile(r"(?i)^[A-Za-z][A-Za-z0-9+.-]*://[A-Za-z][A-Za-z0-9+.-]*://")
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")


@dataclass(frozen=True)
class UrlSecuritySignals:
    """Structural facts about one URL. ``parsed`` is False on failure."""

    parsed: bool
    error: str | None = None
    authority_source: str = "none"  # explicit | implied | none
    scheme: str = ""
    is_protocol_relative: bool = False
    is_opaque_scheme: bool = False  # javascript:, data:, mailto: ...
    host: str = ""
    host_kind: str = "empty"  # domain|ipv4|ipv4_obfuscated|ipv6|empty
    label_count: int = 0
    has_userinfo: bool = False
    userinfo_contains_dot: bool = False  # e.g. paypal.com@evil.example
    port: int | None = None
    port_valid: bool = True
    #: True when a port was present but is not a valid port number
    #: (non-numeric, or outside 0-65535). This is a separate fact from
    #: ``has_nondefault_port``: an invalid port must never be read as
    #: "default port, therefore safe".
    has_invalid_port: bool = False
    has_nondefault_port: bool = False
    has_punycode_label: bool = False  # label starting with "xn--"
    has_non_ascii_host: bool = False
    idna_conversion_failed: bool = False
    has_trailing_dot_host: bool = False
    double_scheme: bool = False  # http://http://...
    embedded_url_in_path_or_query: bool = False  # ...?u=http://other
    percent_escape_count: int = 0
    percent_escape_in_host: bool = False
    has_fragment: bool = False

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def _failed(message: str) -> UrlSecuritySignals:
    return UrlSecuritySignals(parsed=False, error=message)


def analyze_url_security(url: object) -> UrlSecuritySignals:
    """Compute :class:`UrlSecuritySignals` for ``url``. Never raises."""
    if not isinstance(url, str):
        return _failed("invalid_type")
    try:
        p: ParsedURL = parse_url(url)
    except UrlParseError as exc:
        return _failed(str(exc))

    # Same normalisation as the strict parser (strip + delete \t\r\n),
    # so the raw-text checks below cannot disagree with the parsed view.
    text = normalize_url_text(url)
    labels = p.labels
    non_ascii = not p.host.isascii()
    default_port = default_port_for(p.scheme)
    after_authority = f"{p.path}?{p.query}" if p.query else p.path

    return UrlSecuritySignals(
        parsed=True,
        authority_source=p.authority_source,
        scheme=p.scheme,
        is_protocol_relative=p.is_protocol_relative,
        is_opaque_scheme=p.is_opaque_scheme,
        host=p.host,
        host_kind=p.host_kind,
        label_count=len(labels),
        has_userinfo=p.has_userinfo,
        userinfo_contains_dot="." in p.userinfo,
        port=p.port,
        port_valid=p.port_valid,
        has_invalid_port=not p.port_valid,
        has_nondefault_port=(
            p.port is not None
            and default_port is not None
            and p.port != default_port
        ),
        has_punycode_label=any(l.startswith("xn--") for l in labels),
        has_non_ascii_host=non_ascii,
        idna_conversion_failed=(p.host_ascii is None),
        has_trailing_dot_host=p.host_had_trailing_dot,
        double_scheme=_DOUBLE_SCHEME_RE.match(text) is not None,
        embedded_url_in_path_or_query=bool(
            _SCHEME_IN_TEXT_RE.search(after_authority)
        ),
        percent_escape_count=len(_PERCENT_ESCAPE_RE.findall(text)),
        percent_escape_in_host="%" in p.host,
        has_fragment=p.has_fragment,
    )

