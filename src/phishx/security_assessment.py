"""Rule-based advisory security assessment, separate from ML probabilities.

This layer surfaces structural URL red flags without changing the trained
model's prediction, threshold, or probability.
"""
from __future__ import annotations

from typing import Any, Iterable


def assess_security(
    signals: dict[str, Any], extraction_warnings: Iterable[str] = ()
) -> dict[str, Any]:
    """Summarize structural red flags as findings; never overrides ML output."""
    findings: list[dict[str, str]] = []
    warnings = set(extraction_warnings)

    if not signals.get("parsed", False):
        findings.append({
            "code": "security_parse_failed",
            "severity": "medium",
            "title": "Structural inspection incomplete",
            "description": (
                "The security-oriented URL parser could not fully inspect this input. "
                "The model output must not be treated as a safety verdict."
            ),
        })

    scheme = str(signals.get("scheme") or "").lower()
    if signals.get("is_opaque_scheme") or scheme not in {"", "http", "https"}:
        findings.append({
            "code": "unsupported_uri_scheme",
            "severity": "medium",
            "title": "Non-HTTP(S) URI scheme",
            "description": (
                "This input is not a standard HTTP(S) web URL. The phishing model "
                "was evaluated on web-URL data, so its class and probabilities "
                "should not be interpreted as a safety verdict for this URI."
            ),
        })

    if signals.get("has_userinfo") and signals.get("userinfo_contains_dot"):
        findings.append({
            "code": "misleading_userinfo",
            "severity": "high",
            "title": "Misleading user-info detected",
            "description": (
                "Text before '@' may imitate a trusted domain; the actual "
                "destination host is shown separately."
            ),
        })
    elif signals.get("has_userinfo") or "host_contains_userinfo" in warnings:
        findings.append({
            "code": "userinfo_present",
            "severity": "medium",
            "title": "URL contains user-info",
            "description": "The URL authority contains user-info before the actual host.",
        })

    if signals.get("has_invalid_port"):
        findings.append({
            "code": "invalid_port",
            "severity": "medium",
            "title": "Invalid port",
            "description": "The URL contains a port that could not be parsed as valid.",
        })
    if signals.get("has_punycode_label") or signals.get("has_non_ascii_host"):
        findings.append({
            "code": "internationalized_host",
            "severity": "medium",
            "title": "Internationalized or punycode hostname",
            "description": "Review the hostname for visually confusable characters.",
        })
    if signals.get("double_scheme"):
        findings.append({
            "code": "double_scheme",
            "severity": "high",
            "title": "Repeated URL scheme",
            "description": "The URL contains a repeated scheme prefix.",
        })
    if signals.get("embedded_url_in_path_or_query"):
        findings.append({
            "code": "embedded_url",
            "severity": "medium",
            "title": "Embedded URL detected",
            "description": "The path or query contains another URL.",
        })

    host_kind = signals.get("host_kind")
    if host_kind in {"ipv4", "ipv6"}:
        findings.append({
            "code": "ip_address_host",
            "severity": "low",
            "title": "Direct IP address used as destination",
            "description": (
                "The URL targets an IP address instead of a hostname. This can be "
                "legitimate, especially on private networks, but the destination's "
                "domain identity is not available; verify that this address is expected."
            ),
        })
    elif host_kind == "ipv4_obfuscated":
        findings.append({
            "code": "obfuscated_ip_address",
            "severity": "medium",
            "title": "Obfuscated IP address used as destination",
            "description": (
                "The hostname appears to encode an IPv4 address in a non-standard "
                "form. Treat it cautiously and verify the actual destination."
            ),
        })

    severity_rank = {"high": 3, "medium": 2, "low": 1}
    highest = max(
        (f["severity"] for f in findings),
        key=severity_rank.get,
        default=None,
    )
    status = "warning" if findings else "no_structural_flags"
    return {
        "status": status,
        "risk_level": highest or "none",
        "findings": findings,
        "actual_host": signals.get("host") or None,
        "note": (
            "Advisory structural checks; not an ML prediction or a guarantee of safety."
        ),
    }
