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

    severity_rank = {"high": 2, "medium": 1, "low": 0}
    highest = max((f["severity"] for f in findings), key=severity_rank.get, default=None)
    status = "warning" if findings else "no_structural_flags"
    return {
        "status": status,
        "risk_level": highest or "none",
        "findings": findings,
        "actual_host": signals.get("host") or None,
        "note": "Advisory structural checks; not an ML prediction or a guarantee of safety.",
    }
