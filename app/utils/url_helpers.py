
import ipaddress
import re
from urllib.parse import urlsplit


def safe_hostname(url):
    try:
        candidate = url.strip()

        if not re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
            candidate,
        ):
            candidate = "http://" + candidate

        parsed = urlsplit(candidate)
        return parsed.hostname or ""

    except (ValueError, AttributeError):
        return ""


def extract_basic_signals(url):
    normalized = url.strip()

    try:
        parsed_url = normalized

        if not re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
            parsed_url,
        ):
            parsed_url = "http://" + parsed_url

        parsed = urlsplit(parsed_url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""

        is_ip = False

        if hostname:
            try:
                ipaddress.ip_address(hostname)
                is_ip = True
            except ValueError:
                pass

        return {
            "URL length": len(normalized),
            "HTTPS": int(parsed.scheme.lower() == "https"),
            "IP address in hostname": int(is_ip),
            "Dots in full URL": normalized.count("."),
            "Digits in URL": sum(c.isdigit() for c in normalized),
            "Hyphen in hostname": int("-" in hostname),
            "Path length": len(path),
            "Query parameters": len(
                [x for x in query.split("&") if x]
            ),
            "Hostname length": len(hostname),
        }

    except ValueError:
        return {}
