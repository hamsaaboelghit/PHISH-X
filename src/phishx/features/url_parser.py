"""
PHISH-X | Safe, deterministic, offline URL parser.

This module never performs network I/O, never resolves DNS and never
opens the URL. It only manipulates strings.

Two views of a URL are provided:

1. LEGACY split (``legacy_split``)
   A pure-Python re-implementation of ``urllib.parse.urlparse`` as it
   behaved when the training dataset (``url_features_extracted1.csv``)
   was generated. It exists so that the model features can be reproduced
   bit-for-bit and independently of the Python version in use
   (``urllib.parse`` changed behaviour several times between 3.8 and 3.13).
   Its quirks (for example: a URL without a scheme has an EMPTY netloc)
   are intentional and documented in
   ``docs/URL_SECURITY_AND_FEATURE_SPECIFICATION.md``.

2. STRICT view (``parse_url``)
<<<<<<< HEAD
   A security-oriented interpretation used for diagnostics and for the
   URL Investigation page. It separates user-info, host and port,
   understands schemeless and protocol-relative input, IPv4 / IPv6 /
   obfuscated IPv4 hosts and internationalised domain names.
=======
   A security-oriented, browser-aware interpretation used for diagnostics
   and for the URL Investigation page. It separates user-info, host and
   port, understands schemeless and protocol-relative input, IPv4 / IPv6 /
   obfuscated IPv4 hosts and internationalised domain names. It is NOT a
   full WHATWG URL implementation (no complete IPv6 canonicalisation, no
   IDNA 2008 / UTS #46 processing); it covers the browser-like readings
   that matter for phishing diagnostics.
>>>>>>> cb0e666d1b4161a0efb8a8176648128a77dbfb7d

The two views are deliberately separate: the legacy view feeds the model,
the strict view feeds explanations. Mixing them would silently change the
feature definitions the dataset was built with.
"""

from __future__ import annotations

import ipaddress
import re
import string
from dataclasses import dataclass

__all__ = [
    "LegacyParts",
    "ParsedURL",
    "UrlParseError",
    "default_port_for",
    "legacy_split",
<<<<<<< HEAD
=======
    "normalize_url_text",
>>>>>>> cb0e666d1b4161a0efb8a8176648128a77dbfb7d
    "parse_ipv4_whatwg",
    "parse_url",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Characters urllib treats as leading junk (C0 controls and space).
_LEADING_JUNK = "".join(chr(i) for i in range(0x21))

#: Characters urllib silently deletes anywhere in the URL (security fix
#: for CVE-2022-0391 / bpo-43882).
_DELETED_CHARS = ("\t", "\r", "\n")

_SCHEME_CHARS = frozenset(string.ascii_letters + string.digits + "+-.")

#: Schemes for which ``urlparse`` splits ``;params`` off the last path
#: segment. Taken from ``urllib.parse.uses_params``.
_USES_PARAMS = frozenset(
    {
        "", "ftp", "hdl", "prospero", "http", "imap", "https", "shttp",
        "rtsp", "rtspu", "sip", "sips", "mms", "sftp", "tel",
    }
)

#: ``scheme://`` at the start of the string.
_EXPLICIT_AUTHORITY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*://")

#: Special schemes: browsers (WHATWG) repair ``http:/x``, ``http:x`` and
#: ``http:\\x`` into ``http://x``.
_SPECIAL_SCHEME_RE = re.compile(r"^(https?|ftp|wss?):[/\\]*", re.IGNORECASE)

#: ``host:port`` shape without scheme, e.g. ``example.com:8080/path``.
_HOST_PORT_RE = re.compile(r"^[^/?#:@]+:[0-9]+(?:[/?#]|$)")

#: ``scheme:`` for non-hierarchical schemes (mailto:, javascript:, data:).
_OPAQUE_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")

<<<<<<< HEAD
=======
#: Schemes that are always opaque (no authority), even when what follows
#: the colon is all digits. Without this, ``javascript:123`` and
#: ``data:123`` match ``_HOST_PORT_RE`` and are misread as a schemeless
#: ``host:port``. A genuine schemeless host:port such as
#: ``example.com:8080`` (or ``localhost:8080``) is NOT in this list, so
#: the host:port reading is preserved for it. Unknown single-label
#: ``scheme:digits`` input keeps the host:port (address-bar) reading.
_KNOWN_OPAQUE_SCHEMES = frozenset(
    {
        # Script schemes (execute, never navigate to a host).
        "javascript", "vbscript", "jscript", "livescript", "mocha",
        # Data / document schemes.
        "data", "blob", "about", "chrome", "view-source", "feed",
        # Messaging schemes.
        "mailto", "mid", "cid", "news", "nntp",
        # Telephony schemes.
        "tel", "sms", "smsto", "callto", "skype", "facetime",
        # Payment / misc non-hierarchical schemes.
        "bitcoin", "ethereum", "magnet", "urn", "intent", "market",
    }
)

>>>>>>> cb0e666d1b4161a0efb8a8176648128a77dbfb7d
_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443}


class UrlParseError(ValueError):
    """Raised when a URL cannot be split into components."""


# ---------------------------------------------------------------------------
# 1. LEGACY split (feeds the model features)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LegacyParts:
    """Result of :func:`legacy_split` (mirrors ``urllib.parse.ParseResult``)."""

    scheme: str
    netloc: str
    path: str
    params: str
    query: str
    fragment: str


def legacy_split(url: str) -> LegacyParts:
    """Split ``url`` exactly like the dataset generator's ``urlparse`` did.

    Rules (all verified against the 101,219 raw dataset rows):

    * Leading C0 controls / spaces are removed; ``\\t``, ``\\r``, ``\\n``
      are deleted everywhere.
    * A scheme is ``<chars>:`` at the start where every char is in
      ``[A-Za-z0-9+.-]`` and what follows the ``:`` is not purely digits.
      The scheme is lower-cased.
    * The netloc exists only if the remainder starts with ``//``. A URL
      such as ``example.com/login`` therefore has an EMPTY netloc and the
      whole string becomes the path.
    * ``#fragment`` is split first, then ``?query``, then (for schemes in
      ``uses_params``) ``;params`` of the last path segment.

    Raises:
        UrlParseError: unbalanced ``[`` / ``]`` in the netloc.
    """
    if not isinstance(url, str):
        raise UrlParseError("url must be a string")

    url = url.lstrip(_LEADING_JUNK)
    for ch in _DELETED_CHARS:
        url = url.replace(ch, "")

    scheme = ""
    colon = url.find(":")
    if colon > 0 and all(c in _SCHEME_CHARS for c in url[:colon]):
        rest = url[colon + 1:]
        if not rest or any(c not in "0123456789" for c in rest):
            scheme = url[:colon].lower()
            url = rest

    netloc = ""
    if url[:2] == "//":
        end = len(url)
        for delim in "/?#":
            pos = url.find(delim, 2)
            if pos >= 0:
                end = min(end, pos)
        netloc, url = url[2:end], url[end:]
        if "[" in netloc or "]" in netloc:
            if not (netloc.startswith("[") and netloc.count("[") == 1
                    and netloc.count("]") == 1):
                raise UrlParseError("unbalanced IPv6 brackets in netloc")
            close = netloc.find("]")
            suffix = netloc[close + 1:]
            if suffix and not suffix.startswith(":"):
                raise UrlParseError("invalid text after bracketed host")

    fragment = query = params = ""
    if "#" in url:
        url, fragment = url.split("#", 1)
    if "?" in url:
        url, query = url.split("?", 1)
    if scheme in _USES_PARAMS and ";" in url:
        if "/" in url:
            idx = url.find(";", url.rfind("/"))
            if idx >= 0:
                url, params = url[:idx], url[idx + 1:]
        else:
            idx = url.find(";")
            url, params = url[:idx], url[idx + 1:]

    return LegacyParts(scheme, netloc, url, params, query, fragment)


# ---------------------------------------------------------------------------
# 2. STRICT view (diagnostics / investigation page)
# ---------------------------------------------------------------------------


def parse_ipv4_whatwg(host: str) -> str | None:
    """Parse ``host`` with the WHATWG IPv4 parser and return dotted decimal.

    Browsers accept forms such as ``2130706433``, ``0x7f.1`` or
    ``0177.0.0.1`` as IPv4 addresses. ``ipaddress.ip_address`` rejects
    them, so naive checks miss them. Returns ``None`` when ``host`` is not
    an IPv4 address under the WHATWG rules.
    """
    if not host:
        return None
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts = parts[:-1]
    if not parts or len(parts) > 4:
        return None

    numbers = []
    for part in parts:
        if part == "":
            return None
        try:
            if part[:2].lower() == "0x":
                value = int(part[2:] or "0", 16)
            elif len(part) > 1 and part[0] == "0":
                value = int(part[1:], 8)
            else:
                if not part.isascii() or not part.isdigit():
                    return None
                value = int(part, 10)
        except ValueError:
            return None
        numbers.append(value)

    if any(n > 255 for n in numbers[:-1]):
        return None
    if numbers[-1] >= 256 ** (5 - len(numbers)):
        return None

    total = numbers[-1]
    for i, n in enumerate(numbers[:-1]):
        total += n * 256 ** (3 - i)
    return str(ipaddress.IPv4Address(total))


@dataclass(frozen=True)
class ParsedURL:
    """Security-oriented decomposition of a URL.

    ``authority_source`` says where the host came from:

    * ``"explicit"``  - ``scheme://host`` or ``//host`` was present.
    * ``"implied"``   - no scheme; the first segment was treated as host
      (what a browser address bar would do).
    * ``"none"``      - opaque scheme (``mailto:``, ``javascript:`` ...)
      or nothing usable.
    """

    raw: str
    scheme: str
    authority_source: str
    userinfo: str
    host: str
    host_ascii: str | None
    port: int | None
    port_valid: bool
    path: str
    query: str
    fragment: str
    host_kind: str  # domain | ipv4 | ipv4_obfuscated | ipv6 | empty
    is_protocol_relative: bool
    has_explicit_scheme: bool
    is_opaque_scheme: bool
    host_had_trailing_dot: bool = False
    has_fragment: bool = False

    @property
    def has_userinfo(self) -> bool:
        return bool(self.userinfo)

    @property
    def labels(self) -> tuple:
        if self.host_kind not in ("domain",) or not self.host:
            return ()
        return tuple(self.host.split("."))


def _split_authority(authority: str):
    """Return ``(userinfo, host, port, port_valid)`` for an authority."""
    userinfo = ""
    hostport = authority
    if "@" in authority:
        userinfo, hostport = authority.rsplit("@", 1)

    port_text = ""
    if "[" in hostport or "]" in hostport:
        if not (hostport.startswith("[") and hostport.count("[") == 1
                and hostport.count("]") == 1):
            raise UrlParseError("invalid IPv6 brackets")
        end = hostport.find("]")
        host = hostport[1:end]
        tail = hostport[end + 1:]
        if not host or ":" not in host:
            raise UrlParseError("brackets must contain an IPv6 literal")
        try:
            if ipaddress.ip_address(host).version != 6:
                raise UrlParseError("brackets must contain an IPv6 literal")
        except ValueError as exc:
            raise UrlParseError("invalid IPv6 literal") from exc
        if tail.startswith(":"):
            port_text = tail[1:]
        elif tail:
            raise UrlParseError("garbage after IPv6 literal")
    elif hostport.count(":") > 1:
        raise UrlParseError("IPv6 literals must be enclosed in brackets")
    elif ":" in hostport:
        host, _, port_text = hostport.rpartition(":")
    else:
        host = hostport

    port: int | None = None
    port_valid = True
    if port_text:
        # Bound conversion before int(): Python limits decimal conversion
        # length, and hostile inputs may contain thousands of digits.
        if (port_text.isascii() and port_text.isdigit()
                and len(port_text) <= 5 and int(port_text) <= 65535):
            port = int(port_text)
        else:
            port_valid = False
    return userinfo, host, port, port_valid


def _classify_host(host: str) -> str:
    if not host:
        return "empty"
    try:
        addr = ipaddress.ip_address(host)
        return "ipv4" if addr.version == 4 else "ipv6"
    except ValueError:
        pass
    if parse_ipv4_whatwg(host) is not None:
        return "ipv4_obfuscated"
    return "domain"


def _to_ascii(host: str) -> str | None:
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return None


<<<<<<< HEAD
=======
def normalize_url_text(url: str) -> str:
    """Return the canonical text form used by the strict parser.

    Leading/trailing whitespace is stripped and ``\\t``, ``\\r``, ``\\n``
    are deleted everywhere (the same treatment ``urllib.parse`` applies
    since the CVE-2022-0391 / bpo-43882 fix). Every consumer that
    inspects the raw text — the strict parser and the advisory signals
    in ``url_signals`` — must use this helper so that, for example, a
    tab hidden inside ``http://ht\\ttp://...`` cannot make the parser
    and the ``double_scheme`` check disagree about the same input.
    """
    text = url.strip()
    for ch in _DELETED_CHARS:
        text = text.replace(ch, "")
    return text


>>>>>>> cb0e666d1b4161a0efb8a8176648128a77dbfb7d
def parse_url(url: str) -> ParsedURL:
    """Parse ``url`` into a :class:`ParsedURL` (never touches the network).

    Raises:
        UrlParseError: ``url`` is not a string, is blank, or its authority
            is syntactically broken (e.g. unterminated ``[``).
    """
    if not isinstance(url, str):
        raise UrlParseError("url must be a string")
<<<<<<< HEAD
    text = url.strip()
    for ch in _DELETED_CHARS:
        text = text.replace(ch, "")
=======
    text = normalize_url_text(url)
>>>>>>> cb0e666d1b4161a0efb8a8176648128a77dbfb7d
    if not text:
        raise UrlParseError("url is empty")

    scheme = ""
    has_explicit_scheme = False
    is_protocol_relative = False
    is_opaque = False
    authority_source = "none"
    remainder = text

    special = _SPECIAL_SCHEME_RE.match(text)
    if special:
        scheme = special.group(1).lower()
        remainder = text[special.end():].replace("\\", "/")
        has_explicit_scheme = True
        authority_source = "explicit"
    elif _EXPLICIT_AUTHORITY_RE.match(text):
        scheme, _, remainder = text.partition("://")
        scheme = scheme.lower()
        has_explicit_scheme = True
        authority_source = "explicit"
    elif text.startswith("//"):
        remainder = text[2:]
        is_protocol_relative = True
        authority_source = "explicit"
    else:
        m = _OPAQUE_SCHEME_RE.match(text)
<<<<<<< HEAD
        if m and not _HOST_PORT_RE.match(text):
=======
        # A known opaque scheme wins over the host:port reading, so
        # ``javascript:123`` / ``data:123`` are opaque (no host) rather
        # than host ``javascript`` / ``data`` with port 123. Any other
        # ``host:digits`` shape keeps the schemeless host:port reading
        # (``example.com:8080``, ``localhost:8080``).
        if m and (
            m.group(1).lower() in _KNOWN_OPAQUE_SCHEMES
            or not _HOST_PORT_RE.match(text)
        ):
>>>>>>> cb0e666d1b4161a0efb8a8176648128a77dbfb7d
            scheme = m.group(1).lower()
            has_explicit_scheme = True
            is_opaque = True
            authority_source = "none"
            remainder = text[m.end():]
        else:
            authority_source = "implied"

    if is_opaque:
        opaque_fragment = "#" in remainder
        if opaque_fragment:
            remainder, fragment = remainder.split("#", 1)
        else:
            fragment = ""
        if "?" in remainder:
            remainder, query = remainder.split("?", 1)
        else:
            query = ""
        return ParsedURL(
            raw=url, scheme=scheme, authority_source="none", userinfo="",
            host="", host_ascii="", port=None, port_valid=True,
            path=remainder, query=query, fragment=fragment, host_kind="empty",
            is_protocol_relative=False, has_explicit_scheme=True,
            is_opaque_scheme=True, has_fragment=opaque_fragment,
        )

    # Authority ends at the first of / ? #  (RFC 3986 section 3.2)
    end = len(remainder)
    for delim in "/?#":
        pos = remainder.find(delim)
        if pos >= 0:
            end = min(end, pos)
    authority, rest = remainder[:end], remainder[end:]

    has_fragment = "#" in rest
    fragment = query = ""
    if has_fragment:
        rest, fragment = rest.split("#", 1)
    if "?" in rest:
        rest, query = rest.split("?", 1)

    userinfo, host, port, port_valid = _split_authority(authority)
    host = host.lower()
    had_trailing_dot = host.endswith(".") and len(host) > 1
    if had_trailing_dot:
        host = host[:-1]

    return ParsedURL(
        raw=url,
        scheme=scheme,
        authority_source=authority_source,
        userinfo=userinfo,
        host=host,
        host_ascii=_to_ascii(host),
        port=port,
        port_valid=port_valid,
        path=rest,
        query=query,
        fragment=fragment,
        host_kind=_classify_host(host),
        is_protocol_relative=is_protocol_relative,
        has_explicit_scheme=has_explicit_scheme,
        is_opaque_scheme=False,
        host_had_trailing_dot=had_trailing_dot,
        has_fragment=has_fragment,
    )


def default_port_for(scheme: str) -> int | None:
    """Return the well-known port for ``scheme`` or ``None``."""
    return _DEFAULT_PORTS.get(scheme)
