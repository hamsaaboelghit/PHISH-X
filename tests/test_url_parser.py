"""Edge cases for the legacy splitter and the strict parser."""

import pytest

from phishx.features.url_parser import (
    UrlParseError,
    legacy_split,
    normalize_url_text,
    parse_ipv4_whatwg,
    parse_url,
)

# --------------------------------------------------------------- legacy_split


class TestLegacySplit:
    def test_full_url(self):
        p = legacy_split("https://www.example.com/a/b.php?x=1&y=2#frag")
        assert (p.scheme, p.netloc) == ("https", "www.example.com")
        assert (p.path, p.query, p.fragment) == ("/a/b.php", "x=1&y=2", "frag")

    def test_scheme_is_lowercased(self):
        assert legacy_split("HTTPS://a.com").scheme == "https"

    def test_schemeless_url_has_empty_netloc(self):
        """Dataset quirk: without '//' the whole string is the path."""
        p = legacy_split("example.com/login")
        assert p.scheme == "" and p.netloc == ""
        assert p.path == "example.com/login"

    def test_protocol_relative(self):
        p = legacy_split("//example.com/a")
        assert p.scheme == "" and p.netloc == "example.com" and p.path == "/a"

    def test_host_with_port_scheme_less_is_scheme_when_rest_not_digits(self):
        p = legacy_split("example.com:8080/p")
        assert p.scheme == "example.com" and p.path == "8080/p"

    def test_all_digit_remainder_is_not_a_scheme(self):
        p = legacy_split("localhost:8080")
        assert p.scheme == "" and p.path == "localhost:8080"

    def test_params_split_for_http(self):
        p = legacy_split("http://a.com/x;p=1?q=1")
        assert (p.path, p.params, p.query) == ("/x", "p=1", "q=1")

    def test_params_only_on_last_segment(self):
        assert legacy_split("http://a.com/x;p/y").path == "/x;p/y"

    def test_fragment_split_before_query(self):
        p = legacy_split("http://a.com/#frag?x")
        assert p.fragment == "frag?x" and p.query == ""

    def test_tabs_and_newlines_removed_leading_junk_stripped(self):
        p = legacy_split("  \x00http://a.c\to\nm/p")
        assert p.netloc == "a.com" and p.path == "/p"

    def test_userinfo_and_port_stay_in_netloc(self):
        assert legacy_split("http://u:p@h.com:81/").netloc == "u:p@h.com:81"

    @pytest.mark.parametrize("bad", ["http://[::1/", "http://::1]/"])
    def test_unbalanced_brackets_raise(self, bad):
        with pytest.raises(UrlParseError):
            legacy_split(bad)

    @pytest.mark.parametrize("bad", [None, 5, b"http://a.com", ["x"]])
    def test_non_string_raises_parse_error(self, bad):
        with pytest.raises(UrlParseError):
            legacy_split(bad)


# ---------------------------------------------------------------- parse_url


class TestStrictParser:
    def test_full_decomposition(self):
        p = parse_url("http://user:pw@Host.Example:8443/p?q=1#f")
        assert p.scheme == "http"
        assert p.userinfo == "user:pw"
        assert p.host == "host.example"
        assert p.port == 8443 and p.port_valid
        assert (p.path, p.query, p.fragment) == ("/p", "q=1", "f")
        assert p.authority_source == "explicit"
        assert p.host_kind == "domain"
        assert p.labels == ("host", "example")

    def test_schemeless_gets_implied_authority(self):
        p = parse_url("example.com/login")
        assert p.authority_source == "implied"
        assert p.host == "example.com" and p.path == "/login"
        assert not p.has_explicit_scheme

    def test_schemeless_with_port(self):
        p = parse_url("example.com:8080/p")
        assert p.host == "example.com" and p.port == 8080

    def test_protocol_relative(self):
        p = parse_url("//Example.com/a")
        assert p.is_protocol_relative and p.host == "example.com"
        assert p.scheme == ""

    def test_single_slash_and_backslash_are_repaired_like_browsers(self):
        assert parse_url("http:/example.com/a").host == "example.com"
        assert parse_url("http:\\\\evil.com\\x").host == "evil.com"
        assert parse_url("http:\\\\evil.com\\x").path == "/x"

    def test_trailing_dot_removed_and_flagged(self):
        p = parse_url("http://example.com./")
        assert p.host == "example.com" and p.host_had_trailing_dot

    @pytest.mark.parametrize(
        "url", ["mailto:a@b.example", "javascript:alert(1)", "data:text/html,hi"]
    )
    def test_opaque_schemes_have_no_host(self, url):
        p = parse_url(url)
        assert p.is_opaque_scheme and p.host == "" and p.host_kind == "empty"

    # ---- IP addresses
    def test_ipv4(self):
        assert parse_url("http://127.0.0.1/").host_kind == "ipv4"

    def test_ipv6_with_port(self):
        p = parse_url("http://[2001:db8::1]:8080/x")
        assert p.host == "2001:db8::1" and p.host_kind == "ipv6"
        assert p.port == 8080

    @pytest.mark.parametrize(
        "host, dotted",
        [
            ("2130706433", "127.0.0.1"),
            ("0x7f.1", "127.0.0.1"),
            ("0177.0.0.1", "127.0.0.1"),
            ("1.2.3", "1.2.0.3"),
            ("0x7f000001", "127.0.0.1"),
        ],
    )
    def test_obfuscated_ipv4_forms(self, host, dotted):
        assert parse_ipv4_whatwg(host) == dotted
        assert parse_url(f"http://{host}/").host_kind == "ipv4_obfuscated"

    @pytest.mark.parametrize(
        "host", ["256.1.1.1", "example.com", "1.2.3.4.5", "", "a.b.c.1x"]
    )
    def test_not_ipv4(self, host):
        assert parse_ipv4_whatwg(host) is None

    # ---- ports
    def test_invalid_port(self):
        p = parse_url("http://a.com:99999/")
        assert p.port is None and not p.port_valid

    def test_empty_port_is_valid(self):
        p = parse_url("http://a.com:/")
        assert p.port is None and p.port_valid

    # ---- IDN
    def test_unicode_host_gets_ascii_form(self):
        p = parse_url("http://bücher.example/")
        assert p.host == "bücher.example"
        assert p.host_ascii == "xn--bcher-kva.example"

    def test_punycode_host_is_kept(self):
        assert parse_url("http://xn--bcher-kva.example/").host_ascii == (
            "xn--bcher-kva.example"
        )

    # ---- errors
    @pytest.mark.parametrize("bad", ["", "   ", "\t\n", None, 42, b"x"])
    def test_empty_or_non_string_raises(self, bad):
        with pytest.raises(UrlParseError):
            parse_url(bad)

    @pytest.mark.parametrize("bad", ["http://[::1", "http://[::1]x/"])
    def test_broken_ipv6_raises(self, bad):
        with pytest.raises(UrlParseError):
            parse_url(bad)

    def test_deceptive_userinfo_host_is_the_part_after_last_at(self):
        p = parse_url("http://paypal.com@evil.example/login")
        assert p.userinfo == "paypal.com" and p.host == "evil.example"



def test_strict_parser_rejects_invalid_bracketed_hosts_and_unbracketed_ipv6():
    for bad in (
        "http://[::gg]/",
        "http://[not-an-ip]/",
        "http://2001:db8::1/",
        "http://a.com:80:90/",
        "http://[::1]]/",
    ):
        with pytest.raises(UrlParseError):
            parse_url(bad)


def test_very_long_port_is_invalid_without_raising():
    p = parse_url("http://a.com:" + "9" * 5000 + "/")
    assert p.port is None and not p.port_valid


def test_fragment_delimiter_is_preserved_when_fragment_is_empty():
    p = parse_url("http://a.com/#")
    assert p.fragment == "" and p.has_fragment


def test_opaque_scheme_query_and_fragment_are_split():
    p = parse_url("javascript:alert(1)?x=2#frag")
    assert p.is_opaque_scheme
    assert p.path == "alert(1)" and p.query == "x=2"
    assert p.fragment == "frag" and p.has_fragment


@pytest.mark.parametrize("url", ["javascript:123", "data:123"])
def test_numeric_known_opaque_schemes_are_not_host_ports(url):
    parsed = parse_url(url)
    assert parsed.is_opaque_scheme
    assert parsed.authority_source == "none"
    assert parsed.host == "" and parsed.port is None
    assert parsed.path == "123"


def test_known_opaque_scheme_is_case_insensitive():
    assert parse_url("JAVASCRIPT:123").is_opaque_scheme


@pytest.mark.parametrize("url,host,port", [
    ("example.com:8080", "example.com", 8080),
    ("localhost:8080", "localhost", 8080),
])
def test_schemeless_host_port_is_preserved(url, host, port):
    parsed = parse_url(url)
    assert not parsed.is_opaque_scheme
    assert parsed.authority_source == "implied"
    assert parsed.host == host and parsed.port == port


def test_parser_normalization_helper_matches_strict_parser():
    raw = "  http://exa\\nmple.com/\\tlogin  "
    assert normalize_url_text(raw) == "http://example.com/login"
    assert parse_url(raw).host == "example.com"
