"""Advisory security signals (not model features)."""

import pytest

from phishx.features.url_signals import analyze_url_security as analyze


def test_deceptive_userinfo():
    s = analyze("http://paypal.com@evil.example/login")
    assert s.has_userinfo and s.userinfo_contains_dot
    assert s.host == "evil.example"


def test_nondefault_port():
    assert analyze("http://a.com:8080/").has_nondefault_port
    assert not analyze("http://a.com:80/").has_nondefault_port
    assert not analyze("https://a.com:443/").has_nondefault_port
    assert not analyze("http://a.com/").has_nondefault_port


<<<<<<< HEAD
=======
def test_invalid_port_is_visible_and_not_read_as_default():
    """An invalid port must be surfaced, not mistaken for a safe default."""
    s = analyze("http://a.com:99999/")
    assert s.parsed and not s.port_valid
    assert s.has_invalid_port
    assert not s.has_nondefault_port  # invalid != default, but also != nondefault
    assert s.port is None
    # A valid default port is neither invalid nor nondefault.
    ok = analyze("http://a.com:80/")
    assert not ok.has_invalid_port and not ok.has_nondefault_port
    # No port at all is neither invalid nor nondefault.
    none = analyze("http://a.com/")
    assert not none.has_invalid_port and not none.has_nondefault_port


def test_signals_use_parser_normalisation_for_raw_text_checks():
    """Tabs/newlines deleted by the parser must not hide a double scheme."""
    assert analyze("http://ht\ttp://evil.example/").double_scheme
    assert analyze("http://http://evil.example/").double_scheme
    assert not analyze("http://a.com/").double_scheme


>>>>>>> cb0e666d1b4161a0efb8a8176648128a77dbfb7d
def test_punycode_and_unicode_host():
    assert analyze("http://xn--pple-43d.com").has_punycode_label
    s = analyze("http://bücher.example/")
    assert s.has_non_ascii_host and not s.has_punycode_label


def test_host_kinds():
    assert analyze("http://1.2.3.4/").host_kind == "ipv4"
    assert analyze("http://[::1]/").host_kind == "ipv6"
    assert analyze("http://0x7f.1/").host_kind == "ipv4_obfuscated"
    assert analyze("http://example.com/").host_kind == "domain"


def test_double_scheme_and_embedded_url():
    assert analyze("http://http://1.2.3.4/a").double_scheme
    assert not analyze("http://a.com/").double_scheme
    assert analyze("http://a.com/r?u=http://other.example").embedded_url_in_path_or_query
    assert not analyze("http://a.com/plain").embedded_url_in_path_or_query


def test_percent_escapes():
    s = analyze("http://a.com/%41%2f?x=%zz")
    assert s.percent_escape_count == 2
    assert not s.percent_escape_in_host


def test_schemeless_and_protocol_relative_and_opaque():
    assert analyze("example.com/x").authority_source == "implied"
    assert analyze("//example.com/x").is_protocol_relative
    s = analyze("javascript:alert(1)")
    assert s.is_opaque_scheme and s.host_kind == "empty"


def test_trailing_dot_host():
    assert analyze("http://example.com./").has_trailing_dot_host
    assert not analyze("http://example.com/").has_trailing_dot_host


@pytest.mark.parametrize("bad", ["", "  ", None, 5, "http://[::1", b"x"])
def test_failures_are_reported_not_raised(bad):
    s = analyze(bad)
    assert not s.parsed and s.error


def test_as_dict_has_all_fields():
    d = analyze("http://a.com").as_dict()
    assert d["parsed"] is True and "host_kind" in d



def test_double_scheme_is_only_detected_at_url_prefix():
    assert analyze("http://http://evil.example/").double_scheme
    s = analyze("http://a.com/path/http://evil.example/")
    assert not s.double_scheme
    assert s.embedded_url_in_path_or_query


def test_empty_fragment_is_detected_for_hierarchical_and_opaque_urls():
    assert analyze("http://a.com/#").has_fragment
    assert analyze("javascript:alert(1)#frag").has_fragment
    assert not analyze("http://a.com/").has_fragment


@pytest.mark.parametrize(
    "bad",
    [
        "http://[::gg]/",
        "http://[not-an-ip]/",
        "http://2001:db8::1/",
        "http://a.com:80:90/",
        "http://[::1]]/",
    ],
)
def test_invalid_host_authority_is_rejected(bad):
    assert not analyze(bad).parsed
