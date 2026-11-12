"""Extractor contract: values (hand-computed), structure, robustness."""

import json
import math

import pytest

from phishx.features.url_features import (
    FEATURE_NAMES,
    FeatureExtractionError,
    extract_features,
    extract_features_batch,
)


def feats(url):
    r = extract_features(url)
    assert r.ok, (url, r.status)
    return r.features


# ------------------------------------------------------- structure / contract


def test_there_are_exactly_16_features_in_dataset_order():
    assert FEATURE_NAMES == (
        "url_length", "has_ip_address", "dot_count", "https_flag",
        "url_entropy", "token_count", "subdomain_count", "query_param_count",
        "tld_length", "path_length", "has_hyphen_in_domain",
        "number_of_digits", "tld_popularity", "suspicious_file_extension",
        "domain_name_length", "percentage_numeric_chars",
    )


@pytest.mark.parametrize(
    "value",
    ["http://a.com", "", "   ", None, 7, b"x", "http://[::1", "x" * 20000],
)
def test_structure_is_identical_for_every_input(value):
    r = extract_features(value)
    assert tuple(r.features) == FEATURE_NAMES
    assert isinstance(r.warnings, tuple)


def test_extraction_is_deterministic():
    a = extract_features("http://a.example.com/x?y=1")
    b = extract_features("http://a.example.com/x?y=1")
    assert a == b


def test_to_vector_matches_name_order():
    r = extract_features("http://a.com/")
    assert r.to_vector() == [r.features[n] for n in FEATURE_NAMES]
    assert len(r.to_vector()) == 16


def test_to_vector_refuses_failed_extraction():
    with pytest.raises(FeatureExtractionError):
        extract_features("").to_vector()


def test_as_dict_is_json_serialisable_even_on_failure():
    json.dumps(extract_features("http://a.com").as_dict(), allow_nan=False)
    json.dumps(extract_features(None).as_dict(), allow_nan=False)


def test_batch_preserves_order():
    out = extract_features_batch(["http://a.com", "", "http://b.org"])
    assert [r.status for r in out] == ["ok", "empty", "ok"]


# ------------------------------------------------------------ hand-computed


def test_full_url_values():
    f = feats("https://www.example.com/a/b.php?x=1&y=2#frag")
    assert f["url_length"] == 44
    assert f["has_ip_address"] == 0
    assert f["dot_count"] == 3
    assert f["https_flag"] == 1
    assert f["token_count"] == 12  # 3 dots + 4 '/' + '?' + 2 '=' + '&' + 1
    assert f["subdomain_count"] == 1
    assert f["query_param_count"] == 2
    assert f["tld_length"] == 3
    assert f["path_length"] == 8
    assert f["has_hyphen_in_domain"] == 0
    assert f["number_of_digits"] == 2
    assert f["tld_popularity"] == 1
    assert f["suspicious_file_extension"] == 0
    assert f["domain_name_length"] == 7
    assert math.isclose(f["percentage_numeric_chars"], 2 / 44 * 100)


def test_ipv4_host_with_port_and_exe():
    f = feats("http://192.168.0.1:8080/login.exe")
    assert f["url_length"] == 33
    assert f["has_ip_address"] == 1
    assert f["dot_count"] == 4
    assert f["https_flag"] == 0
    assert f["subdomain_count"] == 2
    # legacy: the port text is part of the last label "1:8080"
    assert f["tld_length"] == 6
    assert f["domain_name_length"] == 1
    assert f["tld_popularity"] == 0
    assert f["number_of_digits"] == 12
    assert f["suspicious_file_extension"] == 1
    assert f["path_length"] == 10


def test_entropy_of_uniform_and_constant_strings():
    assert feats("aaaa")["url_entropy"] == 0.0
    # "ab" repeated: two symbols, equal frequency -> exactly 1 bit
    assert math.isclose(feats("abab")["url_entropy"], 1.0)


# --------------------------------------------------------- scheme variations


def test_schemeless_url_legacy_behaviour_and_warning():
    r = extract_features("example.com/login")
    f = r.features
    assert f["subdomain_count"] == -1
    assert f["tld_length"] == 0 and f["domain_name_length"] == 0
    assert f["tld_popularity"] == 0 and f["has_hyphen_in_domain"] == 0
    assert f["https_flag"] == 0
    assert f["path_length"] == len("example.com/login")
    assert "no_authority" in r.warnings


def test_protocol_relative_url():
    f = feats("//example.com/a")
    assert f["subdomain_count"] == 0
    assert f["tld_length"] == 3 and f["domain_name_length"] == 7
    assert f["tld_popularity"] == 1 and f["https_flag"] == 0


def test_scheme_and_tld_case_insensitive():
    f = feats("HTTPS://Example.COM/")
    assert f["https_flag"] == 1 and f["tld_popularity"] == 1


def test_uppercase_digit_url_keeps_string_features_case_sensitive():
    assert feats("http://A.com")["dot_count"] == 1


# ----------------------------------------------------------------- hosts/IPs


def test_ipv6_literal_not_detected_by_legacy_ip_feature():
    r = extract_features("http://[2001:db8::1]:8080/x")
    assert r.features["has_ip_address"] == 0
    assert "ipv6_not_detected" in r.warnings


def test_obfuscated_ipv4_not_detected_by_legacy_ip_feature():
    r = extract_features("http://2130706433/")
    assert r.features["has_ip_address"] == 0
    assert "obfuscated_ipv4_not_detected" in r.warnings


def test_ip_pattern_in_path_triggers_legacy_flag_with_warning():
    r = extract_features("http://example.com/dl/1.2.3.4/file")
    assert r.features["has_ip_address"] == 1
    assert "ip_pattern_outside_host" in r.warnings


def test_version_number_is_a_known_false_positive():
    r = extract_features("https://github.com/x/releases/download/v0.4.5.10/t.zip")
    assert r.features["has_ip_address"] == 1
    assert "ip_pattern_outside_host" in r.warnings


def test_three_group_dotted_number_is_not_ip():
    assert feats("http://example.com/1.2.3")["has_ip_address"] == 0


def test_hyphen_only_counts_in_netloc_not_path():
    assert feats("http://a-b.com/")["has_hyphen_in_domain"] == 1
    assert feats("http://ab.com/a-b")["has_hyphen_in_domain"] == 0


def test_userinfo_is_part_of_legacy_host():
    r = extract_features("http://paypal.com@evil.example/")
    assert "host_contains_userinfo" in r.warnings
    assert r.features["tld_length"] == 7  # "example"


def test_single_label_host():
    r = extract_features("http://localhost/x")
    assert r.features["subdomain_count"] == -1
    assert r.features["tld_length"] == r.features["domain_name_length"] == 9
    assert "single_label_host" in r.warnings


def test_deep_subdomains():
    assert feats("http://a.b.c.d.example.com/")["subdomain_count"] == 4


# ------------------------------------------------------- query / path / ext


def test_query_param_count_rules():
    assert feats("http://a.com/")["query_param_count"] == 1  # legacy minimum
    assert feats("http://a.com/?")["query_param_count"] == 1
    assert feats("http://a.com/?a=1")["query_param_count"] == 1
    assert feats("http://a.com/?a=1&b=2")["query_param_count"] == 2
    assert feats("http://a.com/?a=1&&b=2")["query_param_count"] == 3


def test_path_excludes_query_fragment_and_params():
    assert feats("http://a.com/p;x=1?q=2#f")["path_length"] == 2


@pytest.mark.parametrize(
    "url, expected",
    [
        ("http://a.com/setup.exe", 1),
        ("http://a.com/setup.EXE", 1),
        ("http://a.com/setup.exe?x=1", 1),
        ("http://a.com/setup.exe#f", 1),
        ("http://a.com/a.zip", 1),
        ("http://a.com/bin", 1),  # legacy: suffix match without dot
        ("http://a.com/readme-for-js", 1),  # legacy false positive
        ("http://a.com/x.apk", 1),
        ("http://a.com/x.cmd", 1),
        ("http://a.com/x.js", 1),
        ("http://a.com/x.bat", 0),  # not in the dataset list
        ("http://a.com/x.dll", 0),
        ("http://a.com/exe/index.html", 0),
        ("http://a.com/x.exe/", 0),
        ("http://a.com/?file=x.exe", 0),  # query is not the path
    ],
)
def test_suspicious_extension_rules(url, expected):
    assert feats(url)["suspicious_file_extension"] == expected


@pytest.mark.parametrize(
    "url, expected",
    [
        ("http://a.com", 1), ("http://a.org", 1), ("http://a.net", 1),
        ("http://a.edu", 1), ("http://a.gov", 1),
        ("http://a.io", 0), ("http://a.co.uk", 0), ("http://a.xyz", 0),
        ("http://a.com:8080/", 0),  # legacy: port glued to last label
    ],
)
def test_tld_popularity_list(url, expected):
    assert feats(url)["tld_popularity"] == expected


# ------------------------------------------------------------- IDN / unusual


def test_idn_unicode_host_counts_code_points():
    f = feats("http://bücher.example/")
    assert f["domain_name_length"] == 6 and f["tld_length"] == 7


def test_punycode_host():
    f = feats("http://xn--bcher-kva.example/")
    assert f["domain_name_length"] == 13


def test_percent_encoding_is_not_decoded():
    f = feats("http://a.com/%41%42")
    assert f["path_length"] == 7 and f["number_of_digits"] == 4


def test_double_scheme_dataset_pattern():
    r = extract_features("http://http://comodozeropoint.com/a.exe")
    assert r.features["tld_length"] == 5  # host is "http:"
    assert r.features["domain_name_length"] == 5
    assert r.features["subdomain_count"] == -1


def test_whitespace_around_url_is_stripped():
    assert extract_features("  http://a.com/  ") == extract_features("http://a.com/")


# --------------------------------------------------------------- robustness


@pytest.mark.parametrize(
    "bad, status",
    [
        ("", "empty"), ("   \t\n", "empty"),
        (None, "invalid_type"), (123, "invalid_type"),
        (b"http://a.com", "invalid_type"), (["http://a.com"], "invalid_type"),
        ("http://[::1", "malformed"), ("http://::1]/", "malformed"),
    ],
)
def test_bad_inputs_fail_cleanly(bad, status):
    r = extract_features(bad)
    assert not r.ok and r.status == status
    assert all(math.isnan(v) for v in r.features.values())


def test_too_long_input_rejected():
    r = extract_features("http://a.com/" + "a" * 9000)
    assert r.status == "too_long"
    assert extract_features("http://a.com/" + "a" * 50, max_length=20).status == "too_long"


@pytest.mark.parametrize(
    "weird",
    [
        "\x00", "http://", "://", "http:///", "@@@", "//", "///", "?", "#",
        "http://:@:/", "http://a.com:99999999999999999999/",
        "http://[", "javascript:alert(1)", "data:text/html,<b>x</b>",
        "http://\u202eevil.com", "http://a.com/\ud800", "http://a.com/\u0000",
        "http://" + "a." * 3000 + "com", "%" * 500, "😀😀😀",
    ],
)
def test_weird_inputs_never_raise(weird):
    r = extract_features(weird)
    assert tuple(r.features) == FEATURE_NAMES
    if r.ok:
        assert all(not math.isnan(v) for v in r.features.values())



def test_extractor_survives_very_long_port_and_reports_invalid_port():
    r = extract_features("http://a.com:" + "9" * 5000 + "/")
    assert r.ok
    assert "host_contains_port" in r.warnings


@pytest.mark.parametrize("bad", ["http://[::1]]/", "http://a.com]]/"])
def test_legacy_parser_rejects_unbalanced_closing_brackets(bad):
    r = extract_features(bad)
    assert not r.ok and r.status == "malformed"
