"""Offline tests of EXISTING audit helpers, not production extractor acceptance.
Run: python -m unittest discover -s tests -v
Production feature assertions await Eiad's contract (see handoff document).

Characterization tests below document current audit-helper behavior only;
passing them does not approve that behavior as production behavior.
Network access is blocked for every test (see setUp).
"""
import json
import math
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from phishx.features.subdomain_audit import parse_hostname, is_ip_address, analyze_subdomain
from phishx.security_dataset_audit import (
    summarize,
    validate_dataframe,
    _safe_parse_hostname,
)

CASES = json.loads(
    (ROOT / 'tests/cases/url_security_cases.json').read_text(encoding='utf-8')
)


class URLSecurityCases(unittest.TestCase):
    def setUp(self):
        # Block all network access during every parser/extractor test.
        self._getaddrinfo_patcher = patch(
            'socket.getaddrinfo',
            side_effect=AssertionError('Network forbidden'),
        )
        self._socket_patcher = patch(
            'socket.socket',
            side_effect=AssertionError('Network forbidden'),
        )
        self._getaddrinfo_patcher.start()
        self._socket_patcher.start()
        self.addCleanup(self._socket_patcher.stop)
        self.addCleanup(self._getaddrinfo_patcher.stop)

    def test_existing_hostname_helper(self):
        # Characterization only: documents current parse_hostname /
        # is_ip_address behavior on the 28 synthetic cases.
        for case in CASES:
            with self.subTest(case=case['id']):
                self.assertEqual(parse_hostname(case['url']), case['host'])
                self.assertEqual(is_ip_address(parse_hostname(case['url'])), case['ip'])

    def test_existing_preliminary_subdomain_definition(self):
        # Characterization only: helper explicitly does not implement PSL semantics.
        for url, expected in [('https://a.b.example.com/', 2),
                              ('http://192.0.2.10/', 0),
                              ('http://[2001:db8::1]/', 0),
                              ('Offline', None), (None, None)]:
            with self.subTest(url=url):
                self.assertEqual(analyze_subdomain(url), expected)

    def test_helper_determinism(self):
        # Determinism against expected values (not a tautology):
        # repeated calls must return the same result AND match the
        # documented expected host/IP for every case.
        for case in CASES:
            with self.subTest(case=case['id']):
                first = parse_hostname(case['url'])
                second = parse_hostname(case['url'])
                third = parse_hostname(case['url'])
                self.assertEqual(first, second)
                self.assertEqual(second, third)
                self.assertEqual(first, case['host'])
                self.assertEqual(is_ip_address(first), case['ip'])
                # Subdomain helper must also be stable across calls.
                self.assertEqual(
                    analyze_subdomain(case['url']),
                    analyze_subdomain(case['url']),
                )
        # Known subdomain values stay stable and exact.
        for url, expected in [('https://a.b.example.com/', 2),
                              ('http://192.0.2.10/', 0),
                              ('http://[2001:db8::1]/', 0)]:
            with self.subTest(url=url):
                self.assertEqual(analyze_subdomain(url), expected)
                self.assertEqual(analyze_subdomain(url), expected)

    def test_missing_and_invalid_inputs(self):
        # Missing / non-string / sentinel inputs must not raise and must
        # not be treated as valid hosts. parse_hostname must return None
        # for every non-string type, including NaN, bool, bytes and
        # containers, without raising.
        for value in [None, 123, 12.5, float('nan'), True,
                      b'https://example.com/', ['https://example.com/'],
                      {'url': 'https://example.com/'},
                      '', '   ', 'Offline', 'offline',
                      'OFFLINE', 'http://[2001:db8::1/']:
            with self.subTest(value=repr(value)):
                self.assertIsNone(parse_hostname(value))
                self.assertFalse(is_ip_address(parse_hostname(value)))
                self.assertIsNone(analyze_subdomain(value))
        # is_ip_address itself is safe on missing / non-IP input.
        for value in [None, '', 'example.com', '3221225994', '192.000.002.010']:
            with self.subTest(value=repr(value)):
                self.assertFalse(is_ip_address(value))
        for value in ['192.0.2.10', '2001:db8::1']:
            with self.subTest(value=value):
                self.assertTrue(is_ip_address(value))

    def test_parser_input_safety(self):
        # Task 3: existing-helper safety review only. Expected behavior:
        # invalid inputs return None (host/subdomain) or False (IP),
        # never raise, and never produce a valid-looking host.
        # 1. None
        for func in (parse_hostname, analyze_subdomain):
            self.assertIsNone(func(None))
        self.assertFalse(is_ip_address(None))
        # 2. Integer and float inputs (direct calls, not via parse).
        for value in (123, 0, 12.5, float('nan'), True, False):
            with self.subTest(value=repr(value)):
                self.assertIsNone(parse_hostname(value))
                self.assertIsNone(analyze_subdomain(value))
                self.assertFalse(is_ip_address(value))
        # 3. Empty and whitespace strings.
        for value in ('', '   ', '\t\n '):
            with self.subTest(value=repr(value)):
                self.assertIsNone(parse_hostname(value))
                self.assertIsNone(analyze_subdomain(value))
                self.assertFalse(is_ip_address(parse_hostname(value)))
        # 4. "Offline" in every capitalization variation.
        for value in ('Offline', 'offline', 'OFFLINE', 'OfFlInE',
                      'oFfLiNe', '  Offline  '):
            with self.subTest(value=repr(value)):
                self.assertIsNone(parse_hostname(value))
                self.assertIsNone(analyze_subdomain(value))
        # 5. Malformed URLs: no crash, no valid host.
        for value in ('http://[2001:db8::1/', 'http://[::1',
                      'https://', '://', 'http://'):
            with self.subTest(value=repr(value)):
                self.assertIsNone(parse_hostname(value))
                self.assertIsNone(analyze_subdomain(value))
                self.assertFalse(is_ip_address(parse_hostname(value)))
        # 6. Correct IPv4 and IPv6.
        for url, host in [('http://192.0.2.10/', '192.0.2.10'),
                          ('http://[2001:db8::1]/', '2001:db8::1'),
                          ('https://[2001:db8::1]:443/a', '2001:db8::1')]:
            with self.subTest(url=url):
                self.assertEqual(parse_hostname(url), host)
                self.assertTrue(is_ip_address(parse_hostname(url)))
                self.assertEqual(analyze_subdomain(url), 0)
        # 7. Invalid inputs never become a legitimate-looking host:
        # every invalid value above yields None/False, asserted inline.
        # Documented existing behaviors (characterization, not changed):
        # out-of-range port still yields a host; embedded newline is
        # stripped by urlsplit. Production must reject these explicitly.
        self.assertEqual(
            parse_hostname('https://example.com:99999/'), 'example.com')
        self.assertEqual(
            parse_hostname('https://exa\nmple.com/'), 'example.com')

    def test_normalization(self):
        # Current helper normalization, characterized explicitly so any
        # future change is a deliberate, reviewed decision.
        cases = [
            ('HTTPS://EXAMPLE.COM./', 'example.com'),
            ('  https://Example.COM/path  ', 'example.com'),
            ('example.com/path', 'example.com'),
            ('//example.com/path', 'example.com'),
            ('https://example.com@other.example/login', 'other.example'),
            ('https://a.b.example.com/', 'a.b.example.com'),
            ('http://192.0.2.10/', '192.0.2.10'),
            ('http://[2001:db8::1]/', '2001:db8::1'),
        ]
        for url, expected_host in cases:
            with self.subTest(url=url):
                self.assertEqual(parse_hostname(url), expected_host)
                # Normalization is deterministic.
                self.assertEqual(parse_hostname(url), expected_host)

    def test_cases_file_integrity(self):
        # Schema check for the synthetic cases file itself (not a
        # production extractor assertion).
        self.assertEqual(len(CASES), 28)
        ids = [case['id'] for case in CASES]
        self.assertEqual(len(ids), len(set(ids)), 'case ids must be unique')
        for case in CASES:
            with self.subTest(case=case.get('id')):
                for key in ('id', 'category', 'url', 'host', 'ip', 'expected'):
                    self.assertIn(key, case)
                self.assertIsInstance(case['id'], str)
                self.assertTrue(case['id'])
                self.assertIsInstance(case['category'], str)
                self.assertTrue(case['category'])
                self.assertIsInstance(case['expected'], str)
                self.assertTrue(case['expected'])
                self.assertIsInstance(case['ip'], bool)
                self.assertTrue(
                    case['host'] is None or isinstance(case['host'], str),
                    'host must be a string or null',
                )

    @unittest.skip('Blocked: Eiad must confirm shared extractor module, interface and feature semantics.')
    def test_production_feature_contract(self):
        """Intentionally no invented import, adapter, or competing implementation."""


def _audit_frame(labels, urls=None):
    """Minimal valid audit frame (both classes unless labels say otherwise)."""
    n = len(labels)
    urls = urls if urls is not None else ['https://example.com/'] * n
    return pd.DataFrame({
        'URL': urls,
        'ClassLabel': labels,
        'subdomain_count': [0] * n,
        'tld_length': [3] * n,
        'domain_name_length': [7] * n,
        'has_ip_address': [0] * n,
    })


class SecurityDatasetAuditValidation(unittest.TestCase):
    def setUp(self):
        # Block all network access during every audit test as well.
        self._getaddrinfo_patcher = patch(
            'socket.getaddrinfo',
            side_effect=AssertionError('Network forbidden'),
        )
        self._socket_patcher = patch(
            'socket.socket',
            side_effect=AssertionError('Network forbidden'),
        )
        self._getaddrinfo_patcher.start()
        self._socket_patcher.start()
        self.addCleanup(self._socket_patcher.stop)
        self.addCleanup(self._getaddrinfo_patcher.stop)

    def test_audit_requires_both_classes(self):
        # A single-class frame must raise instead of emitting NaN
        # class percentages.
        for labels in ([0, 0], [1, 1], [0.0, 0.0], [1.0, 1.0]):
            with self.subTest(labels=labels):
                with self.assertRaises(ValueError):
                    validate_dataframe(_audit_frame(labels))
                with self.assertRaises(ValueError):
                    summarize(_audit_frame(labels))
        # Both classes present (int or float labels) must pass.
        for labels in ([0, 1], [0.0, 1.0]):
            with self.subTest(labels=labels):
                validate_dataframe(_audit_frame(labels))
                summarize(_audit_frame(labels))

    def test_audit_rejects_empty_dataset(self):
        # Empty frame with required columns: both classes missing.
        empty_with_columns = _audit_frame([]).iloc[0:0]
        with self.assertRaises(ValueError):
            validate_dataframe(empty_with_columns)
        with self.assertRaises(ValueError):
            summarize(empty_with_columns)
        # Empty frame without any columns: required columns missing.
        with self.assertRaises(ValueError):
            validate_dataframe(pd.DataFrame())
        with self.assertRaises(ValueError):
            summarize(pd.DataFrame())

    def test_audit_handles_non_string_urls_safely(self):
        # The audit must not pass raw non-string values to parse_hostname
        # and must not raise on them; they count as missing hosts.
        df = _audit_frame(
            [0, 1, 0, 1, 0, 1],
            urls=['https://example.com/', None, 123, float('nan'),
                  b'https://example.com/', 'http://192.0.2.10/'],
        )
        result = summarize(df)
        self.assertEqual(result['url_type_audit']['string_count'], 2)
        self.assertEqual(result['url_type_audit']['missing_count'], 2)
        self.assertEqual(
            result['url_type_audit']['non_string_non_missing_count'], 2)
        # 4 of 6 rows have no parsed host (None, 123, NaN, bytes).
        self.assertEqual(
            result['cohorts']['missing_host']['0']['count'], 2)
        self.assertEqual(
            result['cohorts']['missing_host']['1']['count'], 2)
        # The safe wrapper itself never forwards non-strings.
        for value in [None, 123, float('nan'), b'x', ['a'], {'a': 1}, True]:
            with self.subTest(value=repr(value)):
                self.assertIsNone(_safe_parse_hostname(value))
        self.assertEqual(
            _safe_parse_hostname('https://Example.COM./'), 'example.com')

    def test_audit_class_percent_never_nan(self):
        result = summarize(_audit_frame([0, 1, 0, 1]))
        for name, per_label in result['cohorts'].items():
            for label, values in per_label.items():
                with self.subTest(cohort=name, label=label):
                    self.assertTrue(
                        math.isfinite(values['class_percent']),
                        f'{name}/{label} class_percent must be finite',
                    )
        # Strict JSON serialization must succeed (allow_nan=False raises
        # if any NaN/Infinity leaked into the output).
        json.dumps(result, allow_nan=False)


if __name__ == '__main__':
    unittest.main()
