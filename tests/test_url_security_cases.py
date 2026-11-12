"""Offline tests of EXISTING audit helpers, not production extractor acceptance.
Run: python -m unittest discover -s tests -v
Production feature assertions await Eiad's contract (see handoff document).

Characterization tests below document current audit-helper behavior only;
passing them does not approve that behavior as production behavior.
Network access is blocked for every test (see setUp).
"""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from phishx.features.subdomain_audit import parse_hostname, is_ip_address, analyze_subdomain

CASES = json.loads((ROOT / 'tests/cases/url_security_cases.json').read_text())


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
        # not be treated as valid hosts.
        for value in [None, 123, 12.5, '', '   ', 'Offline', 'offline',
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


if __name__ == '__main__':
    unittest.main()
