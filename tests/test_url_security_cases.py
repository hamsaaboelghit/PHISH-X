"""Offline tests of EXISTING audit helpers, not production extractor acceptance.
Run: python -m unittest discover -s tests -v
Production feature assertions await Eiad's contract (see handoff document).
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
    def test_existing_hostname_helper(self):
        with patch('socket.getaddrinfo', side_effect=AssertionError('Network forbidden')), \
             patch('socket.socket', side_effect=AssertionError('Network forbidden')):
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
        for case in CASES:
            self.assertEqual(parse_hostname(case['url']), parse_hostname(case['url']))

    @unittest.skip('Blocked: Eiad must confirm shared extractor module, interface and feature semantics.')
    def test_production_feature_contract(self):
        """Intentionally no invented import, adapter, or competing implementation."""


if __name__ == '__main__':
    unittest.main()
