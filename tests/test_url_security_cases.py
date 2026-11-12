"""Offline tests of EXISTING audit helpers plus the production contract.
Run: python -m unittest discover -s tests -v

The characterization tests below document current audit-helper behavior
only; passing them does not approve that behavior as production behavior.
The 28 synthetic cases in ``tests/cases/url_security_cases.json`` exercise
the OLD audit helpers (``subdomain_audit``), NOT the new production
parser/extractor. Production acceptance is asserted separately in
``test_production_feature_contract`` against the shared extractor
``phishx.features.url_features`` (contract confirmed by Eiad's review of
``origin/eyad``; see ``docs/EIAD_SECURITY_TEST_HANDOFF.md``).

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

    def test_production_feature_contract(self):
        """Production extractor contract (Eiad-confirmed, origin/eyad review).

        Shared extractor: ``phishx.features.url_features``.
        Interface: ``extract_features(url) -> UrlFeatures`` and
        ``extract_features_batch(urls) -> list[UrlFeatures]``.
        Feature order/semantics: the 16 dataset features in
        ``FEATURE_NAMES`` order (spec version ``1.0-legacy``).

<<<<<<< Updated upstream
=======
        The extractor ALWAYS returns all 16 features. A model-side
        subset (e.g. a 5-feature baseline) is a training-time selection
        by name from ``FEATURE_NAMES`` — it is not a competing extractor
        and must not redefine any feature. This test therefore pins the
        16-feature extractor contract; which subset the AI team trains
        on remains a model decision outside this contract.
        """
        from phishx.features.url_features import (
            FEATURE_NAMES,
            FEATURE_SPEC_VERSION,
            FeatureExtractionError,
            extract_features,
            extract_features_batch,
        )

        # --- module / version / feature order -------------------------
        self.assertEqual(FEATURE_SPEC_VERSION, '1.0-legacy')
        self.assertEqual(
            FEATURE_NAMES,
            (
                'url_length', 'has_ip_address', 'dot_count', 'https_flag',
                'url_entropy', 'token_count', 'subdomain_count',
                'query_param_count', 'tld_length', 'path_length',
                'has_hyphen_in_domain', 'number_of_digits',
                'tld_popularity', 'suspicious_file_extension',
                'domain_name_length', 'percentage_numeric_chars',
            ),
        )
        self.assertEqual(len(FEATURE_NAMES), 16)

        # --- happy path: structure, order, hand-computed values -------
        result = extract_features('http://a.com/')
        self.assertTrue(result.ok)
        self.assertEqual(tuple(result.features), FEATURE_NAMES)
        self.assertEqual(len(result.to_vector()), 16)
        self.assertEqual(
            result.to_vector(),
            [result.features[name] for name in FEATURE_NAMES],
        )
        expected = {
            'url_length': 13,
            'has_ip_address': 0,
            'dot_count': 1,
            'https_flag': 0,
            'token_count': 5,  # 1 + 1 '.' + 3 '/'
            'subdomain_count': 0,
            'query_param_count': 1,  # minimum is 1, never 0
            'tld_length': 3,
            'path_length': 1,
            'has_hyphen_in_domain': 0,
            'number_of_digits': 0,
            'tld_popularity': 1,
            'suspicious_file_extension': 0,
            'domain_name_length': 1,
            'percentage_numeric_chars': 0.0,
        }
        for name, value in expected.items():
            with self.subTest(feature=name):
                self.assertEqual(result.features[name], value)

        # --- determinism ----------------------------------------------
        again = extract_features('http://a.com/')
        self.assertEqual(result, again)

        # --- batch preserves order ------------------------------------
        batch = extract_features_batch(['http://a.com/', 'https://b.org/x'])
        self.assertEqual(len(batch), 2)
        self.assertTrue(all(r.ok for r in batch))
        self.assertEqual(batch[0], result)

        # --- failure contract: invalid must not mean legitimate -------
        for bad in ['', '   ', None, 7, b'http://a.com']:
            with self.subTest(bad=repr(bad)):
                failed = extract_features(bad)
                self.assertFalse(failed.ok)
                with self.assertRaises(FeatureExtractionError):
                    failed.to_vector()


>>>>>>> Stashed changes
if __name__ == '__main__':
    unittest.main()
