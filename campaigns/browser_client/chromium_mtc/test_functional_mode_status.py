import json
import tempfile
import unittest
from pathlib import Path

import browser_validation as bv


class FunctionalModeStatusTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def add_result(self, stamp, mode, *, passed=True, result_mode=None):
        root = (self.repo / 'artifacts/results' /
                ('chromium-browser-validation-' + stamp))
        case = root / 'mtc-positive'
        case.mkdir(parents=True)
        evidence = {}
        for name in ('netlog.json', 'server.log', 'chromium.stdout.log',
                     'chromium.stderr.log'):
            path = case / name
            path.write_text('', encoding='utf-8')
            evidence[name] = str(path)
        (root / 'summary.json').write_text(json.dumps({
            'mtc_trust_mode': mode,
            'overall_pass': passed,
        }), encoding='utf-8')
        (root / 'credentials.json').write_text(json.dumps({
            'mtc': {'mode': mode},
        }), encoding='utf-8')
        result = {
            'name': 'mtc-positive',
            'mtc_trust_mode': result_mode or mode,
            'pass': passed,
            'observed_outcome': 'PASS' if passed else 'FAIL',
            'reason': None if passed else 'synthetic failure',
            'evidence': evidence,
        }
        for field in (
                'server_authentication_flight_observed',
                'server_finished_observed', 'client_finished_observed',
                'application_data_observed', 'requested_tai_observed',
                'selected_tai_observed', 'negotiated_canonical_tls'):
            result[field] = passed
        (case / 'result.json').write_text(json.dumps(result), encoding='utf-8')

    def test_standalone_pass_does_not_complete_landmark(self):
        self.add_result('20261008T190000Z-standalone', 'standalone')

        self.assertEqual(('PASS', None),
                         bv.functional_mode_status(self.repo, 'standalone'))
        self.assertEqual(('NOT RUN', None),
                         bv.functional_mode_status(self.repo, 'landmark'))

    def test_modes_use_their_own_latest_evidence(self):
        self.add_result('20261008T190000Z-landmark', 'landmark')
        self.add_result('20261008T200000Z-standalone', 'standalone')

        self.assertEqual(('PASS', None),
                         bv.functional_mode_status(self.repo, 'landmark'))
        self.assertEqual(('PASS', None),
                         bv.functional_mode_status(self.repo, 'standalone'))

    def test_latest_failure_only_affects_its_mode(self):
        self.add_result('20261008T180000Z-landmark', 'landmark')
        self.add_result('20261008T190000Z-standalone', 'standalone')
        self.add_result('20261008T200000Z-landmark', 'landmark', passed=False)

        landmark, reason = bv.functional_mode_status(self.repo, 'landmark')
        self.assertEqual('FAIL', landmark)
        self.assertIn('incomplete', reason)
        self.assertEqual(('PASS', None),
                         bv.functional_mode_status(self.repo, 'standalone'))

    def test_mode_mismatch_fails_closed(self):
        self.add_result('20261008T190000Z-landmark', 'landmark',
                        result_mode='standalone')

        status, reason = bv.functional_mode_status(self.repo, 'landmark')
        self.assertEqual('FAIL', status)
        self.assertIn('Result mode does not match summary', reason)


if __name__ == '__main__':
    unittest.main()
