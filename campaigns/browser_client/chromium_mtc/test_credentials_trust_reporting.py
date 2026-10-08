"""Offline tests for credentials trust reporting; no policy or trust changes."""
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    'browser_validation_credentials_trust_test', HERE / 'browser_validation.py')
bv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bv)


class CredentialsTrustReportingTests(unittest.TestCase):
    @staticmethod
    def mtc():
        return dict(fixture='/mtc/profile', ca_id='32473.101',
                    selected_tai='32473.101.1.1.1',
                    requested_tai='32473.101.2.1.1')

    def policy(self, effect):
        with patch.object(bv, 'chromium_ca_policy', side_effect=effect) as policy, \
             patch.object(bv, 'command') as command:
            report = bv.chromium_ca_policy_report('/fixture/root.pem')
        policy.assert_called_once_with('/fixture/root.pem')
        command.assert_not_called()
        return report

    def output(self, system_status, policy_status):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            bv.print_credentials_trust(
                {'status': system_status}, {'status': policy_status})
        return stream.getvalue()

    def test_root_present_in_policy_is_trusted(self):
        metadata = dict(policy_applied=True, policy_sources=['managed-policy'],
                        certificate_verification_bypass=False)
        report = self.policy(lambda _root: metadata)
        self.assertEqual(report['status'], 'TRUSTED')
        self.assertTrue(report['policy_applied'])
        self.assertEqual(report['policy_sources'], ['managed-policy'])

    def test_root_absent_is_informatively_untrusted(self):
        report = self.policy(ValueError('policy does not contain selected root'))
        self.assertEqual(report['status'], 'UNTRUSTED_OR_UNAVAILABLE')
        self.assertFalse(report['policy_applied'])
        self.assertIn('does not contain', report['error'])

    def test_required_policy_keeps_missing_root_fail_closed(self):
        with patch.object(bv, 'chromium_ca_policy',
                          side_effect=ValueError('policy does not contain selected root')):
            with self.assertRaisesRegex(ValueError, 'does not contain'):
                bv.chromium_ca_policy_report('/fixture/root.pem', required=True)

    def test_formal_d2_fixture_is_reused_with_exact_validation_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            output = repo / 'output'; output.mkdir()
            fixture = repo / 'artifacts/x509/chromium-x509-depth-matrix-v1/ecdsa-p256/d2'
            fixture.mkdir(parents=True)
            root = fixture / 'root.pem'; root.write_bytes(b'root')
            selected = dict(fixture=str(fixture.resolve()), root=str(root.resolve()),
                            root_sha256=bv.sha(root), profile='ecdsa-p256', depth=2,
                            fixture_set='chromium-x509-depth-matrix-v1')

            def discover(paths, validator):
                self.assertEqual(paths, [fixture])
                return validator(fixture), []

            validate = Mock(return_value=selected)
            with patch.object(bv, 'select_or_generate', return_value=(self.mtc(), [])), \
                 patch.object(bv, 'choose_anchor', return_value={}), \
                 patch.object(bv, 'x509_paths', return_value=[fixture]), \
                 patch.object(bv, 'discover', side_effect=discover), \
                 patch.object(bv, 'validate_x509', validate), \
                 patch.object(bv, 'root_trust', return_value={'status': 'UNTRUSTED'}), \
                 patch.object(bv, 'generate_x509') as generate:
                credentials = bv.prepare_credentials(
                    repo, output, 'image', profile='ecdsa-p256', depth=2,
                    x509_fixture_set='chromium-x509-depth-matrix-v1')
            validate.assert_called_once_with(
                fixture, profile='ecdsa-p256', depth=2, image='image',
                fixture_set='chromium-x509-depth-matrix-v1')
            generate.assert_not_called()
            self.assertEqual(credentials['x509']['fixture'], str(fixture.resolve()))
            self.assertEqual(credentials['x509']['origin'], 'reused-formal-fixture-set')

    def test_missing_formal_d2_fixture_fails_without_generation(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            output = repo / 'output'; output.mkdir()
            with patch.object(bv, 'select_or_generate', return_value=(self.mtc(), [])), \
                 patch.object(bv, 'choose_anchor', return_value={}), \
                 patch.object(bv, 'x509_paths', return_value=[]), \
                 patch.object(bv, 'discover', return_value=(None, [])), \
                 patch.object(bv, 'generate_x509') as generate:
                with self.assertRaisesRegex(
                        ValueError,
                        'fixture_set=chromium-x509-depth-matrix-v1, profile=ecdsa-p256, depth=2'):
                    bv.prepare_credentials(
                        repo, output, 'image', profile='ecdsa-p256', depth=2,
                        x509_fixture_set='chromium-x509-depth-matrix-v1')
            generate.assert_not_called()

    def test_untrusted_system_and_trusted_policy_are_reported_separately(self):
        output = self.output('UNTRUSTED_OR_UNAVAILABLE', 'TRUSTED')
        self.assertIn('X509 system root trust:         UNTRUSTED_OR_UNAVAILABLE', output)
        self.assertIn('Chromium CACertificates policy: TRUSTED', output)

    def test_trusted_system_and_absent_policy_are_reported_separately(self):
        output = self.output('TRUSTED', 'UNTRUSTED_OR_UNAVAILABLE')
        self.assertIn('X509 system root trust:         TRUSTED', output)
        self.assertIn('Chromium CACertificates policy: UNTRUSTED_OR_UNAVAILABLE', output)

    def test_platform_handling_remains_delegated_to_policy_function(self):
        for system in ('Darwin', 'Linux'):
            with self.subTest(system=system), \
                 patch.object(bv.platform, 'system', return_value=system), \
                 patch.object(bv, 'chromium_ca_policy',
                              return_value={'policy_applied': True}) as policy:
                self.assertEqual(
                    bv.chromium_ca_policy_report('/fixture/root.pem')['status'], 'TRUSTED')
                policy.assert_called_once_with('/fixture/root.pem')


if __name__ == '__main__':
    unittest.main()
