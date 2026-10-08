"""Offline all-profile fixture preselection tests; Docker is always mocked."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    'browser_validation_preselection_test', HERE/'browser_validation.py')
bv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bv)


class CredentialPreselectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        (self.repo/'artifacts/mtc').mkdir(parents=True)

    def x509(self, profile='ecdsa-p256', *, fixture_set='chromium-x509-depth-matrix-v1',
             depth=2, corrupt=False):
        fixture = self.repo/'artifacts/x509'/fixture_set/profile/'d2'
        fixture.mkdir(parents=True)
        for name, data in [('server.pem', b'server'), ('server.key', b'key'),
                           ('root.pem', b'root')]:
            (fixture/name).write_bytes(data)
        saved = {name: bv.sha(fixture/name) for name in ('server.pem', 'server.key', 'root.pem')}
        manifest = dict(fixture_set=fixture_set, profile=profile, family_id=profile,
                        depth=depth, hostname=bv.HOST, files_sha256=saved,
                        server_key_sha256=saved['server.key'], root_der_sha256='root-der')
        bv.write(fixture/'manifest.json', manifest)
        if corrupt:
            (fixture/'server.pem').write_bytes(b'corrupt')
        return fixture

    def mtc(self, name, profile='ecdsa-p256', anchor=None):
        fixture = self.repo/'artifacts/mtc'/name
        fixture.mkdir()
        bv.write(fixture/'manifest.json', dict(
            server_hostname=bv.HOST, profiles=[profile], sizes=[16],
            test_content_identity=name))
        evidence = fixture.with_name(fixture.name+'-validation')/'validation.json'
        evidence.parent.mkdir()
        bv.write(evidence, {'passed': True})
        canonical = fixture.with_name(fixture.name+'-chromium-anchor.json')
        if anchor is not None:
            bv.write(canonical, anchor)
        return fixture, evidence

    def test_exact_formal_x509_d2_is_selected_without_docker(self):
        fixture = self.x509()
        with patch.object(bv, 'certificate_sha256', return_value='root-der'), \
             patch.object(bv.cryptography_x509, 'load_pem_x509_certificate') as load, \
             patch.object(bv, 'docker_openssl') as docker:
            certificate = load.return_value
            certificate.public_key.return_value = bv.ec.generate_private_key(
                bv.ec.SECP256R1()).public_key()
            certificate.signature_algorithm_oid.dotted_string = '1.2.840.10045.4.3.2'
            selected = bv.precheck_formal_x509_fixture(
                self.repo, 'ecdsa-p256', 2, 'chromium-x509-depth-matrix-v1')
        self.assertEqual(selected, fixture)
        docker.assert_not_called()

    def test_formal_x509_missing_or_bad_hash_fails_before_docker(self):
        with patch.object(bv, 'docker_openssl') as docker:
            with self.assertRaisesRegex(ValueError, 'Missing formal X509'):
                bv.precheck_formal_x509_fixture(
                    self.repo, 'ecdsa-p256', 2, 'chromium-x509-depth-matrix-v1')
            fixture = self.x509(corrupt=True)
            with self.assertRaisesRegex(ValueError, 'Stale fixture hash'):
                bv.precheck_formal_x509_fixture(
                    self.repo, 'ecdsa-p256', 2, 'chromium-x509-depth-matrix-v1')
        self.assertTrue(fixture.exists())
        docker.assert_not_called()

    def test_formal_x509_wrong_profile_fails_before_docker(self):
        self.x509(profile='ecdsa-p256')
        with patch.object(bv, 'docker_openssl') as docker:
            with self.assertRaisesRegex(ValueError, 'Missing formal X509'):
                bv.precheck_formal_x509_fixture(
                    self.repo, 'ecdsa-p384', 2, 'chromium-x509-depth-matrix-v1')
        docker.assert_not_called()

    def test_mldsa_precheck_without_public_key_algorithm_oid(self):
        oids = {'mldsa44': '2.16.840.1.101.3.4.3.17',
                'mldsa65': '2.16.840.1.101.3.4.3.18',
                'mldsa87': '2.16.840.1.101.3.4.3.19'}
        for profile, oid in oids.items():
            with self.subTest(profile=profile):
                fixture = self.x509(profile=profile)
                certificate = SimpleNamespace(
                    signature_algorithm_oid=SimpleNamespace(dotted_string=oid))
                with patch.object(bv, 'certificate_sha256', return_value='root-der'), \
                     patch.object(bv.cryptography_x509, 'load_pem_x509_certificate',
                                  return_value=certificate), \
                     patch.object(bv, 'docker_openssl') as docker:
                    selected = bv.precheck_formal_x509_fixture(
                        self.repo, profile, 2, 'chromium-x509-depth-matrix-v1')
                self.assertEqual(selected, fixture)
                docker.assert_not_called()

    def test_mtc_selection_is_content_deterministic_and_ignores_discarded_crypto(self):
        expected = {'anchor': 'exact'}
        fixtures = [self.mtc('z-later-looking', anchor=expected),
                    self.mtc('a-earlier-looking', anchor=expected)]

        def local(fixture, validation, profile):
            return dict(fixture=str(Path(fixture).resolve()), trust='trust.bin',
                        validation_sha256=bv.sha(validation), profile=profile)

        with patch.object(bv, 'prevalidated_mtc', side_effect=local), \
             patch.object(bv, 'expected_anchor', return_value=expected), \
             patch.object(bv, 'docker_openssl') as docker:
            selected, _ = bv.preselect_mtc_fixture(self.repo, 'ecdsa-p256')
        identities = {bv.sha(fixture/'manifest.json'): fixture.resolve()
                      for fixture, _ in fixtures}
        self.assertEqual(Path(selected['fixture']), identities[min(identities)])
        docker.assert_not_called()

    def test_missing_or_incompatible_canonical_anchor_is_rejected(self):
        self.mtc('missing-anchor')
        self.mtc('wrong-anchor', anchor={'wrong': True})
        local = lambda fixture, validation, profile: dict(
            fixture=str(Path(fixture).resolve()), trust='trust.bin',
            validation_sha256=bv.sha(validation), profile=profile)
        with patch.object(bv, 'prevalidated_mtc', side_effect=local), \
             patch.object(bv, 'expected_anchor', return_value={'anchor': 'exact'}), \
             patch.object(bv, 'docker_openssl') as docker:
            with self.assertRaisesRegex(ValueError, 'No locally valid MTC fixture'):
                bv.preselect_mtc_fixture(self.repo, 'ecdsa-p256')
        docker.assert_not_called()

    def test_selected_mtc_crypto_failure_has_no_fallback(self):
        output = self.repo/'output'; output.mkdir()
        selected = dict(fixture='/selected/fixture', ca_id='32473.101',
                        selected_tai='selected', requested_tai='requested',
                        anchor='/selected/anchor', anchor_sha256='a'*64,
                        anchor_origin='reused')
        validate = Mock(side_effect=ValueError('cryptographic failure'))
        with patch.object(bv, 'preselect_mtc_fixture', return_value=(selected, [])), \
             patch.object(bv, 'validate_mtc', validate), \
             patch.object(bv, 'select_or_generate') as fallback:
            with self.assertRaisesRegex(ValueError, 'cryptographic failure'):
                bv.prepare_credentials(
                    self.repo, output, 'image', profile='ecdsa-p256', depth=2,
                    x509_fixture_set='chromium-x509-depth-matrix-v1',
                    optimized_all_profiles=True)
        validate.assert_called_once_with(Path('/selected/fixture'), 'ecdsa-p256', 'image')
        fallback.assert_not_called()


if __name__ == '__main__':
    unittest.main()
