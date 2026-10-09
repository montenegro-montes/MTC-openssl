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
        fixture = self.repo/'artifacts/x509'/fixture_set/profile/f'd{depth}'
        fixture.mkdir(parents=True)
        for name, data in [('server.pem', b'server'), ('server.key', b'key'),
                           ('root.pem', b'root')]:
            (fixture/name).write_bytes(data)
        names = ['server.pem', 'server.key', 'root.pem']
        if depth > 2:
            (fixture/'intermediates.pem').write_bytes(b'intermediate')
            names.append('intermediates.pem')
        saved = {name: bv.sha(fixture/name) for name in names}
        manifest = dict(fixture_set=fixture_set, profile=profile, family_id=profile,
                        depth=depth, hostname=bv.HOST, files_sha256=saved,
                        server_key_sha256=saved['server.key'], root_der_sha256='root-der')
        bv.write(fixture/'manifest.json', manifest)
        if corrupt:
            (fixture/'server.pem').write_bytes(b'corrupt')
        return fixture

    def mtc(self, name, profile='ecdsa-p256', anchor=None,
            trust_mode='landmark'):
        fixture = self.repo/'artifacts/mtc'/name
        fixture.mkdir()
        bv.write(fixture/'manifest.json', dict(
            server_hostname=bv.HOST, profiles=[profile], sizes=[16],
            test_content_identity=name))
        evidence = fixture.with_name(fixture.name+'-validation')/'validation.json'
        evidence.parent.mkdir()
        bv.write(evidence, {'passed': True})
        suffix = ('-chromium-anchor-standalone.json'
                  if trust_mode == 'standalone'
                  else '-chromium-anchor.json')
        canonical = fixture.with_name(fixture.name+suffix)
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

    def test_exact_formal_x509_d3_is_selected_without_docker(self):
        fixture = self.x509(depth=3)
        with patch.object(bv, 'certificate_sha256', return_value='root-der'), \
             patch.object(bv.cryptography_x509, 'load_pem_x509_certificate') as load, \
             patch.object(bv, 'docker_openssl') as docker:
            certificate = load.return_value
            certificate.public_key.return_value = bv.ec.generate_private_key(
                bv.ec.SECP256R1()).public_key()
            certificate.signature_algorithm_oid.dotted_string = '1.2.840.10045.4.3.2'
            selected = bv.precheck_formal_x509_fixture(
                self.repo, 'ecdsa-p256', 3, 'chromium-x509-depth-matrix-v1')
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

        def local(fixture, validation, profile, trust_mode='landmark'):
            return dict(fixture=str(Path(fixture).resolve()), trust='trust.bin',
                        validation_sha256=bv.sha(validation), profile=profile,
                        mode=trust_mode)

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
        local = lambda fixture, validation, profile, trust_mode='landmark': dict(
            fixture=str(Path(fixture).resolve()), trust='trust.bin',
            validation_sha256=bv.sha(validation), profile=profile,
            mode=trust_mode)
        with patch.object(bv, 'prevalidated_mtc', side_effect=local), \
             patch.object(bv, 'expected_anchor', return_value={'anchor': 'exact'}), \
             patch.object(bv, 'docker_openssl') as docker:
            with self.assertRaisesRegex(ValueError, 'No locally valid MTC fixture'):
                bv.preselect_mtc_fixture(self.repo, 'ecdsa-p256')
        docker.assert_not_called()

    def test_landmark_and_standalone_use_distinct_validated_anchors(self):
        expected = {'anchor': 'exact'}
        fixture, evidence = self.mtc(
            'both-modes', anchor=expected, trust_mode='standalone')
        bv.write(fixture.with_name(fixture.name+'-chromium-anchor.json'), expected)

        def local(path, validation, profile, trust_mode='landmark'):
            self.assertEqual(Path(path), fixture)
            self.assertEqual(Path(validation), evidence)
            return dict(fixture=str(fixture.resolve()), trust='trust.bin',
                        validation_sha256=bv.sha(validation), profile=profile,
                        mode=trust_mode)

        with patch.object(bv, 'prevalidated_mtc', side_effect=local), \
             patch.object(bv, 'expected_anchor', return_value=expected):
            landmark, _ = bv.preselect_mtc_fixture(
                self.repo, 'ecdsa-p256', 'landmark')
            standalone, _ = bv.preselect_mtc_fixture(
                self.repo, 'ecdsa-p256', 'standalone')
        self.assertEqual(landmark['mode'], 'landmark')
        self.assertEqual(standalone['mode'], 'standalone')
        self.assertTrue(landmark['anchor'].endswith('-chromium-anchor.json'))
        self.assertTrue(standalone['anchor'].endswith(
            '-chromium-anchor-standalone.json'))

    def test_setup_selection_allows_only_a_missing_canonical_anchor(self):
        expected = {'anchor': 'exact'}
        fixture, _ = self.mtc('standalone-needs-anchor')

        def local(path, validation, profile, trust_mode='landmark'):
            return dict(fixture=str(Path(path).resolve()), trust='trust.bin',
                        validation_sha256=bv.sha(validation), profile=profile,
                        mode=trust_mode)

        with patch.object(bv, 'prevalidated_mtc', side_effect=local), \
             patch.object(bv, 'expected_anchor', return_value=expected):
            selected, audit = bv.preselect_mtc_fixture(
                self.repo, 'ecdsa-p256', 'standalone',
                require_anchor=False)
        self.assertEqual(Path(selected['fixture']), fixture.resolve())
        self.assertNotIn('anchor', selected)
        self.assertEqual(audit[0]['anchor_status'], 'MISSING')

    def test_setup_selection_rejects_conflicting_anchor(self):
        self.mtc('standalone-conflict', anchor={'wrong': True},
                 trust_mode='standalone')
        local = lambda fixture, validation, profile, trust_mode='landmark': dict(
            fixture=str(Path(fixture).resolve()), trust='trust.bin',
            validation_sha256=bv.sha(validation), profile=profile,
            mode=trust_mode)
        with patch.object(bv, 'prevalidated_mtc', side_effect=local), \
             patch.object(bv, 'expected_anchor', return_value={'anchor': 'exact'}):
            with self.assertRaisesRegex(
                    ValueError, 'content/provenance mismatch'):
                bv.preselect_mtc_fixture(
                    self.repo, 'ecdsa-p256', 'standalone',
                    require_anchor=False)

    def test_measurement_selection_still_requires_canonical_anchor(self):
        self.mtc('standalone-no-anchor')
        local = lambda fixture, validation, profile, trust_mode='landmark': dict(
            fixture=str(Path(fixture).resolve()), trust='trust.bin',
            validation_sha256=bv.sha(validation), profile=profile,
            mode=trust_mode)
        with patch.object(bv, 'prevalidated_mtc', side_effect=local), \
             patch.object(bv, 'expected_anchor', return_value={'anchor': 'exact'}):
            with self.assertRaisesRegex(ValueError,
                                        'Missing canonical Chromium MTC anchor'):
                bv.preselect_mtc_fixture(
                    self.repo, 'ecdsa-p256', 'standalone')

    def test_optimized_setup_allows_standalone_without_explicit_fixture(self):
        self.assertTrue(bv.standalone_operation_allowed(
            'credentials', None, None, True))
        self.assertFalse(bv.standalone_operation_allowed(
            'run', 'mtc-positive', None, False))
        self.assertFalse(bv.standalone_operation_allowed(
            'run', 'mtc-bad-merkle', self.repo/'fixture', False))

    def test_optimized_setup_exports_only_missing_standalone_anchor(self):
        output = self.repo/'output'; output.mkdir()
        fixture = self.repo/'artifacts/mtc/standalone'; fixture.mkdir()
        validation = fixture.with_name(
            fixture.name+'-validation')/'validation.json'
        validation.parent.mkdir(); bv.write(validation, {'passed': True})
        mtc = dict(fixture=str(fixture),
                   validation_evidence=str(validation), mode='standalone',
                   ca_id='32473.101', requested_tai='32473.101.2.1.0',
                   selected_tai='32473.101')
        root = self.repo/'root.pem'; root.write_text('root')
        x509 = dict(root=str(root), root_sha256=bv.sha(root),
                    fixture=str(self.repo/'x509'))
        anchor = self.repo/'canonical-standalone.json'
        anchor.write_text('{}')
        anchor_data = dict(anchor=str(anchor), anchor_sha256=bv.sha(anchor),
                           anchor_origin='generated')
        with patch.object(bv, 'preselect_mtc_fixture',
                          return_value=(mtc.copy(), [])) as select, \
             patch.object(bv, 'prevalidated_mtc',
                          return_value=mtc.copy()), \
             patch.object(bv, 'choose_anchor',
                          return_value=anchor_data) as choose, \
             patch.object(bv, 'generate_mtc') as generate, \
             patch.object(bv, 'precheck_formal_x509_fixture',
                          return_value=self.repo/'x509'), \
             patch.object(bv, 'validate_x509', return_value=x509), \
             patch.object(bv, 'root_trust', return_value={'status': 'TEST'}):
            result = bv.prepare_credentials(
                self.repo, output, 'image', profile='ecdsa-p384', depth=2,
                x509_fixture_set='chromium-x509-depth-matrix-v1',
                optimized_all_profiles=True,
                mtc_trust_mode='standalone')
        select.assert_called_once_with(
            self.repo, 'ecdsa-p384', 'standalone', require_anchor=False)
        choose.assert_called_once()
        generate.assert_not_called()
        self.assertEqual(result['mtc']['anchor'], str(anchor))

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

    def test_openssl_batch_runs_every_check_in_one_ephemeral_container(self):
        root = bv.REPO/'.mt-state/chromium-tmp'; root.mkdir(parents=True, exist_ok=True)
        calls = []
        def command(args, **kwargs):
            calls.append(list(map(str, args)))
            return SimpleNamespace(returncode=0, stdout='ok', stderr='')
        with tempfile.TemporaryDirectory(dir=root) as directory, \
             patch.object(bv, 'command', side_effect=command):
            with bv.DockerOpenSSLBatch('image') as openssl:
                for args in (['version'], ['x509', '-help'], ['verify', 'cert.pem']):
                    self.assertEqual(openssl(directory, args, 'image').stdout, 'ok')
                self.assertEqual(openssl.check_count, 3)
        self.assertEqual(sum(call[:3] == ['docker', 'run', '-d'] for call in calls), 1)
        self.assertEqual(sum(call[:2] == ['docker', 'exec'] for call in calls), 3)
        self.assertEqual(sum(call[:3] == ['docker', 'rm', '-f'] for call in calls), 1)

    def test_openssl_batch_identifies_intermediate_failure_and_code(self):
        root = bv.REPO/'.mt-state/chromium-tmp'; root.mkdir(parents=True, exist_ok=True)
        calls = []
        def command(args, **kwargs):
            args = list(map(str, args)); calls.append(args)
            if args[:2] == ['docker', 'exec'] and 'verify' in args:
                raise ValueError('Command failed (7): synthetic verify')
            return SimpleNamespace(returncode=0, stdout='ok', stderr='')
        with tempfile.TemporaryDirectory(dir=root) as directory, \
             patch.object(bv, 'command', side_effect=command):
            with self.assertRaisesRegex(
                    ValueError, r'check #2 failed: verify cert.pem: Command failed \(7\)'):
                with bv.DockerOpenSSLBatch('image') as openssl:
                    openssl(directory, ['version'], 'image')
                    openssl(directory, ['verify', 'cert.pem'], 'image')
                    openssl(directory, ['x509', '-help'], 'image')
        self.assertEqual(sum(call[:2] == ['docker', 'exec'] for call in calls), 2)
        self.assertEqual(sum(call[:3] == ['docker', 'rm', '-f'] for call in calls), 1)

    def test_openssl_batch_rejects_directory_outside_workspace(self):
        def command(args, **kwargs):
            return SimpleNamespace(returncode=0, stdout='ok', stderr='')
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(bv, 'command', side_effect=command):
            with bv.DockerOpenSSLBatch('image') as openssl:
                with self.assertRaisesRegex(ValueError, 'outside the isolated workspace'):
                    openssl(directory, ['version'], 'image')

    def test_individual_docker_openssl_path_is_unchanged(self):
        result = SimpleNamespace(returncode=0, stdout='ok', stderr='')
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(bv, 'command', return_value=result) as command:
            self.assertIs(bv.docker_openssl(directory, ['version'], 'image'), result)
        invocation = command.call_args.args[0]
        self.assertEqual(invocation[:3], ['docker', 'run', '--rm'])
        self.assertEqual(invocation[-2:], ['image', 'version'])


if __name__ == '__main__':
    unittest.main()
