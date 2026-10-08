"""Fast offline checks for browser-measurement fixture fallback."""
import importlib.util
import ast
import csv
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch


REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    'browser_validation_measurement_fixture_test',
    REPO/'campaigns/browser_client/chromium_mtc/browser_validation.py')
bv = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bv)
MEASUREMENTS_SPEC = importlib.util.spec_from_file_location(
    'browser_measurements_fixture_preflight_test',
    REPO/'campaigns/browser_client/chromium_mtc/browser_measurements.py')
measurements = importlib.util.module_from_spec(MEASUREMENTS_SPEC)
MEASUREMENTS_SPEC.loader.exec_module(measurements)


class BrowserMeasurementFixtureSelectionTests(unittest.TestCase):
    def test_measurements_default_to_formal_x509_fixture_set(self):
        path = REPO/'campaigns/browser_client/chromium_mtc/browser_measurements.py'
        tree = ast.parse(path.read_text())
        assignments = {
            node.targets[0].id: ast.literal_eval(node.value)
            for node in tree.body
            if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == 'FORMAL_X509_FIXTURE_SET'
        }
        self.assertEqual(assignments['FORMAL_X509_FIXTURE_SET'],
                         'chromium-x509-depth-matrix-v1')
        text = path.read_text()
        self.assertIn("if args.action == 'run' and args.x509_fixture_set is None:", text)
        self.assertIn('args.x509_fixture_set = FORMAL_X509_FIXTURE_SET', text)

    def test_missing_formal_fixture_fails_reuse_only_without_generation(self):
        with patch.object(measurements.bv, 'precheck_formal_x509_fixture',
                          side_effect=ValueError('missing exact cell')), \
             patch.object(measurements, 'existing_mtc', return_value={'profile': 'ecdsa-p256'}), \
             patch.object(measurements.bv, 'generate_x509') as generate:
            with self.assertRaisesRegex(ValueError,
                    r'fixture_set=chromium-x509-depth-matrix-v1, profile=ecdsa-p256, depth=3.*reuse-only/fail-closed.*generate-matrix'):
                measurements.profile_run_preconditions(
                    REPO, 'unused-image', 'ecdsa-p256', 3,
                    measurements.FORMAL_X509_FIXTURE_SET)
            generate.assert_not_called()

    def test_run_aborts_before_capture_and_result_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            preflight = Mock(side_effect=ValueError('formal fixture missing'))
            argv = ['browser_measurements.py', 'run', '--pairs', '1',
                    '--profile', 'ecdsa-p256', '--depth', '3']
            with patch.object(measurements.sys, 'argv', argv), \
                 patch.object(measurements.bv, 'REPO', repo), \
                 patch.object(measurements, 'campaign_preconditions', preflight), \
                 patch.object(measurements.pcap, 'requirements') as requirements:
                with self.assertRaisesRegex(ValueError, 'formal fixture missing'):
                    measurements.main()
            self.assertEqual(preflight.call_args.args[-1],
                             measurements.FORMAL_X509_FIXTURE_SET)
            requirements.assert_not_called()
            self.assertFalse((repo/'artifacts/results').exists())

    def test_policy_failure_precedes_measurement_setup(self):
        selected = dict(fixture='/formal/d3', root='/formal/d3/root.pem', root_sha256='a'*64)
        with patch.object(measurements.bv, 'precheck_formal_x509_fixture',
                          return_value=Path('/formal/d3')), \
             patch.object(measurements.bv, 'validate_x509', return_value=selected), \
             patch.object(measurements, 'existing_mtc', return_value={'profile': 'ecdsa-p256'}), \
             patch.object(measurements.bv, 'chromium_ca_policy',
                          side_effect=ValueError('policy lacks selected root')) as policy:
            with self.assertRaisesRegex(ValueError, 'policy lacks selected root'):
                measurements.profile_run_preconditions(
                    REPO, 'unused-image', 'ecdsa-p256', 3,
                    measurements.FORMAL_X509_FIXTURE_SET)
            policy.assert_called_once_with('/formal/d3/root.pem')

    def test_formal_fixture_and_policy_allow_preflight_to_continue(self):
        selected = dict(fixture='/formal/d3', root='/formal/d3/root.pem', root_sha256='a'*64)
        metadata = dict(x509_trust_mode='chromium-ca-policy',
                        certificate_verification_bypass=False,
                        policy_root_der_sha256='b'*64)
        with patch.object(measurements.bv, 'precheck_formal_x509_fixture',
                          return_value=Path('/formal/d3')) as precheck, \
             patch.object(measurements.bv, 'validate_x509', return_value=selected) as validate, \
             patch.object(measurements, 'existing_mtc', return_value={'profile': 'ecdsa-p256'}), \
             patch.object(measurements.bv, 'chromium_ca_policy', return_value=metadata):
            actual = measurements.profile_run_preconditions(
                REPO, 'unused-image', 'ecdsa-p256', 3,
                measurements.FORMAL_X509_FIXTURE_SET)
        self.assertEqual(actual, ({'mtc': {'profile': 'ecdsa-p256'}, 'x509': selected}, metadata))
        precheck.assert_called_once_with(
            REPO, 'ecdsa-p256', 3, measurements.FORMAL_X509_FIXTURE_SET)
        validate.assert_called_once_with(
            Path('/formal/d3'), profile='ecdsa-p256', depth=3,
            image='unused-image', fixture_set=measurements.FORMAL_X509_FIXTURE_SET)

    def test_existing_mtc_preselects_locally_and_validates_only_selected_fixture(self):
        selected = dict(fixture='/mtc/selected', anchor='/mtc/anchor.json',
                        anchor_sha256='a'*64, anchor_origin='reused')
        validated = dict(fixture='/mtc/selected', profile='mldsa44')
        with patch.object(measurements.bv, 'preselect_mtc_fixture',
                          return_value=(selected, [])) as preselect, \
             patch.object(measurements.bv, 'validate_mtc', return_value=validated) as validate, \
             patch.object(measurements.bv, 'discover') as discover:
            actual = measurements.existing_mtc(REPO, 'image', 'mldsa44')
        preselect.assert_called_once_with(REPO, 'mldsa44')
        validate.assert_called_once_with(Path('/mtc/selected'), 'mldsa44', 'image')
        discover.assert_not_called()
        self.assertEqual(actual['anchor'], '/mtc/anchor.json')

    def test_all_profiles_validate_only_the_selected_mtc_and_x509(self):
        policy = {'policy_applied': True}
        with patch.object(measurements, 'existing_mtc',
                          side_effect=lambda repo, image, profile: {'profile': profile}) as mtc, \
             patch.object(measurements.bv, 'precheck_formal_x509_fixture',
                          side_effect=lambda repo, profile, depth, fixture_set:
                          Path('/formal')/profile/f'd{depth}'), \
             patch.object(measurements.bv, 'validate_x509',
                          side_effect=lambda path, **kwargs:
                          {'fixture': str(path), 'root': str(path/'root.pem')}) as x509, \
             patch.object(measurements.bv, 'chromium_ca_policy', return_value=policy):
            prepared = measurements.campaign_preconditions(
                REPO, 'image', measurements.CAMPAIGN_PROFILES, 3,
                measurements.FORMAL_X509_FIXTURE_SET)
        self.assertEqual(set(prepared), set(measurements.CAMPAIGN_PROFILES))
        self.assertEqual(mtc.call_count, 5)
        self.assertEqual(x509.call_count, 5)

    def test_preconditions_precede_capture_lock_and_result_directory(self):
        source = (REPO/'campaigns/browser_client/chromium_mtc/browser_measurements.py').read_text()
        preflight = source.index('prepared = campaign_preconditions(')
        capture = source.index('tools = pcap.requirements()', preflight)
        lock = source.index("lock = bv.REPO/'.mt-state/chromium-browser-validation.lock'", capture)
        result = source.index("root = bv.REPO/'artifacts/results'/", lock)
        self.assertLess(preflight, capture)
        self.assertLess(capture, lock)
        self.assertLess(lock, result)
        self.assertNotIn('/Library/Managed Preferences', source)
        self.assertNotIn('/etc/chromium/policies', source)

    def test_multi_profile_plan_and_totals(self):
        self.assertEqual(measurements.CAMPAIGN_PROFILES,
                         ('ecdsa-p256', 'ecdsa-p384', 'mldsa44', 'mldsa65', 'mldsa87'))
        self.assertEqual(measurements.campaign_totals(measurements.CAMPAIGN_PROFILES, 3),
                         {'pairs_per_profile': 3, 'total_pairs': 15, 'total_measurements': 30})
        self.assertEqual(measurements.campaign_totals(measurements.CAMPAIGN_PROFILES, 30),
                         {'pairs_per_profile': 30, 'total_pairs': 150, 'total_measurements': 300})

    def test_fifth_profile_failure_aborts_global_precheck_without_generation(self):
        successes = [({'mtc': {}, 'x509': {}}, {})] * 4
        with patch.object(measurements, 'profile_run_preconditions',
                          side_effect=[*successes, ValueError('missing mldsa87')]) as check, \
             patch.object(measurements.bv, 'generate_mtc') as generate_mtc, \
             patch.object(measurements.bv, 'generate_x509') as generate_x509:
            with self.assertRaisesRegex(ValueError, 'profile=mldsa87.*missing mldsa87'):
                measurements.campaign_preconditions(
                    REPO, 'unused-image', measurements.CAMPAIGN_PROFILES, 3,
                    measurements.FORMAL_X509_FIXTURE_SET)
        self.assertEqual(check.call_count, 5)
        generate_mtc.assert_not_called()
        generate_x509.assert_not_called()

    def test_single_csv_schema_identifies_profile_depth_and_pair(self):
        self.assertIn('signature_profile', measurements.META)
        self.assertIn('depth', measurements.META)
        self.assertIn('pair', measurements.PAIR_FIELDS)
        self.assertIn('signature_profile', measurements.PAIR_FIELDS)
        self.assertIn('key_establishment', measurements.PAIR_FIELDS)
        self.assertIn('depth', measurements.PAIR_FIELDS)

    def test_one_campaign_writes_30_measurements_and_15_pairs(self):
        rows = []
        paired_rows = []
        for profile in measurements.CAMPAIGN_PROFILES:
            for pair in range(1, 4):
                for case in measurements.CASES:
                    row = dict.fromkeys(measurements.META, '')
                    row.update({key: 1 for key in measurements.METRICS})
                    row.update(dict.fromkeys((*measurements.DECOMPOSITION,
                                              *measurements.COMPARISON)))
                    row.update(pair=pair, pair_index=pair, case=case,
                               signature_profile=profile, status='PASS', pair_complete=True)
                    rows.append(row)
                paired = dict.fromkeys(measurements.PAIR_FIELDS)
                paired.update(pair=pair, pair_index=pair, signature_profile=profile,
                              key_establishment='x25519-mlkem768', depth=3)
                for metric in measurements.PRIMARY:
                    paired[metric+'_delta'] = 0
                paired_rows.append(paired)
        summary = dict(status='PASS', requested_pairs=15,
                       profiles=list(measurements.CAMPAIGN_PROFILES),
                       tls=dict(version='TLS 1.3', group='X25519MLKEM768',
                                cipher='TLS_AES_256_GCM_SHA384'),
                       key_establishment='x25519-mlkem768', depth=3)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            measurements.save_outputs(root, summary, rows, paired_rows)
            with (root/'measurements.csv').open(newline='') as stream:
                saved_rows = list(csv.DictReader(stream))
            with (root/'pairs.csv').open(newline='') as stream:
                saved_pairs = list(csv.DictReader(stream))
        self.assertEqual(len(saved_rows), 30)
        self.assertEqual(len(saved_pairs), 15)
        self.assertEqual({row['signature_profile'] for row in saved_rows},
                         set(measurements.CAMPAIGN_PROFILES))
        self.assertEqual({(row['signature_profile'], row['pair']) for row in saved_pairs},
                         {(profile, str(pair)) for profile in measurements.CAMPAIGN_PROFILES
                          for pair in range(1, 4)})

    def test_direct_cli_profile_remains_single_profile(self):
        source = (REPO/'campaigns/browser_client/chromium_mtc/browser_measurements.py').read_text()
        self.assertIn("profiles = CAMPAIGN_PROFILES if args.all_profiles else (args.profile,)", source)

    def test_chromium_ca_policy_requires_selected_root_and_records_der_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/'root.pem'; root.write_bytes(b'fixture root')
            der = b'fixture root der'
            digest = bv.hashlib.sha256(der).hexdigest()
            documents = [(Path('/managed/policy.json'), {
                'CACertificates': [bv.base64.b64encode(der).decode('ascii')]})]
            with patch.object(bv, 'certificate_sha256', return_value=digest):
                metadata = bv.chromium_ca_policy(root, documents)
            self.assertTrue(metadata['policy_applied'])
            self.assertFalse(metadata['certificate_verification_bypass'])
            self.assertEqual(metadata['policy_root_der_sha256'], digest)

            with patch.object(bv, 'certificate_sha256', return_value='0'*64):
                with self.assertRaisesRegex(ValueError, 'does not contain'):
                    bv.chromium_ca_policy(root, documents)

    def test_existing_fixture_is_reused_and_campaign_receives_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp)/'existing'; fixture.mkdir()
            validator = lambda path: dict(fixture=str(path.resolve()))
            generator = Mock(side_effect=AssertionError('valid fixture regenerated'))
            selected, _ = bv.select_or_generate([fixture], validator, generator)
            generator.assert_not_called()
            self.assertEqual(selected['origin'], 'reused')
            self.assertEqual(selected['fixture'], str(fixture.resolve()))

    def test_missing_fixture_calls_generator_and_campaign_receives_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp)/'artifacts/x509/generated'; fixture.mkdir(parents=True)
            validator = lambda path: dict(fixture=str(path.resolve()))
            generator = Mock(return_value=fixture)
            selected, _ = bv.select_or_generate([], validator, generator)
            generator.assert_called_once_with()
            self.assertEqual(selected['origin'], 'generated')
            self.assertEqual(selected['fixture'], str(fixture.resolve()))

    def test_wrapper_disables_generation_outside_measurements_only(self):
        text = (REPO/'bin/browser_client/mt-chromium-tests').read_text()
        self.assertIn("if sys.argv[2] != 'browser_measurements':", text)
        self.assertIn('bv.generate_mtc=bv.generate_x509=no_generation', text)

    def test_measurement_runs_automatically_use_chromium_ca_policy(self):
        text = (REPO/'bin/browser_client/mt-chromium-tests').read_text()
        self.assertIn('[[ "$module" == browser_measurements && "${1:-}" == run ]]', text)
        self.assertIn('set -- "$@" --x509-chromium-ca-policy', text)

    def test_measurement_menu_uses_one_paired_run_with_explicit_inputs(self):
        text = (REPO/'bin/browser_client/mt-chromium-menu.sh').read_text()
        self.assertIn("labels=('Status' 'Run paired comparison')", text)
        self.assertIn("commands=(readiness run)", text)
        self.assertIn('args+=(--key-establishment "$kem" --depth "$depth")', text)
        self.assertIn('args+=(--pairs "$pairs" --all-profiles)', text)
        self.assertNotIn('matrix-smoke', text)
        self.assertNotIn('depth=all', text)

    def test_tests_menu_uses_compact_status(self):
        text = (REPO/'bin/browser_client/mt-chromium-tests').read_text()
        self.assertIn('2) menu_invoke readonly menu-status;;', text)
        self.assertIn("print('Chromium / MTC — Tests status')", text)
        self.assertIn("('Browser measurements', measurements)", text)
        self.assertIn("('Capture backend', 'READY' if capture_ready else 'NOT READY')", text)
        self.assertIn("('Chromium', 'READY' if chromium_ready else 'NOT READY')", text)


if __name__ == '__main__':
    unittest.main()
