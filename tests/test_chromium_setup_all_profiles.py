#!/usr/bin/env python3
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
PROFILES = ('ecdsa-p256', 'ecdsa-p384', 'mldsa44', 'mldsa65', 'mldsa87')


class ChromiumSetupAllProfilesTests(unittest.TestCase):
    def test_shared_campaign_profiles_are_exact(self):
        source = (REPO / 'campaigns/browser_client/chromium_mtc/browser_measurements.py').read_text()
        tree = ast.parse(source)
        assignment = next(
            node for node in tree.body if isinstance(node, ast.Assign)
            if any(isinstance(target, ast.Name) and target.id == 'CAMPAIGN_PROFILES'
                   for target in node.targets)
        )
        self.assertEqual(ast.literal_eval(assignment.value), PROFILES)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name)
        wrapper_dir = self.repo / 'bin/browser_client'
        module_dir = self.repo / 'campaigns/browser_client/chromium_mtc'
        state_dir = self.repo / '.mt-state/chromium-mtc'
        fixture = self.repo / 'fixture'
        validation = self.repo / 'validation.json'
        wrapper_dir.mkdir(parents=True)
        module_dir.mkdir(parents=True)
        state_dir.mkdir(parents=True)
        fixture.mkdir()
        validation.write_text('{}')
        shutil.copy2(REPO / 'bin/browser_client/mt-chromium-setup', wrapper_dir)
        shutil.copy2(REPO / 'bin/browser_client/mt-chromium-menu.sh', wrapper_dir)
        (module_dir / 'browser_measurements.py').write_text(
            f'CAMPAIGN_PROFILES = {PROFILES!r}\n')
        (module_dir / 'generate_x509_depth_matrix.py').write_text(
            """import json
import os
import sys
with open(os.environ['GENERATION_CAPTURE'], 'a') as output:
    output.write(json.dumps(sys.argv[1:]) + '\\n')
if os.environ.get('FAIL_GENERATION'):
    print('synthetic X509 generation failure', file=sys.stderr)
    raise SystemExit(9)
""")
        (module_dir / 'browser_validation.py').write_text(
            """import json
import os
import sys

if sys.argv[1] == 'prepare-mtc-dependencies':
    raise SystemExit(0)

with open(os.environ['CAPTURE'], 'a') as output:
    output.write(json.dumps(sys.argv[1:]) + '\\n')
profile = sys.argv[sys.argv.index('--profile') + 1]
if profile == os.environ.get('FAIL_PROFILE'):
    print('ORIGINAL FAILURE', file=sys.stderr)
    raise SystemExit(7)
""")
        (state_dir / 'paths.env').write_text(
            f"FIXTURE={fixture}\nVALIDATION={validation}\n")
        self.wrapper = wrapper_dir / 'mt-chromium-setup'
        self.wrapper.chmod(0o755)
        self.capture = self.repo / 'calls.jsonl'
        self.generation_capture = self.repo / 'generation-calls.jsonl'

    def tearDown(self):
        self.temporary.cleanup()

    def run_setup(self, *arguments, fail_profile=None):
        environment = os.environ.copy()
        environment['CAPTURE'] = str(self.capture)
        environment['GENERATION_CAPTURE'] = str(self.generation_capture)
        if fail_profile:
            environment['FAIL_PROFILE'] = fail_profile
        return subprocess.run(
            [str(self.wrapper), 'browser-validation', 'credentials', *arguments],
            cwd=self.repo, env=environment, text=True, capture_output=True)

    def calls(self):
        if not self.capture.exists():
            return []
        return [json.loads(line) for line in self.capture.read_text().splitlines()]

    def generation_calls(self):
        if not self.generation_capture.exists():
            return []
        return [json.loads(line) for line in self.generation_capture.read_text().splitlines()]

    @staticmethod
    def profiles(calls):
        return [call[call.index('--profile') + 1] for call in calls]

    def test_all_profiles_uses_normal_unforced_credentials_workflow(self):
        result = self.run_setup('--all-profiles', '--depth', '3')
        calls = self.calls()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.profiles(calls),
                         [profile for profile in PROFILES for _ in range(2)])
        self.assertEqual(
            [call[call.index('--mtc-trust-mode') + 1] for call in calls],
            ['landmark', 'standalone'] * len(PROFILES))
        self.assertTrue(all(call[0] == 'credentials' for call in calls))
        self.assertTrue(all('--mtc-fixture' not in call and '--mtc-validation' not in call
                            for call in calls))
        self.assertTrue(all(call[call.index('--depth') + 1] == '3' for call in calls))
        self.assertTrue(all(call[call.index('--x509-fixture-set') + 1] ==
                            'chromium-x509-depth-matrix-v1' for call in calls))
        self.assertTrue(all('--x509-chromium-ca-policy' in call for call in calls))
        self.assertTrue(all('--optimized-all-profiles' in call for call in calls))
        generation = self.generation_calls()
        self.assertEqual(len(generation), 1)
        self.assertEqual(generation[0][0], 'ensure')
        self.assertEqual(generation[0][generation[0].index('--depth') + 1], '3')
        profile_index = generation[0].index('--profiles') + 1
        self.assertEqual(generation[0][profile_index:profile_index + len(PROFILES)],
                         list(PROFILES))
        self.assertIn('Overall: PASS', result.stdout)
        self.assertIn('Docker run invocations: 0', result.stdout)

    def test_single_profile_is_unchanged(self):
        result = self.run_setup('--profile', 'ecdsa-p384')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual(self.profiles(calls), ['ecdsa-p384'])
        self.assertIn('--mtc-fixture', calls[0])
        self.assertIn('--mtc-validation', calls[0])
        self.assertNotIn('--x509-fixture-set', calls[0])
        self.assertNotIn('--x509-chromium-ca-policy', calls[0])
        self.assertNotIn('--optimized-all-profiles', calls[0])
        self.assertEqual(self.generation_calls(), [])

    def test_profile_and_all_profiles_are_mutually_exclusive(self):
        result = self.run_setup('--profile', 'ecdsa-p256', '--all-profiles')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertIn('mutually exclusive', result.stderr)

    def test_failure_stops_before_later_profiles_and_preserves_status(self):
        result = self.run_setup('--all-profiles', fail_profile='mldsa44')
        self.assertEqual(result.returncode, 7)
        self.assertEqual(self.profiles(self.calls()),
                         ['ecdsa-p256', 'ecdsa-p256', 'ecdsa-p384',
                          'ecdsa-p384', 'mldsa44'])
        self.assertIn('ORIGINAL FAILURE', result.stderr)
        self.assertIn('failed for profile=mldsa44 trust_mode=landmark', result.stderr)

    def test_generation_failure_stops_before_credentials(self):
        environment = os.environ.copy()
        environment['CAPTURE'] = str(self.capture)
        environment['GENERATION_CAPTURE'] = str(self.generation_capture)
        environment['FAIL_GENERATION'] = '1'
        result = subprocess.run(
            [str(self.wrapper), 'browser-validation', 'credentials',
             '--all-profiles', '--depth', '3'], cwd=self.repo,
            env=environment, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        self.assertIn('Formal X509 dependency preparation failed', result.stderr)


if __name__ == '__main__':
    unittest.main()
