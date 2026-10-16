#!/usr/bin/env python3
"""Offline contract tests for autonomous browser-measurements preparation."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]


class BrowserMeasurementsAutoPrepareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        wrapper_dir = self.repo/'bin/browser_client'
        wrapper_dir.mkdir(parents=True)
        shutil.copy2(REPO/'bin/browser_client/mt-chromium-tests', wrapper_dir)
        shutil.copy2(REPO/'bin/browser_client/mt-chromium-menu.sh', wrapper_dir)
        self.log = self.repo/'calls.log'
        self.bin = self.repo/'fake-bin'; self.bin.mkdir()
        python = self.bin/'python3'
        python.write_text(
            '#!/bin/sh\n'
            'printf "PYTHON %s\\n" "$*" >> "$CALL_LOG"\n'
            'if [ "$#" -eq 3 ] && [ "$1" = -B ] && [ "$2" = - ]; then\n'
            '  echo "ecdsa-p256 ecdsa-p384 mldsa44 mldsa65 mldsa87"\n'
            'fi\n')
        python.chmod(0o755)
        setup = wrapper_dir/'mt-chromium-setup'
        setup.write_text(
            '#!/bin/sh\n'
            'printf "SETUP %s\\n" "$*" >> "$CALL_LOG"\n')
        setup.chmod(0o755)
        self.docker = self.bin/'docker'
        self.docker.write_text(
            '#!/bin/sh\n'
            'printf "DOCKER %s\\n" "$*" >> "$CALL_LOG"\n'
            '[ "$1" != info ] || exit "${DOCKER_INFO_STATUS:-0}"\n'
            'exit 0\n')
        self.docker.chmod(0o755)
        self.wrapper = wrapper_dir/'mt-chromium-tests'
        self.wrapper.chmod(0o755)

    def run_wrapper(self, *, docker_status='0'):
        env = os.environ.copy()
        env.update(PATH=str(self.bin)+os.pathsep+env['PATH'],
                   CALL_LOG=str(self.log), DOCKER_INFO_STATUS=docker_status)
        return subprocess.run(
            [str(self.wrapper), 'browser-measurements', 'run',
             '--depth', '3', '--pairs', '1', '--warmups', '1',
             '--all-profiles'], cwd=self.repo, env=env,
            text=True, capture_output=True)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_cli_prepares_x509_policy_and_credentials_before_campaign(self):
        result = self.run_wrapper()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        x509 = next(i for i, line in enumerate(calls)
                    if line.startswith('SETUP x509-fixtures ensure '))
        policy = calls.index('SETUP ca-policy-prepare')
        credentials = next(i for i, line in enumerate(calls)
                           if line.startswith('SETUP browser-validation credentials '))
        campaign = max(i for i, line in enumerate(calls)
                       if ' browser_measurements run ' in line)
        self.assertLess(x509, policy)
        self.assertLess(policy, credentials)
        self.assertLess(credentials, campaign)
        self.assertIn('--depth 3', calls[x509])
        self.assertIn('--all-profiles --depth 3', calls[credentials])

    def test_inaccessible_docker_stops_before_setup_and_campaign(self):
        result = self.run_wrapper(docker_status='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Docker API is inaccessible', result.stderr)
        self.assertIn('User:', result.stderr)
        self.assertNotIn('Start Docker and wait', result.stderr)
        self.assertFalse(any(line.startswith('SETUP ') for line in self.calls()))
        self.assertFalse(any(' browser_measurements run ' in line
                             for line in self.calls()))

    def test_interactive_docker_startup_covers_macos_and_linux(self):
        launcher = (REPO/'bin/browser_client/mt-chromium-tests').read_text()
        self.assertIn('open -a Docker', launcher)
        self.assertIn('systemctl --user start docker', launcher)
        self.assertIn('sudo systemctl start docker', launcher)
        self.assertIn('sudo service docker start', launcher)
        self.assertIn('MT_DOCKER_START_TIMEOUT', launcher)
        self.assertIn('if [[ ! -t 0 || ! -t 1 ]]', launcher)
        self.assertLess(launcher.index('permission denied'),
                        launcher.index('Start Docker and wait'))

    def test_policy_prepare_reuses_existing_setup_workflow(self):
        setup = (REPO/'bin/browser_client/mt-chromium-setup').read_text()
        self.assertIn('ca_policy_action generate', setup)
        self.assertIn('ca_policy_action install', setup)
        self.assertIn('ca_policy_verify_roots', setup)
        self.assertIn('ca-policy-prepare) ca_policy_prepare', setup)


if __name__ == '__main__':
    unittest.main()
