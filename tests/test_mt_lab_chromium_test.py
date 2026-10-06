"""Offline launcher contract tests; no Docker services or Chromium are run."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]


class MtLabChromiumTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo/'bin/base').mkdir(parents=True)
        (self.repo/'bin/browser_client').mkdir(parents=True)
        (self.repo/'.mt-state/mt-lab').mkdir(parents=True)
        (self.repo/'.mt-state/chromium-mtc').mkdir(parents=True)
        shutil.copy2(REPO/'bin/base/mt-lab', self.repo/'bin/base/mt-lab')

        self.fixture = self.repo/'artifacts/mt-lab/fixture-current'
        required = (
            'manifest.json',
            'transparency/ecdsa-p256/persistent-log',
            'transparency/ecdsa-p256/snapshot-n8.mcp2',
            'transparency/ecdsa-p256/snapshot-n16.mcp2',
            'transparency/ecdsa-p256/trusted-authority.bin',
            'batch16/mtc/ecdsa-p256/manifest.json',
            'batch16/mtc/ecdsa-p256/landmarks.txt',
            'batch16/mtc/ecdsa-p256/authority.bin',
            'batch16/mtc/ecdsa-p256/trust.bin',
            'population/ecdsa-p256/0.key',
        )
        for name in required:
            path = self.fixture/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture')
        validation = self.fixture.with_name(self.fixture.name+'-validation')/'validation.json'
        validation.parent.mkdir()
        validation.write_text('{}')
        (self.repo/'.mt-state/mt-lab/paths.env').write_text(
            f'MT_LAB_REPOSITORY={self.repo}\nMT_LAB_STATE={self.repo}/.mt-state/mt-lab\n'
            f'MT_LAB_FIXTURE={self.fixture}\n')
        (self.repo/'.mt-state/mt-lab/services.env').write_text(
            'MTC_LOG_BIND_ADDRESS=127.0.0.1\nMTC_LOG_PORT=18080\nMTC_LOG_URL=http://mtc-log:8080\n'
            'COSIGNER_BIND_ADDRESS=127.0.0.1\nCOSIGNER_PORT=8443\nCOSIGNER_TLS_NAME=localhost\n'
            'MONITOR_A_BIND_ADDRESS=127.0.0.1\nMONITOR_A_PORT=18081\nMONITOR_A_URL=http://monitor-a:8081\n'
            'MONITOR_B_BIND_ADDRESS=127.0.0.1\nMONITOR_B_PORT=18082\nMONITOR_B_URL=http://monitor-b:8081\n'
            'RP_SERVER_BIND_ADDRESS=127.0.0.9\nRP_SERVER_PORT=19083\nRP_SERVER_URL=http://rp-server:8082\n'
            'RP_UPDATER_LOG_URL=http://mtc-log:8080\nRP_UPDATER_SERVER_URL=http://rp-server:8082\n'
            'RP_UPDATER_INTERVAL=60\nGOSSIP_FIRST_URL=http://monitor-a:8081/checkpoint\n'
            'GOSSIP_SECOND_URL=http://monitor-b:8081/checkpoint\nGOSSIP_LOG_URL=http://mtc-log:8080\n')
        self.chromium_selection = self.repo/'.mt-state/chromium-mtc/paths.env'
        self.chromium_selection.write_text('FIXTURE=/must/not/be/used\nVALIDATION=/must/not/be/used.json\n')
        self.bin = self.repo/'test-bin'; self.bin.mkdir()
        docker = self.bin/'docker'
        docker.write_text('#!/bin/sh\ncase "$1" in info) exit 0;; compose) echo running;; esac\n')
        docker.chmod(0o755)
        wrapper = self.repo/'bin/browser_client/mt-chromium-tests'
        wrapper.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE"\n')
        wrapper.chmod(0o755)

    def test_uses_lab_fixture_and_rp_configuration_without_mutating_chromium_selection(self):
        before = self.chromium_selection.read_bytes()
        capture = self.repo/'arguments.txt'
        env = {**os.environ, 'PATH': str(self.bin)+os.pathsep+os.environ['PATH'],
               'CAPTURE': str(capture)}
        result = subprocess.run([self.repo/'bin/base/mt-lab', 'chromium-test'],
                                text=True, capture_output=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        args = capture.read_text().splitlines()
        self.assertIn(str(self.fixture), args)
        self.assertNotIn('/must/not/be/used', args)
        self.assertIn(str(self.fixture)+'-validation/validation.json', args)
        self.assertIn('http://127.0.0.9:19083/trusted-subtrees', args)
        self.assertEqual(self.chromium_selection.read_bytes(), before)


class ChromiumWrapperSelectionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        (self.repo/'bin/browser_client').mkdir(parents=True)
        (self.repo/'campaigns/browser_client/chromium_mtc').mkdir(parents=True)
        (self.repo/'.mt-state/chromium-mtc').mkdir(parents=True)
        for name in ('mt-chromium-tests', 'mt-chromium-menu.sh'):
            shutil.copy2(REPO/'bin/browser_client'/name, self.repo/'bin/browser_client'/name)
        (self.repo/'.mt-state/chromium-mtc/paths.env').write_text(
            f'FIXTURE={self.repo}/selected\nVALIDATION={self.repo}/selected-validation.json\n')
        (self.repo/'selected').mkdir()
        (self.repo/'selected-validation.json').write_text('{}')
        self.bin = self.repo/'test-bin'; self.bin.mkdir()
        python = self.bin/'python3'
        python.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$CAPTURE"\ncat >/dev/null\n')
        python.chmod(0o755)

    def run_wrapper(self, *args):
        capture = self.repo/'wrapper-arguments.txt'
        env = {**os.environ, 'PATH': str(self.bin)+os.pathsep+os.environ['PATH'],
               'CAPTURE': str(capture)}
        result = subprocess.run([self.repo/'bin/browser_client/mt-chromium-tests', *args],
                                text=True, capture_output=True, env=env)
        return result, capture.read_text().splitlines() if capture.exists() else []

    def test_normal_run_still_appends_persistent_selection(self):
        result, args = self.run_wrapper('browser-validation', 'run', 'mtc-positive')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(self.repo/'selected'), args)
        self.assertIn(str(self.repo/'selected-validation.json'), args)

    def test_prevalidated_entry_preserves_explicit_fixture(self):
        fixture = self.repo/'lab-fixture'; validation = self.repo/'lab-validation.json'
        result, args = self.run_wrapper(
            'browser-validation', 'run-prevalidated-mtc', 'mtc-positive',
            '--mtc-fixture', str(fixture), '--mtc-validation', str(validation))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(str(fixture), args)
        self.assertIn(str(validation), args)
        self.assertNotIn(str(self.repo/'selected'), args)


if __name__ == '__main__':
    unittest.main()
