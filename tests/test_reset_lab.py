"""Destructive reset tests use temporary directories and a mocked Docker client."""
import contextlib
import importlib.util
import io
import json
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('reset_lab', ROOT/'scripts/maintenance/reset_lab.py')
reset = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reset)


class ResetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'repo'
        self.root.mkdir()
        for name in ('artifacts', '.mt-state', 'results', 'src'):
            (self.root/name).mkdir()
            (self.root/name/'keep.txt').write_text('original')
        self.calls = []

    def docker(self, *args):
        self.calls.append(args)
        if args in [('ps', '-aq'), ('network', 'ls', '-q'), ('volume', 'ls', '-q')]:
            return 'owned foreign'
        if args[1:2] == ('inspect',):
            rows = []
            for identity, project in [('owned', 'mtlatency'), ('foreign', 'other-project')]:
                labels = {'com.docker.compose.project': project}
                rows.append({'Id': identity, 'Name': identity, 'Labels': labels, 'Config': {'Labels': labels}})
            return json.dumps(rows)
        if args[:2] == ('image', 'ls'):
            return 'mt-tls-lab:local\nmt-tls-mtc:local\n'
        return ''

    def run_reset(self, answer='RESET ALL', docker=None, answers=None):
        with patch.object(reset, 'REPO', self.root), patch.object(reset, 'docker', docker or self.docker), \
             patch('builtins.input', side_effect=answers or [answer]), contextlib.redirect_stdout(io.StringIO()):
            reset.main()

    def install_linux_policy_fixture(self):
        package = self.root/'artifacts/chromium-ca-policy-test'
        contents = {
            'canonical-policy.json': b'{"CACertificates": []}\n',
            'linux/mtc-ca-policy.json': b'{"CACertificates": []}\n',
            'macos/chromium-mtc-ca.mobileconfig': b'profile',
        }
        outputs = {}
        for name, content in contents.items():
            path = package/name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            outputs[name] = {'sha256': hashlib.sha256(content).hexdigest()}
        (package/'policy-manifest.json').write_text(json.dumps({
            'fixture_set': 'chromium-x509-depth-matrix-v1',
            'policy_name': 'CACertificates', 'outputs': outputs}))
        installed = Path(self.tmp.name)/'mtc-ca-policy.json'
        installed.write_bytes(contents['linux/mtc-ca-policy.json'])
        return installed

    def test_cancel_changes_nothing(self):
        self.run_reset('yes')
        self.assertEqual(self.calls, [])
        self.assertTrue((self.root/'artifacts/keep.txt').exists())

    def test_eof_cancels(self):
        with patch('builtins.input', side_effect=EOFError), patch.object(reset, 'docker') as docker, \
             contextlib.redirect_stdout(io.StringIO()):
            reset.main()
        docker.assert_not_called()

    def test_confirm_discards_only_local_data_and_owned_resources(self):
        self.run_reset()
        self.assertFalse((self.root/'artifacts').exists())
        self.assertFalse((self.root/'.mt-state').exists())
        self.assertTrue((self.root/'results/keep.txt').exists())
        self.assertTrue((self.root/'src/keep.txt').exists())
        removals = [c for c in self.calls if c[1:2] == ('rm',)]
        self.assertEqual(len(removals), 4)
        self.assertTrue(all('foreign' not in c for c in removals))
        self.assertIn(('container', 'rm', '-f', 'owned'), removals)

    def test_docker_failure_keeps_local_data(self):
        def fail(*args):
            if args[:2] == ('image', 'rm'):
                raise OSError('image in use')
            return self.docker(*args)
        with self.assertRaises(OSError):
            self.run_reset(docker=fail)
        self.assertTrue((self.root/'artifacts/keep.txt').exists())
        self.assertTrue((self.root/'.mt-state/keep.txt').exists())

    def test_symlink_does_not_delete_target(self):
        import shutil
        shutil.rmtree(self.root/'artifacts')
        outside = Path(self.tmp.name)/'outside'
        outside.mkdir()
        (outside/'keep').write_text('data')
        (self.root/'artifacts').symlink_to(outside, target_is_directory=True)
        self.run_reset()
        self.assertTrue((outside/'keep').exists())

    def test_matching_chromium_policy_can_be_preserved(self):
        installed = self.install_linux_policy_fixture()
        with patch.object(reset.platform, 'system', return_value='Linux'), \
             patch.object(reset, 'LINUX_CHROMIUM_POLICY', installed), \
             patch.object(reset, 'remove_chromium_policy') as remove:
            self.run_reset(answers=['RESET ALL', 'n'])
        remove.assert_not_called()
        self.assertTrue(installed.exists())

    def test_matching_chromium_policy_is_removed_before_local_data(self):
        installed = self.install_linux_policy_fixture()
        def remove(policy):
            self.assertTrue((self.root/'artifacts').exists())
            installed.unlink()
        with patch.object(reset.platform, 'system', return_value='Linux'), \
             patch.object(reset, 'LINUX_CHROMIUM_POLICY', installed), \
             patch.object(reset, 'remove_chromium_policy', side_effect=remove) as action:
            self.run_reset(answers=['RESET ALL', 'y'])
        action.assert_called_once()
        self.assertFalse(installed.exists())
        self.assertFalse((self.root/'artifacts').exists())

    def test_foreign_chromium_policy_is_never_offered_or_removed(self):
        installed = self.install_linux_policy_fixture()
        installed.write_text('{"foreign": true}\n')
        with patch.object(reset.platform, 'system', return_value='Linux'), \
             patch.object(reset, 'LINUX_CHROMIUM_POLICY', installed), \
             patch.object(reset, 'remove_chromium_policy') as remove:
            self.run_reset()
        remove.assert_not_called()
        self.assertTrue(installed.exists())

    def test_chromium_policy_removal_failure_preserves_local_data(self):
        installed = self.install_linux_policy_fixture()
        with patch.object(reset.platform, 'system', return_value='Linux'), \
             patch.object(reset, 'LINUX_CHROMIUM_POLICY', installed), \
             patch.object(reset, 'remove_chromium_policy', side_effect=OSError('denied')):
            with self.assertRaises(OSError):
                self.run_reset(answers=['RESET ALL', 'y'])
        self.assertTrue((self.root/'artifacts').exists())
        self.assertTrue((self.root/'.mt-state').exists())

    def test_linux_removal_rechecks_hash_and_exact_path(self):
        installed = self.install_linux_policy_fixture()
        with patch.object(reset, 'REPO', self.root):
            policy = reset.installed_chromium_policy('Linux', installed)
        def remove(command, check):
            self.assertEqual(command, ['sudo', 'rm', '--', str(installed)])
            self.assertTrue(check)
            installed.unlink()
        with patch.object(reset.subprocess, 'run', side_effect=remove) as run:
            reset.remove_chromium_policy(policy)
        run.assert_called_once()

    def test_macos_profile_detection_uses_fixed_lab_identifier(self):
        self.install_linux_policy_fixture()
        result = SimpleNamespace(returncode=0, stdout='',
                                 stderr=reset.MACOS_PROFILE_IDENTIFIER)
        with patch.object(reset, 'REPO', self.root), \
             patch.object(reset, 'command_output', return_value=result):
            policy = reset.installed_chromium_policy('Darwin')
        self.assertEqual(policy, {'platform': 'Darwin',
                                  'identifier': reset.MACOS_PROFILE_IDENTIFIER})

if __name__ == '__main__':
    unittest.main()
