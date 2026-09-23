"""Destructive reset tests use temporary directories and a mocked Docker client."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
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
            return 'owned foreign pcma'
        if args[1:2] == ('inspect',):
            rows = []
            for identity, project in [('owned', 'mt'), ('foreign', 'other-project'), ('pcma', 'pcmab0123456789ab')]:
                labels = {'com.docker.compose.project': project}
                rows.append({'Id': identity, 'Name': identity, 'Labels': labels, 'Config': {'Labels': labels}})
            return json.dumps(rows)
        if args[:2] == ('image', 'ls'):
            return 'mt-tls-lab:local\nmt-tls-pcma:stage-b-v1\n'
        return ''

    def run_reset(self, answer='RESET ALL', docker=None):
        with patch.object(reset, 'REPO', self.root), patch.object(reset, 'docker', docker or self.docker), \
             patch('builtins.input', return_value=answer), contextlib.redirect_stdout(io.StringIO()):
            reset.main()

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
        self.assertIn(('container', 'rm', '-f', 'owned', 'pcma'), removals)

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

    def test_pcma_bind_mounts_resolve_to_repository(self):
        compose = ROOT/'campaigns/historical_campaigns/pcma_stage_b/compose.yaml'
        mounts = [line.strip()[2:].split(':')[0] for line in compose.read_text().splitlines()
                  if line.strip().startswith('- ../')]
        self.assertEqual([(compose.parent/p).resolve() for p in mounts],
                         [ROOT/'artifacts', ROOT/'artifacts/results'])


if __name__ == '__main__':
    unittest.main()
