"""Exercise the stage-110 shell sequence with simulated Python entrypoints."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]


class Stage110SetupTests(unittest.TestCase):
    def run_stage(self, root, fail=False):
        launcher = (REPO / 'bin/cryptographic_scaling/mt-cert-scaling').read_text()
        stage = launcher.split('  110.*) OUT=$TLS_ROOT', 1)[1].split('  102.*)', 1)[0]
        script = stage.split("CMD=(bash -c '", 1)[1].split("' _ ", 1)[0]
        tools = root / 'tools'
        tools.mkdir(exist_ok=True)
        python = tools / 'python3'
        python.write_text('#!' + sys.executable + '\n' + '''
import json, os, pathlib, sys
args = sys.argv[1:]
if args[0] == '-c':
    os.execv(sys.executable, [sys.executable, *args])
with open(os.environ['CALL_LOG'], 'a') as log:
    log.write(json.dumps(args) + '\\n')
if args[0].endswith('/inspect_environment.py'):
    if os.environ.get('FAIL_PROBE') == '1':
        sys.exit(17)
    path = pathlib.Path(args[args.index('--output') + 1])
    path.write_text(json.dumps({'image_id': 'sha256:profile-snapshot'}))
''')
        python.chmod(0o755)
        env = dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH'],
                   CALL_LOG=str(root / 'calls.jsonl'), FAIL_PROBE='1' if fail else '0')
        return subprocess.run(['bash', '-c', script, '_', 'mock-chain',
            str(root / 'existing-fixtures'), str(root / 'tls-results'),
            'custom-profile:local', 'mock-baseline', '/usr/bin/true', 'mock-report'],
            env=env, capture_output=True, text=True)

    def test_fresh_snapshot_pins_both_calls_and_preserves_old_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = root / 'old-environment.json'
            old.write_text('{"image_id":"sha256:old"}')
            for _ in range(2):
                result = self.run_stage(root)
                self.assertEqual(result.returncode, 0, result.stderr)
            calls = [json.loads(line) for line in (root / 'calls.jsonl').read_text().splitlines()]
            runs = [a for a in calls if a[0].endswith('/run.py')]
            self.assertEqual(len(runs), 4)
            for args in runs:
                self.assertEqual(args[args.index('--image') + 1], 'sha256:profile-snapshot')
            self.assertEqual(runs[0][-1], '--dry-run')
            self.assertEqual(runs[1][-1], '--execute')
            snapshots = [a[a.index('--environment') + 1] for a in runs]
            self.assertEqual(snapshots[0], snapshots[1])
            self.assertNotEqual(snapshots[0], snapshots[2])
            self.assertEqual(old.read_text(), '{"image_id":"sha256:old"}')
            self.assertFalse((root / 'tls-results').exists())

    def test_failed_probe_never_reaches_measurement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = self.run_stage(root, fail=True)
            self.assertEqual(result.returncode, 17)
            calls = (root / 'calls.jsonl').read_text().splitlines()
            self.assertEqual(len(calls), 1)
            self.assertIn('inspect_environment.py', calls[0])


if __name__ == '__main__':
    unittest.main()
