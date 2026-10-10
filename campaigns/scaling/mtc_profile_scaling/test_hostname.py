"""Small offline hostname checks; OpenSSL, Docker and sockets are mocked."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from campaigns.scaling.mtc_profile_scaling import workflow as w


class HostnameTests(unittest.TestCase):
    def test_population_cn_san_and_other_leaves(self):
        for hostname in ('server', 'server.test'):
            with self.subTest(hostname=hostname), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / 'ca.pem').touch()
                subjects, extensions = [], []

                def command(*args):
                    if args[0] == 'req':
                        subjects.append(args[args.index('-subj') + 1])
                        Path(args[args.index('-out') + 1]).touch()
                    if args[0] == 'x509':
                        extensions.append(Path(args[args.index('-extfile') + 1]).read_text())

                with patch.object(w.prepare, 'keygen'), patch.object(w.prepare, 'command', side_effect=command):
                    if hostname == 'server':
                        w.populate(root, 'ecdsa-p256', 2)
                    else:
                        w.populate(root, 'ecdsa-p256', 2, hostname)
                self.assertEqual(subjects, ['/CN=' + hostname, '/CN=member-1.lab'])
                self.assertIn('subjectAltName=DNS:' + hostname + '\n', extensions[0])
                self.assertIn('subjectAltName=DNS:member-1.lab\n', extensions[1])

    def test_tls_hostname(self):
        for hostname in ('server', 'server.test'):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                sock = MagicMock()
                sock.__enter__.return_value.getsockname.return_value = ('127.0.0.1', 4433)
                proc = MagicMock()
                proc.wait.return_value = 0
                proc.poll.return_value = 0

                def start(*args, **kwargs):
                    kwargs['stdout'].write('ACCEPT\n')
                    kwargs['stdout'].flush()
                    return proc

                result = SimpleNamespace(returncode=0, stderr='', stdout=
                    'MTC verification: OK\nHTTP/1.0 200\n'
                    'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nServer Temp Key: X25519')
                with patch.object(w.socket, 'socket', return_value=sock), patch.object(
                        w.subprocess, 'Popen', side_effect=start), patch.object(
                        w.subprocess, 'run', return_value=result) as run:
                    w.tls_once(root, root, 'ecdsa-p256', 'landmark', root / 'out', hostname)
                command = run.call_args.args[0]
                self.assertEqual(command[command.index('-servername') + 1], hostname)
                self.assertEqual(command[command.index('-verify_hostname') + 1], hostname)

    def test_cli_forwarding_and_single_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'new'
            argv = ['workflow.py', 'generate', '--output', str(output), '--profile',
                    'ecdsa-p256', '--server-hostname', 'server.test', '--execute']
            replies = [SimpleNamespace(stdout='[{"Id":"sha256:mock"}]'),
                       SimpleNamespace(stdout='commit\n'), SimpleNamespace(stdout='')]
            with patch.object(sys, 'argv', argv), patch.object(w, 'checked', side_effect=replies), patch.object(
                    w.subprocess, 'run') as run, contextlib.redirect_stdout(io.StringIO()):
                w.main()
            command = run.call_args.args[0]
            self.assertEqual(command[command.index('--server-hostname') + 1], 'server.test')
            self.assertEqual(command[command.index('--profile') + 1], 'ecdsa-p256')
            self.assertEqual(command[command.index('--user') + 1],
                             f'{w.os.getuid()}:{w.os.getgid()}')
            self.assertIn('HOME=/tmp', command)
            self.assertIn(str(output.parent.resolve()) + ':/output', command)
            self.assertFalse(output.exists())

    def test_validation_container_uses_host_identity_for_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fixtures = root / 'fixtures'
            fixtures.mkdir()
            output = root / 'validation'
            argv = ['workflow.py', 'validate', '--output', str(output),
                    '--fixtures', str(fixtures), '--profile', 'ecdsa-p256',
                    '--mode', 'standalone', '--server-hostname', 'server.test',
                    '--execute']
            replies = [SimpleNamespace(stdout='[{"Id":"sha256:mock"}]'),
                       SimpleNamespace(stdout='commit\n'), SimpleNamespace(stdout='')]
            with patch.object(sys, 'argv', argv), patch.object(
                    w, 'checked', side_effect=replies), patch.object(
                    w.subprocess, 'run') as run, contextlib.redirect_stdout(io.StringIO()):
                w.main()
            command = run.call_args.args[0]
            self.assertEqual(command[command.index('--user') + 1],
                             f'{w.os.getuid()}:{w.os.getgid()}')
            self.assertIn('HOME=/tmp', command)
            self.assertIn(str(output.parent.resolve()) + ':/output', command)
            self.assertIn(str(fixtures.resolve()) + ':/fixtures:ro', command)
            self.assertFalse(output.exists())

    def test_existing_output_and_seed_rejected_before_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            cases = [
                ['--output', tmp],
                ['--output', tmp + '/new', '--seed-fixtures', tmp, '--server-hostname', 'server.test'],
            ]
            for options in cases:
                with patch.object(sys, 'argv', ['workflow.py', 'generate', *options, '--execute']), patch.object(
                        w, 'checked') as checked, contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        w.main()
                    checked.assert_not_called()

    def test_invalid_hostname(self):
        for value in ('', '-bad', 'server\nDNS:other', 'server/name', 'server..test'):
            with self.assertRaises(argparse.ArgumentTypeError):
                w.server_hostname(value)

    def test_validation_hostname_mismatch_precedes_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'manifest.json').write_text(json.dumps({'server_hostname': 'server.test'}))
            args = SimpleNamespace(fixtures=root, output=root / 'validation', profile=['ecdsa-p256'],
                                   mode=None, tree_size=16, server_hostname='server')
            with patch.object(w, 'provenance', return_value={}), patch.object(w, 'require_current_mtc_image'):
                with self.assertRaisesRegex(ValueError, 'hostname'):
                    w.validate(args)
            self.assertFalse(args.output.exists())


if __name__ == '__main__':
    unittest.main()
