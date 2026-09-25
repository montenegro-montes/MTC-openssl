"""Offline runner -> Compose environment -> measurement CSV contract."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
HERE = REPO / 'campaigns/scaling/cert_chain_scaling'
sys.path.insert(0, str(HERE))


def load(name):
    spec = importlib.util.spec_from_file_location('stage110_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


runner, measure = load('run'), load('measure')


def client_environment(host):
    # Extract this Compose service's flat environment map, without requiring Docker/YAML packages.
    text = (REPO / 'docker/validation/compose.cert-chain-scaling.yaml').read_text()
    block = text.split('  client:\n', 1)[1].split('    environment:\n', 1)[1].split('    command:', 1)[0]
    def expand(match):
        key, operator, fallback = match.group(1), match.group(2), match.group(3)
        if host.get(key):
            return host[key]
        if operator == ':-':
            return fallback
        raise AssertionError('Compose requires missing host variable: ' + key)
    return {key: re.sub(r'\$\{([A-Z0-9_]+)(?:(:\?|:-)([^}]*))?\}', expand, value.strip('"'))
            for key, value in re.findall(r'^      ([A-Z0-9_]+): (.*)$', block, re.M)}


class Stage110ContractTests(unittest.TestCase):
    def test_runner_compose_measurement_and_validation(self):
        for depth in (2, 5):
            with self.subTest(depth=depth), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                args = SimpleNamespace(output=root / 'results', fixtures=root / 'fixtures')
                plan = dict(image_id='sha256:mock', seed=41000, repetitions=2, warmups=1,
                            git_commit='mock-commit')
                cell = dict(profile='ecdsa-p256', depth=depth, campaign=1, fixture_hash='mock-hash')
                with patch.object(runner.subprocess, 'run') as run, patch.object(
                        runner, 'validate_complete', return_value=('COMPLETE', [])):
                    runner.execute_cell(cell, args, plan, root / 'attempt', 'mock-commit')
                host = run.call_args_list[0].kwargs['env']
                env = client_environment(host)
                self.assertEqual(env['CERT_DEPTH_VALUE'], str(depth))
                self.assertEqual(env['CERT_PROFILE_NAME'], 'ecdsa-p256')
                # Map container mounts to the temporary host directory.
                for key in ('CERT_FIXTURE', 'SERVER_METRICS', 'CAMPAIGN_OUTPUT'):
                    env[key] = env[key].replace('/results/', str(args.output) + '/').replace('/fixtures/', str(args.fixtures) + '/')
                metrics = Path(env['SERVER_METRICS']); metrics.mkdir(parents=True)
                count = 0
                def handshake(command, **kwargs):
                    nonlocal count
                    count += 1
                    key = f'{count:064x}'
                    data = dict(client_random=key, reused=0, certificate_message_bytes=100,
                                certificate_verify_message_bytes=80, handshake_wall_ms=1,
                                handshake_cpu_ms=.5, transport_read_bytes=300, transport_written_bytes=200,
                                components={'peer_auth': {'wall_ms': .3, 'cpu_ms': .2}})
                    (metrics / (key + '.json')).write_text(json.dumps(data))
                    self.assertEqual(command[0], '/opt/mtc/openssl.sh')
                    return SimpleNamespace(returncode=0, stdout='Verify return code: 0 (ok)\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\n',
                                           stderr='PROFILE_METRICS ' + json.dumps(data) + '\n')
                name = f'ecdsa-p256-d{depth}-c1'
                argv = ['measure.py', '--runs', '2', '--warmups', '1', '--scenario',
                        f'ecdsa-p256-d{depth}', '--campaign', name, '--seed', str(41001 + depth * 100)]
                with patch.dict(os.environ, env, clear=True), patch.object(sys, 'argv', argv), patch.object(
                        measure.subprocess, 'run', side_effect=handshake), contextlib.redirect_stdout(io.StringIO()):
                    measure.main()
                self.assertEqual(count, 3)
                status, errors = runner.validate_complete(args.output / name, 'ecdsa-p256', depth, 1, plan, 'mock-hash')
                self.assertEqual((status, errors), ('COMPLETE', []))

    def test_missing_environment_stops_before_tls(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(sys, 'argv',
                ['measure.py', '--runs', '2', '--warmups', '0', '--scenario', 'x', '--campaign', 'x', '--seed', '1']), patch.object(
                measure.subprocess, 'run') as run, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                measure.main()
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
