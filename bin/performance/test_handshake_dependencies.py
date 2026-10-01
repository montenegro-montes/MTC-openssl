#!/usr/bin/env python3
"""Offline dependency tests: no Docker, certificates or measured handshakes."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import handshake_dependencies as deps

DRIVER = Path(__file__).with_name('mt-handshake-performance').read_text()
# Load definitions only, with a fixed repo path; never enter the CLI dispatcher.
FUNCTIONS = DRIVER.split('command=${1:-menu}')[0]
FUNCTIONS = FUNCTIONS.replace('source "$REPO/bin/lib/docker-preflight.sh"', ':')
FUNCTIONS = FUNCTIONS.replace('REPO=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)',
                              'REPO=' + shlex.quote(str(deps.REPO)))


def shell(code):
    return subprocess.run(['bash', '-c', FUNCTIONS + '\n' + code], capture_output=True, text=True)


def cell(root, profile='ecdsa-p256', depth=3, role='server'):
    d = root / profile / f'depth-{depth}'
    d.mkdir(parents=True)
    def cert(name):
        return f'-----BEGIN CERTIFICATE-----\n{name}\n-----END CERTIFICATE-----\n'
    entries = {'root.pem': cert('root'), 'server.pem': cert('leaf'), 'server.key': 'test only',
               'intermediates.pem': ''.join(cert(str(i)) for i in range(depth-2))}
    entries['server-chain.pem'] = entries['server.pem'] + entries['intermediates.pem']
    for name, content in entries.items():
        (d / name).write_text(content)
    (d / 'manifest.json').write_text(json.dumps(dict(profile=profile, depth_including_root=depth,
        role=role, transmitted_certificates=depth-1, root_transmitted=False,
        files_sha256={n: hashlib.sha256(v.encode()).hexdigest() for n,v in entries.items()})))
    return d


class Dependencies(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = patch.object(deps, 'REPO', self.root)
        self.repo.start()
        self.output = io.StringIO()
        self.stderr = contextlib.redirect_stderr(self.output)
        self.stderr.__enter__()

    def tearDown(self):
        self.stderr.__exit__(None,None,None)
        self.repo.stop()
        self.temp.cleanup()

    def test_client_chain_generator_depths(self):
        import fixture_builder as builder
        def openssl(*args):
            if '-out' in args:
                output = Path(args[args.index('-out')+1])
                if output.suffix == '.pem':
                    output.write_text(f'-----BEGIN CERTIFICATE-----\n{output.name}\n-----END CERTIFICATE-----\n')
                else:
                    output.write_bytes(b'public')
            return 'Signature Algorithm: ecdsa-with-SHA256'
        for depth in (2,3,4,5):
            out = self.root / f'client-d{depth}'
            with patch('sys.argv', ['fixture_builder.py','--output',str(out),
                    '--profile','ecdsa-p256','--depth',str(depth),'--role','client']), \
                    patch.object(builder,'run',side_effect=openssl) as run, \
                    patch.object(builder,'run_bytes',return_value=b'public'), \
                    patch.object(builder.os,'umask'):
                builder.main()
            calls = [c.args for c in run.call_args_list]
            self.assertTrue(any(c[0]=='verify' and 'sslclient' in c for c in calls))
            meta = json.loads((out/'manifest.json').read_text())
            self.assertEqual(meta['role'],'client')
            self.assertEqual(meta['transmitted_certificates'],depth-1)
            self.assertEqual((out/'intermediates.pem').read_text().count('BEGIN CERTIFICATE'),depth-2)

    def test_single_d2_no_generation(self):
        with patch.object(deps.subprocess, 'run') as run:
            self.assertEqual(deps.resolve(['ecdsa-p256'], [2], False, execute=True), [])
            run.assert_not_called()

    def test_single_d3_identifies_missing_without_generation(self):
        with patch.object(deps.subprocess, 'run') as run:
            self.assertEqual(deps.resolve(['ecdsa-p256'], [3], False), [])
            self.assertIn('X.509 server ecdsa-p256 D=3: MISSING', self.output.getvalue())
            run.assert_not_called()

    def test_found_chain_not_regenerated(self):
        cell(self.root/'artifacts/fixtures/test')
        with patch.object(deps.subprocess,'run') as run:
            self.assertEqual(len(deps.resolve(['ecdsa-p256'], [3], False, execute=True)), 1)
            run.assert_not_called()

    def test_mutual_d3_only_missing_client_prepared(self):
        cell(self.root/'artifacts/fixtures/server')
        def command(args, **kwargs):
            output = Path(args[args.index('--output')+1])
            if args[1].endswith('generate_fixtures.py'):
                self.assertEqual(args[args.index('--depth')+1], '3')
                self.assertEqual(args[args.index('--role')+1], 'client')
                cell(output, role='client')
            else:
                output.parent.mkdir(parents=True)
                output.write_text('{"passed": true}')
        with patch.object(deps.subprocess,'run', side_effect=command) as run:
            self.assertEqual(len(deps.resolve(['ecdsa-p256'], [3], True, execute=True)),2)
            self.assertEqual(run.call_count,2)  # generation plus validation, client only

    def test_all_depths_and_deduplicated_roles(self):
        req = deps.requirements(['a','b'], [2,3,4,5], True)
        self.assertEqual(len(req),12)
        self.assertEqual(len(req),len(set(req)))
        self.assertEqual({x[1] for x in req},{3,4,5})

    def test_validation_failure_stops_resolution(self):
        def command(args,**kwargs):
            output = Path(args[args.index('--output')+1])
            if args[1].endswith('generate_fixtures.py'): cell(output)
            else:
                output.parent.mkdir(parents=True)
                output.write_text('{"passed": false}')
        with patch.object(deps.subprocess,'run',side_effect=command):
            with self.assertRaisesRegex(ValueError,'did not PASS'):
                deps.resolve(['ecdsa-p256'],[3],False,execute=True)

    def test_partial_or_tampered_not_reused(self):
        d = cell(self.root/'artifacts/fixtures/test')
        (d/'server.pem').write_text('tampered')
        self.assertEqual(deps.resolve(['ecdsa-p256'],[3],False),[])

    def test_mutual_d2_reuse_and_hybrid_preserved(self):
        result = shell('''
command=run-native-mutual
configure_kem x25519_mlkem512
configure_depth 2
ACTIVE_CASES=("${MUTUAL_CASES[@]}")
preflight_mtc_generation() { :; }
resolve_mtc_inputs() { echo MTC_FOUND; }
MUTUAL_CLIENT_ROOT=artifacts/existing
validate_mutual_fixtures() { echo MUTUAL_FOUND; }
python3() { echo CHAINS_CHECK >&2; }
resolve_dependencies run
printf '%s %s\n' "$KEM_GROUP" "${common[*]}"
''')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('MUTUAL_FOUND',result.stdout)
        self.assertIn('-groups x25519_mlkem512',result.stdout)

    def test_all6_resolves_once(self):
        result = shell('''
command=run-native-pcap
configure_depth all
ACTIVE_CASES=("${CASES[@]}")
preflight_mtc_generation() { :; }
docker() { :; }
resolve_mtc_inputs() { echo MTC_ONCE; }
resolve_mutual_inputs() { echo MUTUAL_ONCE; }
python3() { echo CHAINS_ONCE >&2; }
resolve_dependencies run
''')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.count('MTC_ONCE'),1)
        self.assertEqual(result.stdout.count('MUTUAL_ONCE'),1)
        self.assertEqual(result.stderr.count('CHAINS_ONCE'),1)

    def test_daemon_missing_clean(self):
        result = shell('docker() { return 1; }; preflight_mtc_generation; echo SHOULD_NOT_RUN')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Docker daemon',result.stderr)
        self.assertNotIn('Traceback',result.stderr)
        self.assertNotIn('SHOULD_NOT_RUN',result.stdout)

    def test_stale_image_clean(self):
        result = shell('''docker() { if [[ "$1" == run ]]; then echo stale >&2; return 1; fi; }; preflight_mtc_generation; echo SHOULD_NOT_RUN''')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('rebuild 2',result.stderr)
        self.assertNotIn('Traceback',result.stderr)
        self.assertNotIn('SHOULD_NOT_RUN',result.stdout)

    def test_status_plan_do_not_prepare(self):
        for action in ('status','plan'):
            result = shell(f'''
command={action}
configure_depth all
ACTIVE_CASES=("${{CASES[@]}}")
preflight_mtc_generation() {{ fail 'unexpected Docker'; }}
resolve_mtc_inputs() {{ [[ "$1" == inspect ]] || fail generate; }}
resolve_mutual_inputs() {{ [[ "$1" == inspect ]] || fail generate; }}
python3() {{ [[ " $* " != *--execute* ]] || fail generate; }}
resolve_dependencies inspect
''')
            self.assertEqual(result.returncode,0,result.stderr)

    def test_gate_failure_never_measures(self):
        self.assertLess(DRIVER.index('    validate_selected_dependencies ||'),
                        DRIVER.index('    base_cases='))
        with tempfile.TemporaryDirectory() as directory:
            result = shell(f'''
REPO={shlex.quote(directory)}
configure_depth 2
PROFILES=(ecdsa-p256)
ACTIVE_CASES=(x509-simple)
cleanup() {{ :; }}
docker() {{ :; }}
start_server() {{ :; }}
client_command() {{ return 1; }}
validate_selected_dependencies || fail 'No measurements started.'
echo MEASURED
''')
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('MEASURED',result.stdout)
        self.assertIn('No measurements started',result.stderr)


if __name__ == '__main__':
    unittest.main()
