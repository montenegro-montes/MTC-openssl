"""Explicit, bounded local Docker interoperability test; no image builds."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from trust_ids import configured_ids

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def command(args, timeout=30):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def required(args, timeout=30):
    result = command(args, timeout)
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout or 'Command failed')
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--server-image', default='mt-tls-mtc:local')
    parser.add_argument('--client-image', default='mt-browser-boringssl:wire')
    parser.add_argument('--profile', choices=['ecdsa-p256', 'ecdsa-p384', 'ecdsa-p521', 'mldsa44', 'mldsa65', 'mldsa87'], default='ecdsa-p256')
    parser.add_argument('--mode', choices=['standalone', 'landmark'], default='standalone')
    parser.add_argument('--mtc-root', type=Path,
                        help='MTC fixture root containing batch16/mtc and population')
    parser.add_argument('--fixture', type=Path)
    parser.add_argument('--key', type=Path)
    parser.add_argument('--ordinary-cert', type=Path)
    args = parser.parse_args()
    if args.mtc_root is None and (args.fixture is None or args.key is None):
        parser.error('--mtc-root is required unless both --fixture and --key are supplied')
    if not args.execute:
        print(f'PLAN: {args.profile}/{args.mode}; 4 isolated TLS connections: valid, wrong hostname, altered proof, missing negotiation.')
        print('No Docker or TLS executed. Add --execute to run.')
        return
    root = args.mtc_root.resolve() if args.mtc_root is not None else None
    fixture = (args.fixture or root / 'batch16/mtc' / args.profile).resolve()
    key = (args.key or root / 'population' / args.profile / '0.key').resolve()
    ordinary = (args.ordinary_cert or key.with_suffix('.pem')).resolve()
    cert_name = args.mode + '-0000.pem'
    trust_name = 'trust.bin' if args.mode == 'landmark' else 'authority.bin'
    for path in [key, ordinary, fixture / trust_name, fixture / cert_name, fixture / 'manifest.json']:
        if not path.is_file():
            raise FileNotFoundError(path)
    manifest = json.loads((fixture / 'manifest.json').read_text())
    if manifest.get('profile', manifest.get('crypto_family')) != args.profile:
        raise ValueError('Fixture profile mismatch')
    ids = configured_ids((fixture / trust_name).read_bytes(), args.mode)
    if ids['caid'] != manifest['ca_id']:
        raise ValueError('Trust config / manifest CA mismatch')
    ca_id = ids['selected_id']  # Server selects the individual, not the CH group.
    parent = REPO / 'artifacts/results'
    parent.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix='browser-mtc-tls-', dir=parent))
    print(f'Evidence: {out}', flush=True)
    summary = {'status': 'running', 'tls_executed': False, 'cases': [], 'profile': args.profile, 'mode': args.mode,
               'configured_trust_anchor_ids': ids}
    try:
        images = {name: required(['docker', 'image', 'inspect', '--format', '{{.Id}}', tag])
                  for name, tag in [('server', args.server_image), ('client', args.client_image)]}
        summary['images'] = images
        summary['source_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                    for p in HERE.iterdir() if p.is_file()}
        public = out / 'public'
        public.mkdir()
        for name in [trust_name, cert_name, 'manifest.json']:
            shutil.copyfile(fixture / name, public / name)
        shutil.copyfile(ordinary, public / 'ordinary.pem')
        der = base64.b64decode(''.join(line for line in (public / cert_name).read_text().splitlines()
                                       if not line.startswith('-----')), validate=True)
        altered = der[:-1] + bytes([der[-1] ^ 1])
        encoded = base64.b64encode(altered).decode()
        (public / 'altered.pem').write_text('-----BEGIN CERTIFICATE-----\n' +
            '\n'.join(encoded[i:i+64] for i in range(0, len(encoded), 64)) + '\n-----END CERTIFICATE-----\n')
        summary['public_input_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                           for p in public.iterdir()}
        build = out / 'build'
        build.mkdir()
        result = command(['docker', 'run', '--rm', '--network', 'none',
            '-v', f'{HERE}:/port:ro', '-v', f'{build}:/build', images['client'],
            'sh', '/port/build-client.sh', '/build'], timeout=120)
        (out / 'build.log').write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f'Client build failed; see {out / "build.log"}')
        for label, cert, hostname, rejection, negotiate in [
            ('valid', cert_name, 'server', None, True),
            ('wrong-hostname', cert_name, 'wrong.invalid', 'hostname', True),
            ('altered-proof', 'altered.pem', 'server', 'proof', True),
            ('missing-negotiation', 'ordinary.pem', 'server', 'negotiation', False),
        ]:
            server = None
            try:
                server = required(['docker', 'run', '-d', '--network', 'none',
                    '-v', f'{public}:/fixture:ro', '-v', f'{key}:/server.key:ro',
                    '--entrypoint', '/opt/mtc/openssl.sh', images['server'],
                    's_server', '-accept', '127.0.0.1:4433', '-tls1_3',
                    '-groups', 'X25519', '-ciphersuites', 'TLS_AES_256_GCM_SHA384',
                    '-cert', f'/fixture/{cert}', '-key', '/server.key',
                    *(['-mtc_id', ca_id] if negotiate else []),
                    '-num_tickets', '0', '-www', '-naccept', '1'])
                deadline = time.monotonic() + 20
                while True:
                    logs = command(['docker', 'logs', server])
                    if 'ACCEPT' in logs.stdout + logs.stderr:
                        break
                    if time.monotonic() > deadline or required(['docker', 'inspect', '--format', '{{.State.Running}}', server]) != 'true':
                        raise RuntimeError(f'{label}: server not ready; see server log')
                    time.sleep(0.2)
                summary['tls_executed'] = True
                result = command(['docker', 'run', '--rm', '--network', f'container:{server}',
                    '-v', f'{public}:/fixture:ro', '-v', f'{build}:/build:ro',
                    images['client'], '/build/tls-client', f'/fixture/{trust_name}', hostname, args.mode], timeout=30)
                log = result.stdout + result.stderr
                (out / f'{label}-client.log').write_text(log)
                if rejection is None:
                    passed = result.returncode == 0 and 'TLS_OK: TLSv1.3 ' in log
                else:
                    passed = result.returncode == 1 and f'MTC_REJECT: {rejection}\n' in log and 'TLS_OK:' not in log
                summary['cases'].append({'name': label, 'passed': passed, 'returncode': result.returncode})
                print(('PASS' if passed else 'FAIL') + ': ' + label, flush=True)
                if not passed:
                    raise RuntimeError(f'{label}: unexpected result; see client/server logs')
            finally:
                if server:
                    logs = command(['docker', 'logs', server])
                    (out / f'{label}-server.log').write_text(logs.stdout + logs.stderr)
                    required(['docker', 'rm', '-f', server])
        summary['status'] = 'passed'
        print(f'RESULT: 4 PASS, 0 FAIL (TLS 1.3, {args.profile}, {args.mode})')
    except Exception as exc:
        summary['status'] = 'failed'
        summary['error'] = str(exc)
        raise
    finally:
        (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')


if __name__ == '__main__':
    main()
