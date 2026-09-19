"""Pure planning, identity and integrity helpers; never starts Docker."""
import hashlib
import json
import random
import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
OPENSSL = '/opt/openssl-mtc/bin/openssl'
LIBS = '/opt/openssl-mtc/lib:/opt/openssl/lib:/opt/oqs/lib'
TLS_FLAGS = ['-tls1_3', '-groups', 'X25519', '-ciphersuites', 'TLS_AES_256_GCM_SHA384']
IDS = {'ecdsa-p256': '32473.101.1.1.1', 'mldsa65': '32473.112.1.1.1'}


def load(path):
    return json.loads(Path(path).read_text())


def save(path, value):
    path = Path(path)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    tmp.replace(path)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def protocol():
    return load(HERE / 'protocol.json')


def cases(spec):
    result = []
    for profile, sizes in spec['profiles'].items():
        for auth in spec['authentication']:
            for scheme, n in [('x509-ca', 0)] + [('mtc-landmark', n) for n in sizes]:
                result.append(dict(id=f'{profile}-{auth}-{scheme}-n{n}', profile=profile,
                                   authentication=auth, credential=scheme, tree_size=n))
    return result


def schedule(spec, stage):
    conditions = spec['conditions'] if stage != 'preflight' else spec['conditions'][:1]
    repetitions = spec['campaign_repetitions'] if stage == 'full' else 1
    warmups = spec['warmup_rounds'] if stage == 'full' else 0
    measured = spec['measured_rounds'] if stage == 'full' else 1
    blocks = [(c, rep) for c in conditions for rep in range(1, repetitions + 1)]
    rng = random.Random(spec['seed'] + {'preflight': 0, 'smoke': 1, 'full': 2}[stage])
    rng.shuffle(blocks)
    output = []
    for c, rep in blocks:
        rounds = []
        for phase, count in [('warmup', warmups), ('measured', measured)]:
            for index in range(1, count + 1):
                order = cases(spec)
                rng.shuffle(order)
                rounds.append(dict(phase=phase, round=index, cases=order))
        output.append(dict(id=f"{c['name']}-c{rep}", condition=c, repetition=rep, rounds=rounds))
    return output


def source_inventory():
    # Includes upstream MTC preparation and instrumentation dependencies, not historical data.
    paths = []
    for prefix in ['campaigns/network_authentication', 'docker/network_authentication', 'src/mtc']:
        paths.extend(p for p in (REPO / prefix).rglob('*') if p.is_file()
                     and '__pycache__' not in p.parts and p.suffix != '.pyc')
    paths.append(REPO / 'campaigns/validation/mutual_auth_crossover/patch_mutual_metrics.py')
    return {str(p.relative_to(REPO)): sha(p) for p in sorted(paths)}


def fixture_inventory(root):
    return {str(p.relative_to(root)): sha(p) for p in sorted(root.rglob('*')) if p.is_file()}


def verify_inventory(base, inventory):
    for name, digest in inventory.items():
        p = Path(base) / name
        require(p.is_file() and sha(p) == digest, f'Preservation mismatch: {p}')


def image_id(value):
    require(bool(re.fullmatch(r'sha256:[0-9a-f]{64}', value)), 'Use an immutable Docker image ID (sha256:...)')
    return value


def git_metadata():
    return {k: subprocess.check_output(['git', *args], cwd=REPO, text=True).strip()
            for k, args in [('commit', ['rev-parse', 'HEAD']), ('status', ['status', '--short'])]}


def frozen(root):
    root = Path(root).resolve()
    m = load(root / 'manifest.json')
    require(sha(root / 'manifest.json') == (root / 'manifest.sha256').read_text().strip(), 'Manifest changed')
    require(m['protocol'] == protocol(), 'Protocol differs from frozen protocol')
    verify_inventory(REPO, m['source_sha256'])
    verify_inventory(root / 'source', m['source_sha256'])
    require(source_inventory() == m['source_sha256'], 'Source inventory changed')
    fixtures = Path(m['fixtures'])
    verify_inventory(fixtures, m['fixture_sha256'])
    require(fixture_inventory(fixtures) == m['fixture_sha256'], 'Fixture inventory changed')
    return m


def tls_arguments(case, *, missing_client=False):
    p = case['profile']; n = case['tree_size']
    base = f'/fixtures/{p}'
    server = ['-accept', '4433', '-naccept', '1', *TLS_FLAGS, '-num_tickets', '0', '-www', '-state', '-lab_metrics']
    client = ['-connect', 'server:4433', '-servername', 'server', *TLS_FLAGS,
              '-no_ticket', '-verify_return_error', '-state', '-lab_metrics']
    mutual = case['authentication'] == 'mutual'
    if case['credential'] == 'x509-ca':
        server += ['-cert', f'{base}/server/leaf-0000.pem', '-key', f'{base}/server/leaf-0000.key']
        client += ['-CAfile', f'{base}/server/ca.pem', '-verify_hostname', 'server']
        if mutual:
            server += ['-CAfile', f'{base}/client/ca.pem']
            if not missing_client:
                client += ['-cert', f'{base}/client/leaf-0000.pem', '-key', f'{base}/client/leaf-0000.key']
    else:
        server += ['-cert', f'{base}/server/mtc-n{n}/landmark-0000.pem',
                   '-key', f'{base}/server/leaf-0000.key', '-mtc_id', IDS[p], '-mtc_landmark']
        client += ['-mtc_trust', f'{base}/server/mtc-n{n}/trust.bin', '-mtc_landmark']
        if mutual:
            server += ['-mtc_client_trust', f'{base}/client/mtc-n{n}/trust.bin']
            if not missing_client:
                client += ['-cert', f'{base}/client/mtc-n{n}/landmark-0000.pem',
                           '-key', f'{base}/client/leaf-0000.key', '-mtc_client_id', IDS[p]]
    if mutual:
        server += ['-Verify', '1', '-verify_return_error']
    return server, client
