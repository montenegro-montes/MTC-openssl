"""Issue compact credentials and one signed root in a NEW directory; preserve prior phases."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import time

OPENSSL = '/opt/openssl/bin/openssl'

def command(*args, data=None):
    return subprocess.run([OPENSSL, *map(str, args)], input=data, capture_output=True, check=True).stdout

def dates(cert):
    values = command('x509', '-in', cert, '-noout', '-startdate', '-enddate').decode().splitlines()
    return [int(dt.datetime.strptime(v.split('=', 1)[1], '%b %d %H:%M:%S %Y GMT').replace(tzinfo=dt.timezone.utc).timestamp()) for v in values]

def spki(cert):
    public = command('x509', '-in', cert, '-pubkey', '-noout')
    return command('pkey', '-pubin', '-outform', 'DER', data=public)

def credential(cert, hostname):
    if len(hostname) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in hostname.split('.')):
        raise ValueError('Only canonical lowercase DNS names are supported')
    nb, na = dates(cert)
    name = hostname.encode('ascii')
    return b'MTC2' + struct.pack('!H', len(name)) + name + struct.pack('!QQ', nb, na) + hashlib.sha256(spki(cert)).digest() + b'\1'

def tree(values):
    levels = [[hashlib.sha256(b'\0' + value).digest() for value in values]]
    while len(levels[-1]) > 1:
        previous = levels[-1]
        levels.append([hashlib.sha256(b'\1' + previous[i] + previous[min(i+1, len(previous)-1)]).digest() for i in range(0, len(previous), 2)])
    root = levels[-1][0]
    proofs = []
    for index in range(len(values)):
        pos = index; siblings = []
        for level in levels[:-1]:
            siblings.append(level[pos-1 if pos & 1 else min(pos+1, len(level)-1)])
            pos //= 2
        proofs.append(b'MTP1' + struct.pack('!II', len(values), index) + root + bytes([len(siblings)]) + b''.join(siblings))
    return root, proofs

def bundle(cred, proof):
    return b'MCB2' + struct.pack('!H', len(cred)) + cred + struct.pack('!H', len(proof)) + proof + b'\0\0'

def prepare(output, scenario, leaves, cert_base):
    output.mkdir()
    source = cert_base / scenario
    ca, cakey = source / 'ca.pem', source / 'ca.key'
    certificates = [source / 'server.pem']; names = ['server']
    timings = {}
    issued = output / 'issued'; issued.mkdir()
    start = time.perf_counter_ns()
    for index in range(1, leaves):
        name = f'member-{index}.lab'; names.append(name)
        key = issued / f'{index}.key'; cert = issued / f'{index}.pem'; csr = issued / f'{index}.csr'
        key_args = ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'] if scenario == 'classic' else ['-algorithm', 'mldsa65']
        command('genpkey', *key_args, '-out', key)
        command('req', '-new', '-key', key, '-subj', '/CN=' + name, '-out', csr)
        ext = issued / f'{index}.cnf'
        ext.write_text(f'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{name}\n')
        command('x509', '-req', '-in', csr, '-CA', ca, '-CAkey', cakey, '-set_serial', str(index + 1000), '-days', '30', '-extfile', ext, '-out', cert)
        certificates.append(cert)
    timings['extra_x509_fixture_issuance_ms'] = (time.perf_counter_ns() - start) / 1e6
    start = time.perf_counter_ns()
    values = []
    for cert, name in zip(certificates, names):
        command('verify', '-CAfile', ca, '-verify_hostname', name, '-purpose', 'sslserver', cert)
        values.append(credential(cert, name))
    timings['credential_extraction_and_x509_validation_ms'] = (time.perf_counter_ns() - start) / 1e6
    subprocess.run(['/opt/mt/bin/mt_bundle', str(output/'x509-merkle'), *map(str,certificates)], check=True)
    start = time.perf_counter_ns(); root, proofs = tree(values)
    timings['tree_and_all_proofs_ms'] = (time.perf_counter_ns() - start) / 1e6
    intervals = [dates(cert) for cert in certificates] + [dates(ca)]
    nb = max(x[0] for x in intervals); na = min(x[1] for x in intervals)
    ca_spki = spki(ca)
    header = b'MTR2' + struct.pack('!I', leaves) + root + struct.pack('!QQ', nb, na) + hashlib.sha256(ca_spki).digest()
    (output / 'root.header').write_bytes(header)
    start = time.perf_counter_ns()
    args = ['pkeyutl', '-sign', '-rawin', '-inkey', cakey, '-in', output / 'root.header']
    if scenario == 'classic': args += ['-digest', 'sha256']
    signature = command(*args)
    timings['root_signature_process_ms'] = (time.perf_counter_ns() - start) / 1e6
    signed = header + struct.pack('!H', len(signature)) + signature
    (output / 'root.signed').write_bytes(signed)
    for index, (value, proof) in enumerate(zip(values, proofs)):
        (output / f'credential-{index:04d}.bin').write_bytes(value)
        (output / f'proof-{index:04d}.bin').write_bytes(proof)
        (output / f'bundle-{index:04d}.bin').write_bytes(bundle(value, proof))
    info = {'format': 'compact-v2', 'scenario': scenario, 'leaves': leaves,
            'leaf0_x509_sha256': hashlib.sha256(certificates[0].read_bytes()).hexdigest(),
            'authority_spki_sha256': hashlib.sha256(ca_spki).hexdigest(),
            'root_signed_bytes': len(signed), 'root_signature_bytes': len(signature),
            'credential0_bytes': len(values[0]), 'proof0_bytes': len(proofs[0]),
            'bundle0_bytes': len(bundle(values[0], proofs[0])), 'leaf0_spki_bytes': len(spki(certificates[0])),
            'leaf0_der_bytes': len(command('x509', '-in', certificates[0], '-outform', 'DER')),
            'not_before': nb, 'not_after': na, 'offline_timings': timings,
            'offline_timing_note': 'Python/openssl process wall times, not isolated C cryptographic operation costs'}
    (output / 'manifest.json').write_text(json.dumps(info, indent=2) + '\n')
    return info

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--both', action='store_true')
    parser.add_argument('--scenario', choices=['classic', 'pq'], default='classic')
    parser.add_argument('--leaves', type=int, default=16)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cert-base', type=Path, default=Path('/work/certs'))
    args = parser.parse_args()
    if not 1 <= args.leaves <= 1024: parser.error('leaves must be 1..1024')
    if args.output.exists(): parser.error('Output already exists; choose a new directory. Previous data are preserved.')
    os.umask(0o077)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=args.output.parent, prefix='.preparing-') as temp:
        stage = Path(temp) / 'batch'; stage.mkdir()
        for scenario in (['classic', 'pq'] if args.both else [args.scenario]):
            prepare(stage / scenario, scenario, args.leaves, args.cert_base)
        os.rename(stage, args.output)
    print(args.output)
