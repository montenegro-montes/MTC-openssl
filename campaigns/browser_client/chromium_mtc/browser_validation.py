#!/usr/bin/env python3
"""Evidence-gated browser battery; trust changes require explicit trust actions."""
import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
import getpass
import hashlib
import html
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from urllib.parse import urlsplit
from urllib.request import urlopen

from cryptography import x509 as cryptography_x509
from cryptography.hazmat.primitives.asymmetric import ec

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE))
from export_chromium_anchor import parse_landmark, parse_standalone, core
from config_formats import decode_mtb2

HOST = 'server.mtc.example.com'
PROFILE = 'ecdsa-p256'
PROFILES = ('ecdsa-p256', 'ecdsa-p384', 'ecdsa-p521', 'mldsa44', 'mldsa65', 'mldsa87')
# Compatibility context for existing PCAP callers; set only after fixture selection.
REQUESTED = SELECTED = CA = None
DOCKER_RUN_COUNT = 0
CASES = ('mtc-positive', 'mtc-no-trust', 'mtc-bad-merkle', 'mtc-bad-serial', 'x509-positive')
TLS = dict(version='TLS 1.3', group='X25519', cipher='TLS_AES_256_GCM_SHA384',
           tickets=False, client_authentication=False, port=4433)
CDP_STABILIZATION_SETTLE_SECONDS = 1.0
KEY_ESTABLISHMENTS = {
    'x25519': dict(label='X25519', openssl_group='X25519', netlog_group=29),
    'x25519-mlkem768': dict(label='X25519+ML-KEM768', openssl_group='X25519MLKEM768', netlog_group=0x11ec),
}
LABEL = 'mtc.browser-validation'
PAGE_HTML = '''<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <link rel="icon" href="data:,">
  <title>MTC browser test</title>
</head>
<body>
  <h1>MTC browser test</h1>
  <p id="result">TLS browser validation page</p>
</body>
</html>
'''


def page_target(case, run_root):
    return 'browser-test.html?mtc_case='+case+'&run='+run_root.name


def key_establishment_config(key_establishment):
    require(key_establishment in KEY_ESTABLISHMENTS, 'Unsupported key-establishment group')
    selected = KEY_ESTABLISHMENTS[key_establishment]
    return dict(TLS, group=selected['openssl_group'], key_establishment=key_establishment,
                key_establishment_label=selected['label'], netlog_group=selected['netlog_group'])


def browser_page(case, run_root, credentials, browser_mode, key_establishment='x25519'):
    if case != 'mtc-positive' or browser_mode != 'headed':
        return PAGE_HTML
    mtc = credentials['mtc']
    fields = [
        ('Case', case), ('Mode', 'Visible browser inspection'),
        ('Authentication configured', 'MTC; server-only'), ('Signature profile', mtc['profile']),
        ('TLS version configured', TLS['version']), ('Cipher suite configured', TLS['cipher']),
        ('Group restricted by server', key_establishment_config(key_establishment)['group']),
        ('Session tickets configured', 'Disabled'),
        ('MTC tree size', mtc['tree_size']), ('MTC mode', mtc['mode']), ('MTC leaf', mtc['leaf']),
        ('CA ID', mtc['ca_id']), ('Requested TAI expected (0xca34)', mtc['requested_tai']),
        ('Selected TAI expected (0xca34)', mtc['selected_tai']),
        ('Target host', HOST+':'+str(TLS['port'])), ('Target path', '/'+page_target(case, run_root)),
    ]
    details = '<section><h2>Connection configuration</h2><dl>'+''.join(
        '<dt>'+html.escape(label)+'</dt><dd>'+html.escape(str(value))+'</dd>' for label, value in fields)
    details += ('</dl><p>These values describe the test configuration, not observed negotiation. '
                'This page does not report MTC verification, CertificateVerify, Finished, '
                'received HTTP headers or a final validation result.</p></section>\n')
    return PAGE_HTML.replace('</body>', details+'</body>')


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def take_number(data, pos, size):
    end = pos + size
    if end > len(data):
        raise ValueError('truncated binary field')
    return int.from_bytes(data[pos:end], 'big'), end


def take_vector(data, pos, size=2):
    length, pos = take_number(data, pos, size)
    end = pos + length
    if end > len(data):
        raise ValueError('truncated binary vector')
    return data[pos:end], end


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write(path, value):
    with Path(path).open('x') as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write('\n')


def command(args, *, check=True, timeout=60, **kwargs):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True,
                            timeout=timeout, **kwargs)
    if check and result.returncode:
        raise ValueError(f'Command failed ({result.returncode}): {shlex.join(list(map(str, args)))}\n{result.stderr[-1500:]}')
    return result


def stamp():
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ') + '-' + uuid.uuid4().hex[:8]


def hashes(root):
    files = sorted(root.rglob('*'))
    require(not any(p.is_symlink() for p in files), 'Symlink in fixture')
    return {str(p.relative_to(root)): sha(p) for p in files if p.is_file()}


def check_saved_hashes(root, saved, *, complete=False):
    require(isinstance(saved, dict) and bool(saved), 'Empty fixture hash evidence')
    for name, expected in saved.items():
        p = Path(name)
        require(not p.is_absolute() and '..' not in p.parts, 'Unsafe hash path')
        require((root / p).is_file() and sha(root / p) == expected, 'Stale fixture hash: ' + name)
    if complete:
        require(hashes(root) == saved, 'Fixture hash inventory differs from validation evidence')


def pem_certificates(data):
    blocks = re.findall(rb'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----', data)
    require(bool(blocks), 'Missing PEM certificate')
    return [block+b'\n' for block in blocks]


def certificate_der(pem):
    blocks = pem_certificates(pem)
    require(len(blocks) == 1, 'Expected one certificate')
    return base64.b64decode(re.sub(rb'\s+', b'', blocks[0].split(b'-----')[2]), validate=True)


def docker_temporary_directory(prefix):
    root = REPO / '.mt-state' / 'chromium-tmp'
    root.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(prefix=prefix, dir=root)


def docker_openssl(directory, args, image='mt-tls-mtc:local'):
    global DOCKER_RUN_COUNT
    DOCKER_RUN_COUNT += 1
    return command(['docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
                    '--user', f'{os.getuid()}:{os.getgid()}', '-e', 'LC_ALL=C',
                    '-v', str(Path(directory).resolve())+':/work:ro', '-w', '/work',
                    '--entrypoint', '/opt/mtc/openssl.sh', image, *args])


class DockerOpenSSLBatch:
    """One ephemeral container, preserving one checked OpenSSL process per call."""
    def __init__(self, image='mt-tls-mtc:local'):
        self.image = image
        self.root = (REPO/'.mt-state/chromium-tmp').resolve()
        self.name = 'mtc-openssl-batch-'+uuid.uuid4().hex[:16]
        self.started = False
        self.check_count = 0

    def __enter__(self):
        global DOCKER_RUN_COUNT
        self.root.mkdir(parents=True, exist_ok=True)
        DOCKER_RUN_COUNT += 1
        command(['docker', 'run', '-d', '--rm', '--pull', 'never', '--network', 'none',
                 '--name', self.name, '--user', f'{os.getuid()}:{os.getgid()}',
                 '-e', 'LC_ALL=C', '-v', str(self.root)+':/workspace:ro',
                 '--entrypoint', '/bin/sh', self.image, '-c',
                 'while :; do sleep 3600; done'])
        self.started = True
        return self

    def __call__(self, directory, args, image='mt-tls-mtc:local'):
        require(self.started, 'OpenSSL batch container is not running')
        require(image == self.image, 'OpenSSL batch image mismatch')
        directory = Path(directory).resolve()
        try:
            relative = directory.relative_to(self.root)
        except ValueError as error:
            raise ValueError('OpenSSL batch directory is outside the isolated workspace') from error
        require(relative.parts and '..' not in relative.parts,
                'Malformed OpenSSL batch working directory')
        self.check_count += 1
        openssl_args = list(map(str, args))
        invocation = ['docker', 'exec', '-e', 'LC_ALL=C', '-w',
                      '/workspace/'+relative.as_posix(), self.name,
                      '/opt/mtc/openssl.sh', *openssl_args]
        try:
            return command(invocation)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            raise ValueError(
                f'OpenSSL batch check #{self.check_count} failed: '
                f'{shlex.join(openssl_args)}: {error}') from error

    def __exit__(self, exception_type, exception, traceback):
        if not self.started:
            return False
        self.started = False
        cleanup = command(['docker', 'rm', '-f', self.name], check=False)
        if exception_type is None:
            require(cleanup.returncode == 0,
                    f'OpenSSL batch container cleanup failed ({cleanup.returncode}): {cleanup.stderr[-1500:]}')
        return False


def profile_options(profile):
    require(profile in PROFILES, 'Unsupported signature profile')
    if profile.startswith('ecdsa-'):
        curve, digest = {'ecdsa-p256': ('P-256', 'sha256'), 'ecdsa-p384': ('P-384', 'sha384'),
                         'ecdsa-p521': ('P-521', 'sha512')}[profile]
        return ['-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:'+curve], ['-'+digest]
    return ['-algorithm', profile], []


def normalized_algorithm(name):
    return re.sub(r'[-_\s]+', '', name).lower()


def check_public_profile(text, profile):
    if profile.startswith('ecdsa-'):
        curve = {'ecdsa-p256': 'P-256', 'ecdsa-p384': 'P-384', 'ecdsa-p521': 'P-521'}[profile]
        require(re.search(r'NIST CURVE: '+curve+r'\s*$', text, re.M), 'Public-key profile mismatch')
    else:
        names = re.findall(r'\bML[-_\s]*DSA[-_\s]*[0-9]+\b', text, re.I)
        require(bool(names) and all(normalized_algorithm(name) == profile for name in names), 'Public-key profile mismatch')


def certificate_info(directory, name, profile, image, *, signature=True,
                     openssl=docker_openssl):
    run = lambda args: openssl(directory, args, image).stdout
    text = run(['x509', '-in', name, '-noout', '-text'])
    public = run(['x509', '-in', name, '-pubkey', '-noout'])
    with docker_temporary_directory('browser-public-') as temp:
        Path(temp, 'public.pem').write_text(public)
        check_public_profile(openssl(temp, ['pkey', '-pubin', '-in', 'public.pem', '-text', '-noout'], image).stdout, profile)
    if signature:
        expected = ('ecdsa-with-SHA'+{'ecdsa-p256':'256', 'ecdsa-p384':'384', 'ecdsa-p521':'512'}[profile]
                    if profile.startswith('ecdsa-') else 'ML-DSA-'+profile[5:])
        signatures = re.findall(r'Signature Algorithm:\s*(\S+)', text)
        normalize = str.lower
        if profile.startswith('mldsa'):
            signatures = re.findall(r'Signature Algorithm:[ \t]*([^\r\n]+)', text)
            normalize = normalized_algorithm
        require(len(signatures) == 2 and all(normalize(v) == normalize(expected) for v in signatures), 'Certificate signature profile mismatch')
    details = run(['x509', '-in', name, '-noout', '-subject', '-issuer', '-serial', '-dates', '-nameopt', 'RFC2253'])
    values = dict(line.split('=', 1) for line in details.splitlines() if '=' in line)
    before = datetime.strptime(values['notBefore'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
    after = datetime.strptime(values['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
    require(before <= datetime.now(timezone.utc) <= after, 'Expired/not-yet-valid certificate')
    extension = lambda key: run(['x509', '-in', name, '-noout', '-ext', key])
    return dict(public=public, subject=values['subject'], issuer=values['issuer'], serial=int(values['serial'], 16),
                not_before=before.isoformat(), not_after=after.isoformat(),
                constraints=extension('basicConstraints'), usage=extension('keyUsage'),
                eku=extension('extendedKeyUsage'), san=extension('subjectAltName'))


def web_leaf(cert_path, key_path, *, profile=PROFILE, image='mt-tls-mtc:local',
             signature=False, openssl=docker_openssl):
    require(not Path(cert_path).is_symlink() and not Path(key_path).is_symlink(), 'Symlink credential rejected')
    with docker_temporary_directory('browser-leaf-') as temp:
        shutil.copyfile(cert_path, Path(temp)/'cert.pem')
        shutil.copyfile(key_path, Path(temp)/'key.pem'); (Path(temp)/'key.pem').chmod(0o600)
        cert = certificate_info(temp, 'cert.pem', profile, image, signature=signature,
                                openssl=openssl)
        sans = re.findall(r'DNS:([^,\s]+)', cert['san'])
        require(HOST in sans, 'Wrong SAN: browser hostname absent')
        require('CA:FALSE' in cert['constraints'] and 'CA:TRUE' not in cert['constraints'], 'CA leaf rejected')
        require('Digital Signature' in cert['usage'], 'Missing Digital Signature KU')
        require('TLS Web Server Authentication' in cert['eku'], 'Missing serverAuth EKU')
        public = openssl(temp, ['pkey', '-in', 'key.pem', '-pubout'], image).stdout
        require(public.strip() == cert['public'].strip(), 'Certificate/key mismatch')
    return cert, dict(SAN=sans, KU=['Digital Signature'], EKU=['serverAuth'],
                      not_before=cert['not_before'], not_after=cert['not_after'],
                      hostname_validation=True, key_match=True)


def validate_mtc(fixture, profile=PROFILE, image='mt-tls-mtc:local', *,
                 openssl=docker_openssl):
    fixture = Path(fixture)
    manifest = read(fixture / 'manifest.json')
    require(manifest.get('server_hostname') == HOST, 'MTC manifest hostname mismatch')
    require(profile in manifest.get('profiles', []) and 16 in manifest.get('sizes', []), 'MTC profile/tree size mismatch')
    directory = fixture / 'batch16/mtc' / profile
    meta = read(directory / 'manifest.json')
    ca_id = meta['ca_id']
    require(isinstance(ca_id, str) and bool(ca_id), 'Missing MTC ca_id identity')
    require(meta.get('profile') == profile and meta.get('tree_size') == 16 and
            meta.get('draft') == core.DRAFT and meta.get('merkle_hash') == 'SHA-256', 'MTC metadata mismatch')
    check_saved_hashes(directory, read(directory / 'fixture-sha256.json'))
    cert_path, key_path = directory / 'landmark-0000.pem', fixture / 'population' / profile / '0.key'
    mtc_ca = directory / 'mtc-ca.der'
    mtc_ca_root = directory / 'mtc-representation-root.pem'
    require(mtc_ca.is_file() and mtc_ca_root.is_file(),
            'Missing MTC-07 CA certificate or representation root')
    cert, leaf = web_leaf(cert_path, key_path, profile=profile, image=image,
                          openssl=openssl)
    raw = (directory / 'trust.bin').read_bytes()
    anchor = parse_landmark(raw)
    selected_tai = anchor['landmark']['selected_trust_anchor_id']
    requested_tai = anchor['landmark']['requested_trust_anchor_id']
    require(cert['serial'] == anchor['log_number'] << 48,
            'MTC credential is not configured-log leaf 0')
    require(anchor['ca_id'] == ca_id and anchor['landmark']['tree_size'] == 16 and
            anchor['min_serial'] == anchor['log_number'] << 48 and
            anchor['max_serial'] == (anchor['log_number'] << 48) + 15 and
            anchor['landmark']['requested_trust_anchor_id'] == requested_tai and
            anchor['landmark']['selected_trust_anchor_id'] == selected_tai, 'MTC trust identity mismatch')
    # Authenticate the checkpoint, not just its typed structure or JSON syntax.
    bundle = decode_mtb2(raw)
    signers = bundle.authority.signers
    size = bundle.checkpoint.tree_size
    timestamp = bundle.checkpoint.timestamp
    root_hash = bundle.checkpoint.root_hash
    require(timestamp <= int(time.time()), 'Future checkpoint timestamp')
    verified = set()
    for name, signature in bundle.checkpoint.signatures:
        ident = core.relid(name)
        require(ident not in verified, 'Duplicate checkpoint signer')
        matched = [(name, spki) for name, spki in signers if core.relid(name) == ident]
        require(len(matched) == 1, 'Unknown checkpoint signer')
        name, spki = matched[0]
        message = core.message(name, ca_id, 0, size, root_hash, timestamp)
        with docker_temporary_directory('browser-checkpoint-') as temp:
            for filename, data in [('public.der', spki), ('message.bin', message), ('signature.bin', signature)]:
                Path(temp, filename).write_bytes(data)
            public = openssl(temp, ['pkey', '-pubin', '-inform', 'DER', '-in', 'public.der', '-text', '-noout'], image).stdout
            check_public_profile(public, profile)
            digest = profile_options(profile)[1]
            openssl(temp, ['pkeyutl', '-verify', '-rawin', '-pubin', '-keyform', 'DER', '-inkey', 'public.der',
                           '-in', 'message.bin', '-sigfile', 'signature.bin',
                           *(['-digest', digest[0][1:]] if digest else [])], image)
        verified.add(ident)
    require(verified == {core.relid(name) for name, _ in signers}, 'Incomplete checkpoint authentication')
    der = certificate_der(cert_path.read_bytes())
    outer, tbs = core.certificate_parts(der)
    require(outer[1][2] == core.ALG and tbs[2][2] == core.ALG and tbs[3][2] == core.name(ca_id), 'MTC algorithm/issuer mismatch')
    require(outer[2][1][0] == 0, 'Invalid MTC bit string')
    proof = outer[2][1][1:]
    extensions, pos = take_vector(proof, 0)
    start, pos = take_number(proof, pos, 6)
    end, pos = take_number(proof, pos, 6)
    path, pos = take_vector(proof, pos)
    signatures, pos = take_vector(proof, pos, 3)
    require(pos == len(proof), 'Trailing MTC proof data')
    require(not extensions and not signatures and len(path) % 32 == 0, 'Invalid landmark proof/signatures')
    calculated = core.evaluate(core.entry(outer[0][2]), 0, start, end,
                                [path[i:i+32] for i in range(0, len(path), 32)])
    require(any(s['start'] == start and s['end'] == end and s['hash'] == calculated.hex()
                for s in anchor['landmark']['trusted_subtrees']), 'MTC inclusion proof mismatch')
    evidence_paths = sorted(fixture.parent.glob(fixture.name + '-validation*/validation.json'))
    failures = sorted(fixture.parent.glob(fixture.name + '-validation*/failure.json'))
    require(not failures, 'Existing failed functional validation: ' + ', '.join(map(str, failures)))
    evidence = None
    for p in evidence_paths:
        d = read(p)
        require(d.get('passed') is True and d.get('server_hostname') == HOST and any(
            c.get('profile') == profile and c.get('tree_size') == 16 and c.get('mtc_mode') == 'landmark' and c.get('success') is True
            for c in d.get('cells', [])), 'Existing functional evidence does not PASS')
        if 'fixture_hashes' in d:
            check_saved_hashes(fixture, d['fixture_hashes'], complete=True)
        evidence = p
    image = (read(evidence) if evidence else manifest).get('provenance', {}).get('image_id')
    require(isinstance(image, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'Missing pinned MTC image')
    return dict(fixture=str(fixture.resolve()), cert=str(cert_path.resolve()), key=str(key_path.resolve()),
                trust=str((directory/'trust.bin').resolve()),
                mtc_ca=str(mtc_ca.resolve()), mtc_ca_root=str(mtc_ca_root.resolve()),
                profile=profile, tree_size=16, mode='landmark', leaf=0,
                hostname=HOST, validation_evidence=str(evidence.resolve()) if evidence else None,
                complete_evidence=bool(evidence and 'fixture_hashes' in read(evidence)),
                fixture_hash_status='MATCH' if evidence and 'fixture_hashes' in read(evidence) else 'LOCAL_HASHES_AND_CRYPTO_VERIFIED',
                ca_id=ca_id, requested_tai=requested_tai, selected_tai=selected_tai, image_id=image,
                cert_sha256=sha(cert_path), key_sha256=sha(key_path),
                trust_sha256=sha(directory/'trust.bin'), mtc_ca_sha256=sha(mtc_ca),
                mtc_ca_root_sha256=sha(mtc_ca_root), **leaf)


def prevalidated_mtc(fixture, validation, profile=PROFILE,
                     trust_mode='landmark'):
    require(trust_mode in ('landmark', 'standalone'),
            'Unsupported MTC trust mode')
    fixture, validation = Path(fixture).absolute(), Path(validation).absolute()
    for path in (fixture, validation):
        require(not any(p.is_symlink() for p in (path, *path.parents)), 'Symlink fixture/evidence path rejected')
    require(fixture.is_dir() and validation.is_file(), 'Selected MTC fixture/validation missing; rerun setup steps 20/30')
    evidence = read(validation)
    require(evidence.get('passed') is True and evidence.get('server_hostname') == HOST,
            'Selected MTC validation must PASS for the browser hostname')
    require(not (validation.parent/'failure.json').exists(), 'Failed validation evidence present')
    for field in ('fixture', 'fixtures', 'fixture_directory'):
        if field in evidence:
            require(Path(evidence[field]).resolve() == fixture.resolve(), 'Validation refers to another fixture')
    # A complete inventory is required: cryptographic checks are being reused, not repeated.
    require(not any(p.is_symlink() for p in fixture.rglob('*')), 'Symlink fixture contents rejected')
    check_saved_hashes(fixture, evidence.get('fixture_hashes'), complete=True)
    manifest = read(fixture/'manifest.json')
    require(manifest.get('server_hostname') == HOST, 'MTC manifest hostname mismatch')
    require(profile in manifest.get('profiles', []) and 16 in manifest.get('sizes', []), 'MTC profile/tree size mismatch')
    directory = fixture/'batch16/mtc'/profile
    meta = read(directory/'manifest.json')
    require(meta.get('profile') == profile and meta.get('tree_size') == 16
            and meta.get('draft') == core.DRAFT and meta.get('merkle_hash') == 'SHA-256', 'MTC metadata mismatch')
    check_saved_hashes(directory, read(directory/'fixture-sha256.json'))
    cells = [c for c in evidence.get('cells', []) if c.get('profile') == profile
             and c.get('tree_size') == 16 and c.get('mtc_mode') == trust_mode
             and c.get('success') is True]
    require(bool(cells), 'Selected validation lacks a successful profile/N=16/'
            + trust_mode + ' cell')
    image = evidence.get('provenance', {}).get('image_id')
    require(isinstance(image, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'Missing pinned MTC image')
    for cell in cells:
        require(cell.get('fixture_hash') == sha(directory/'manifest.json'), 'Validation cell fixture hash mismatch')
        require(cell.get('image_id') == image and cell.get('draft') == core.DRAFT, 'Validation cell provenance mismatch')
    for recorded in (manifest.get('provenance', {}), meta.get('provenance', {})):
        for field in ('image_id', 'source_hashes'):
            if field in recorded:
                require(recorded[field] == evidence.get('provenance', {}).get(field), 'MTC provenance mismatch: '+field)
    ca_id = meta.get('ca_id')
    require(isinstance(ca_id, str) and bool(ca_id), 'Missing MTC CA identity')
    cert_path = directory/(trust_mode+'-0000.pem')
    key_path, trust = fixture/'population'/profile/'0.key', directory/'trust.bin'
    mtc_ca = directory/'mtc-ca.der'
    mtc_ca_root = directory/'mtc-representation-root.pem'
    require(all(p.is_file() for p in (cert_path, key_path, trust, mtc_ca,
                                      mtc_ca_root)),
            'Missing selected MTC credential/trust/CA hierarchy')
    anchor = (parse_landmark(trust.read_bytes()) if trust_mode == 'landmark'
              else parse_standalone(trust.read_bytes()))
    requested = (anchor['landmark']['requested_trust_anchor_id']
                 if trust_mode == 'landmark'
                 else f"{ca_id}.2.{anchor['log_number']}.0")
    selected = (anchor['landmark']['selected_trust_anchor_id']
                if trust_mode == 'landmark' else ca_id)
    require(anchor['ca_id'] == ca_id
            and anchor['min_serial'] == anchor['log_number'] << 48
            and anchor['max_serial'] == (anchor['log_number'] << 48)+15,
            'MTC trust identity mismatch')
    if trust_mode == 'landmark':
        require(anchor['landmark']['tree_size'] == 16
                and anchor['landmark']['requested_trust_anchor_id'] == requested
                and anchor['landmark']['selected_trust_anchor_id'] == selected,
                'MTC landmark identity mismatch')
    outer, tbs = core.certificate_parts(certificate_der(cert_path.read_bytes()))
    require(int.from_bytes(tbs[1][1], 'big') == anchor['log_number'] << 48
            and outer[1][2] == core.ALG
            and tbs[2][2] == core.ALG and tbs[3][2] == core.name(ca_id), 'MTC leaf 0 algorithm/issuer mismatch')
    require(outer[2][1][0] == 0, 'Invalid MTC proof bit string')
    if trust_mode == 'standalone':
        proof = outer[2][1][1:]
        _, pos = take_vector(proof, 0)
        _, pos = take_number(proof, pos, 6)
        _, pos = take_number(proof, pos, 6)
        path, pos = take_vector(proof, pos)
        signatures, pos = take_vector(proof, pos, 3)
        require(pos == len(proof) and len(path) % 32 == 0 and signatures,
                'Malformed or unsigned standalone MTC proof')
    dates = core.items(tbs[4][1])
    require(len(dates) == 2 and all(t[0] in (23, 24) for t in dates), 'Invalid certificate validity')
    before, after = [datetime.strptime(t[1].decode(), '%y%m%d%H%M%SZ' if t[0] == 23 else '%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc) for t in dates]
    require(before <= datetime.now(timezone.utc) <= after, 'Expired/not-yet-valid certificate')
    return dict(fixture=str(fixture.resolve()), cert=str(cert_path.resolve()), key=str(key_path.resolve()),
                trust=str(trust.resolve()), mtc_ca=str(mtc_ca.resolve()),
                mtc_ca_root=str(mtc_ca_root.resolve()), profile=profile,
                tree_size=16, mode=trust_mode, leaf=0, hostname=HOST,
                validation_evidence=str(validation.resolve()), validation_sha256=sha(validation),
                complete_evidence=True, fixture_hash_status='MATCH', origin='reused-prevalidated',
                ca_id=ca_id, requested_tai=requested, selected_tai=selected, image_id=image,
                cert_sha256=sha(cert_path), key_sha256=sha(key_path),
                trust_sha256=sha(trust), mtc_ca_sha256=sha(mtc_ca),
                mtc_ca_root_sha256=sha(mtc_ca_root),
                SAN=[HOST], KU=['Digital Signature'], EKU=['serverAuth'],
                not_before=before.isoformat(), not_after=after.isoformat(), hostname_validation=True, key_match=True,
                verification_source='Selected successful functional validation and matching complete fixture hashes')


def preselect_mtc_fixture(repo, profile, trust_mode='landmark',
                          require_anchor=True):
    require(trust_mode in ('landmark', 'standalone'),
            'Unsupported MTC trust mode')
    candidates, audit = [], []
    for fixture in sorted((repo/'artifacts/mtc').glob('*')):
        if not (fixture/'manifest.json').is_file():
            continue
        record = dict(path=str(fixture))
        try:
            manifest = read(fixture/'manifest.json')
            require(manifest.get('server_hostname') == HOST, 'MTC manifest hostname mismatch')
            require(profile in manifest.get('profiles', []) and 16 in manifest.get('sizes', []),
                    'MTC profile/tree size mismatch')
            evidence_paths = sorted(fixture.parent.glob(fixture.name+'-validation*/validation.json'))
            require(bool(evidence_paths), 'Missing complete MTC validation evidence')
            locally_valid = []
            for evidence in evidence_paths:
                try:
                    locally_valid.append(prevalidated_mtc(
                        fixture, evidence, profile, trust_mode))
                except Exception:
                    continue
            require(bool(locally_valid), 'No matching complete MTC validation evidence')
            mtc = min(locally_valid, key=lambda item: item['validation_sha256'])
            suffix = ('-chromium-anchor-standalone.json'
                      if trust_mode == 'standalone'
                      else '-chromium-anchor.json')
            canonical = fixture.with_name(fixture.name+suffix)
            if canonical.exists() or canonical.is_symlink():
                require(canonical.is_file() and not canonical.is_symlink(),
                        'Unsafe canonical Chromium MTC anchor')
                require(read(canonical) == expected_anchor(mtc),
                        'Canonical Chromium MTC anchor content/provenance mismatch')
                mtc.update(anchor=str(canonical.resolve()),
                           anchor_sha256=sha(canonical),
                           anchor_origin='reused')
                record['anchor_status'] = 'MATCH'
            else:
                require(not require_anchor,
                        'Missing canonical Chromium MTC anchor')
                record['anchor_status'] = 'MISSING'
            dedicated = manifest.get('profiles') == [profile]
            identity = sha(fixture/'manifest.json')
            candidates.append((not dedicated, identity, mtc))
            record.update(valid=True, dedicated_profile=dedicated,
                          content_identity=identity)
        except Exception as error:
            record.update(valid=False, reason=str(error) or type(error).__name__)
        audit.append(record)
    if not candidates:
        prioritized = sorted(
            audit, key=lambda item: (
                'canonical' not in item.get('reason', '').lower(),
                'validation' not in item.get('reason', '').lower(),
                item['path']))
        diagnostics = '; '.join(
            Path(item['path']).name+': '+item.get('reason', 'incompatible')
            for item in prioritized[:8])
        anchor_text = ' with canonical anchor' if require_anchor else ''
        require(False, 'No locally valid MTC fixture'+anchor_text+
                f' for profile={profile}, trust_mode={trust_mode}. '
                +(diagnostics or 'No fixture manifests found'))
    selected_key = min(item[:2] for item in candidates)
    selected_candidates = [item[2] for item in candidates if item[:2] == selected_key]
    require(len(selected_candidates) == 1,
            f'Ambiguous content-identical MTC fixtures for profile={profile}')
    selected = selected_candidates[0]
    selected['origin'] = 'reused-prechecked'
    for record in audit:
        record['selected'] = record.get('valid', False) and Path(record['path']).resolve() == Path(selected['fixture'])
    return selected, audit


def precheck_formal_x509_fixture(repo, profile, depth, fixture_set):
    require(fixture_set == 'chromium-x509-depth-matrix-v1' and depth in (2, 3, 4, 5),
            'Optimized credentials require the formal X509 depth matrix')
    fixture = repo/'artifacts/x509'/fixture_set/profile/f'd{depth}'
    require(fixture.is_dir() and not fixture.is_symlink(),
            f'Missing formal X509 fixture: {fixture}')
    files = [fixture/name for name in ('manifest.json', 'server.pem', 'server.key', 'root.pem')]
    if depth > 2:
        files.append(fixture/'intermediates.pem')
    require(all(path.is_file() and not path.is_symlink() for path in files),
            'Formal X509 fixture files missing or unsafe')
    require(not any(path.is_symlink() for path in fixture.rglob('*')),
            'Symlink in formal X509 fixture')
    manifest = read(fixture/'manifest.json')
    require(manifest.get('fixture_set') == fixture_set and
            manifest.get('profile') == profile and manifest.get('family_id') == profile and
            manifest.get('depth') == depth and manifest.get('hostname') == HOST,
            'Formal X509 fixture identity/profile/depth mismatch')
    saved = manifest.get('files_sha256')
    check_saved_hashes(fixture, saved)
    actual = hashes(fixture)
    actual.pop('manifest.json', None)
    require(actual == saved, 'Formal X509 fixture hash inventory differs from manifest')
    require(saved.get('server.key') == manifest.get('server_key_sha256'),
            'Formal X509 server key provenance mismatch')
    require(certificate_sha256((fixture/'root.pem').read_bytes()) == manifest.get('root_der_sha256'),
            'Formal X509 root provenance mismatch')
    certificate = cryptography_x509.load_pem_x509_certificate((fixture/'server.pem').read_bytes())
    if profile.startswith('ecdsa-'):
        public = certificate.public_key()
        curves = {'ecdsa-p256': 'secp256r1', 'ecdsa-p384': 'secp384r1',
                  'ecdsa-p521': 'secp521r1'}
        signatures = {'ecdsa-p256': '1.2.840.10045.4.3.2',
                      'ecdsa-p384': '1.2.840.10045.4.3.3',
                      'ecdsa-p521': '1.2.840.10045.4.3.4'}
        require(isinstance(public, ec.EllipticCurvePublicKey) and
                public.curve.name == curves[profile] and
                certificate.signature_algorithm_oid.dotted_string == signatures[profile],
                'Formal X509 cryptographic profile mismatch')
    else:
        oid = {'mldsa44': '2.16.840.1.101.3.4.3.17',
               'mldsa65': '2.16.840.1.101.3.4.3.18',
               'mldsa87': '2.16.840.1.101.3.4.3.19'}[profile]
        public_key_oid = getattr(certificate, 'public_key_algorithm_oid', None)
        require((public_key_oid is None or public_key_oid.dotted_string == oid) and
                certificate.signature_algorithm_oid.dotted_string == oid,
                'Formal X509 cryptographic profile mismatch')
        # Older cryptography releases do not expose the ML-DSA SubjectPublicKeyInfo
        # OID. validate_x509() immediately performs the authoritative public-key
        # profile check with OpenSSL; the manifest alone is never trusted.
    return fixture


def validate_x509(fixture, *, profile=PROFILE, depth=2, image='mt-tls-mtc:local',
                  fixture_set=None, openssl=docker_openssl):
    require(profile in PROFILES and depth in (2, 3, 4, 5), 'Unsupported profile/depth')
    fixture = Path(fixture)
    cert_path, key_path, root_path = [fixture / n for n in ('server.pem', 'server.key', 'root.pem')]
    cert, leaf = web_leaf(cert_path, key_path, profile=profile, image=image,
                          signature=True, openssl=openssl)
    intermediate = fixture/'intermediates.pem'
    require(not root_path.is_symlink() and not intermediate.is_symlink(), 'Symlink chain rejected')
    chain = pem_certificates(intermediate.read_bytes()) if intermediate.is_file() and intermediate.stat().st_size else []
    require(len(chain) == depth-2, 'X509 intermediate count does not match requested depth')
    certificates = [cert_path.read_bytes(), *chain, root_path.read_bytes()]
    require(len({certificate_sha256(c) for c in certificates}) == depth, 'Duplicate chain certificate')
    with docker_temporary_directory('browser-chain-') as temp:
        for index, pem in enumerate(certificates):
            Path(temp, f'{index}.pem').write_bytes(pem)
        infos = [cert, *(certificate_info(temp, f'{i}.pem', profile, image,
                                          openssl=openssl) for i in range(1, depth))]
        require(infos[-1]['subject'] == infos[-1]['issuer'], 'Root is not self-issued')
        require(all('CA:TRUE' in c['constraints'] and 'Certificate Sign' in c['usage'] for c in infos[1:]), 'Invalid CA constraints/key usage')
        for i in range(depth-1):
            require(infos[i]['issuer'] == infos[i+1]['subject'], 'X509 chain ordering/depth mismatch')
            openssl(temp, ['verify', '-no-CAfile', '-no-CApath', '-no-CAstore', '-partial_chain',
                           '-trusted', f'{i+1}.pem', f'{i}.pem'], image)
        shutil.copyfile(root_path, Path(temp)/'root.pem')
        shutil.copyfile(cert_path, Path(temp)/'server.pem')
        openssl(temp, ['verify', '-no-CApath', '-no-CAstore', '-check_ss_sig', '-CAfile', 'root.pem', 'root.pem'], image)
        args = ['verify', '-no-CApath', '-no-CAstore', '-CAfile', 'root.pem', '-purpose', 'sslserver', '-verify_hostname', HOST]
        if chain:
            Path(temp, 'intermediates.pem').write_bytes(b''.join(chain))
            args += ['-untrusted', 'intermediates.pem']
        openssl(temp, [*args, 'server.pem'], image)
    manifest = fixture / 'manifest.json'
    complete = False
    manifest_data = {}
    if manifest.is_file():
        manifest_data = read(manifest)
        if manifest_data.get('files_sha256'):
            check_saved_hashes(fixture, manifest_data['files_sha256']); complete = True
    if fixture_set is not None:
        require(manifest_data.get('fixture_set') == fixture_set,
                'X509 fixture does not belong to requested fixture_set')
    return dict(fixture=str(fixture.resolve()), cert=str(cert_path.resolve()), key=str(key_path.resolve()),
                root=str(root_path.resolve()), intermediates=str(intermediate.resolve()) if intermediate.is_file() and intermediate.stat().st_size else None,
                certificate_sha256=sha(cert_path), key_sha256=sha(key_path), root_sha256=sha(root_path),
                profile=profile, depth=depth, intermediate_count=len(chain), hostname=HOST, complete_evidence=complete,
                fixture_set=manifest_data.get('fixture_set'),
                root_ca=True, root_self_signature_verified=True, **leaf)


def rank(candidate):
    name = Path(candidate['fixture']).name
    browser = HOST.replace('.', '-') in str(candidate['fixture'])
    timestamps = re.findall(r'\d{8}T\d{6}(?:\.\d+)?Z', str(candidate['fixture']))
    return (int(candidate.get('complete_evidence', False) and browser), int(candidate.get('complete_evidence', False)),
            int(browser), max(timestamps, default=''), candidate['fixture'])


def discover(paths, validator):
    audit, valid = [], []
    for p in sorted(set(map(Path, paths))):
        try:
            require(not p.is_symlink(), 'Symlink candidate')
            candidate = validator(p)
            valid.append(candidate); audit.append(dict(path=str(p), valid=True, rank=list(rank(candidate))))
        except (AttributeError, TypeError, ImportError) as e:
            raise ValueError('Credential validator/environment error; generation disabled: '+str(e)) from e
        except Exception as e:
            audit.append(dict(path=str(p), valid=False, reason=str(e) or type(e).__name__))
    selected = max(valid, key=rank) if valid else None
    for record in audit:
        record['selected'] = bool(selected and str(Path(record['path']).resolve()) == selected['fixture'])
        if record['valid']:
            record['reason'] = 'Highest deterministic rank: validated browser evidence, evidence, browser identity, timestamp, path' if record['selected'] else 'Valid, lower deterministic rank'
    return selected, audit


def select_or_generate(paths, validator, generator, audit_path=None):
    selected, audit = discover(paths, validator)
    if audit_path:
        write(audit_path, audit)
    if selected:
        selected['origin'] = 'reused'
    else:
        path = generator()
        selected = validator(path)  # A failed fallback is terminal, never used by Chromium.
        selected['origin'] = 'generated'
        audit.append(dict(path=str(path), valid=True, selected=True, reason='Fresh fallback; no valid existing candidate'))
    return selected, audit


def expected_anchor(mtc):
    raw = Path(mtc['trust']).read_bytes()
    expected = (parse_standalone(raw) if mtc.get('mode') == 'standalone'
                else parse_landmark(raw))
    require(expected['ca_id'] == mtc['ca_id'],
            'Anchor identity differs from selected fixture manifest')
    if mtc.get('mode') != 'standalone':
        require(expected['landmark']['requested_trust_anchor_id'] == mtc['requested_tai']
                and expected['landmark']['selected_trust_anchor_id'] == mtc['selected_tai'],
                'Anchor identity differs from selected fixture manifest')
    expected['source'] = dict(trust_file='trust.bin', trust_file_bytes=len(raw), trust_file_sha256=hashlib.sha256(raw).hexdigest())
    meta = read(Path(mtc['trust']).with_name('manifest.json'))
    for key in ('profile', 'draft', 'trust_anchor_draft', 'implementation_algorithm', 'merkle_hash'):
        expected[key] = meta.get(key)
    return expected


def choose_anchor(mtc, output):
    expected = expected_anchor(mtc); fixture = Path(mtc['fixture'])
    suffix = ('-chromium-anchor-standalone.json'
              if mtc.get('mode') == 'standalone'
              else '-chromium-anchor.json')
    canonical = fixture.with_name(fixture.name + suffix)
    if canonical.exists() or canonical.is_symlink():
        require(not canonical.is_symlink() and canonical.is_file() and read(canonical) == expected,
                'Canonical Chromium anchor content/provenance mismatch')
    candidates = sorted(set(fixture.parent.glob(fixture.name + '*chromium*.json')) | set(fixture.glob('*chromium*.json')))
    audit = []
    for p in candidates:
        try:
            require(not p.is_symlink() and read(p) == expected, 'Anchor content/provenance mismatch')
            audit.append(dict(path=str(p), valid=True))
        except Exception as e:
            audit.append(dict(path=str(p), valid=False, reason=str(e)))
    good = [Path(r['path']) for r in audit if r['valid']]
    if good:
        anchor, origin = good[0], 'reused'
    else:
        anchor, origin = output / 'chromium-anchor.json', 'generated'
        require(not anchor.exists(), 'Anchor output exists')
        command([sys.executable, HERE/'export_chromium_anchor.py', '--trust', mtc['trust'],
                 '--output', anchor, '--trust-mode', mtc.get('mode', 'landmark')])
        require(read(anchor) == expected, 'Exported anchor mismatch')
        descriptor, temporary = tempfile.mkstemp(prefix='.chromium-anchor-', dir=fixture.parent)
        try:
            with os.fdopen(descriptor, 'wb') as destination:
                destination.write(anchor.read_bytes())
                destination.flush()
                os.fsync(destination.fileno())
            try:
                os.link(temporary, canonical)
            except FileExistsError:
                require(not canonical.is_symlink() and canonical.is_file() and read(canonical) == expected,
                        'Canonical Chromium anchor content/provenance mismatch')
        finally:
            Path(temporary).unlink(missing_ok=True)
        require(read(canonical) == expected, 'Persisted Chromium anchor mismatch')
        anchor = canonical
    return dict(anchor=str(anchor.resolve()), anchor_sha256=sha(anchor), anchor_origin=origin, anchor_candidates=audit)


def generate_mtc(repo, output, image, profile=PROFILE):
    fixture = repo/'artifacts/mtc'/('browser-'+HOST.replace('.', '-')+'-'+profile+'-n16-'+stamp())
    validation = fixture.with_name(fixture.name+'-validation')
    for action, extra in [('generate', ['--output', fixture]), ('validate', ['--fixtures', fixture, '--output', validation])]:
        result = command([sys.executable, HERE/'fixtures.py', action, *extra, '--profile', profile, '--server-hostname', HOST, '--image', image, '--execute'], timeout=1800)
        (output/(action+'-mtc.stdout.log')).write_text(result.stdout)
        (output/(action+'-mtc.stderr.log')).write_text(result.stderr)
    return fixture


def generate_x509(repo, profile=PROFILE, depth=2, image='mt-tls-mtc:local'):
    require(profile in PROFILES and depth in (2, 3, 4, 5),
            'Unsupported profile/depth')
    out = repo/'artifacts/x509'/('chromium-'+HOST.replace('.', '-')+'-'+profile+'-d'+str(depth)+'-'+stamp())
    out.mkdir(parents=True, exist_ok=False)
    key_options, digest = profile_options(profile)
    # Temporary issuer keys/CSRs/configs never become fixture files.
    with tempfile.TemporaryDirectory(prefix='issuance-', dir=out) as temporary:
        scratch = Path(temporary)
        commands = []
        labels = ['root', *('intermediate-'+str(i) for i in range(depth-2)), 'server']
        for index, label in enumerate(labels):
            ca = label != 'server'
            subject = ('Chromium MTC comparison lab '+out.name[-8:] if index == 0 else
                       'Browser intermediate '+str(index-1)+' '+out.name[-8:] if ca else HOST)
            extensions = (f'basicConstraints=critical,CA:TRUE,pathlen:{depth-2-index}\n'
                          'keyUsage=critical,keyCertSign,cRLSign\n' if ca else
                          'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n'
                          f'subjectAltName=DNS:{HOST}\nextendedKeyUsage=serverAuth\n')
            (scratch/(label+'.cnf')).write_text('[req]\ndistinguished_name=dn\n[dn]\n[cert]\n'+extensions+
                                               'subjectKeyIdentifier=none\nauthorityKeyIdentifier=none\n')
            commands.append(['genpkey', *key_options, '-out', label+'.key'])
            serial = str(uuid.uuid4().int)
            if index == 0:
                commands.append(['req', *digest, '-new', '-x509', '-key', label+'.key', '-subj', '/CN='+subject,
                                 '-config', label+'.cnf', '-extensions', 'cert', '-days', '30',
                                 '-set_serial', serial, '-out', label+'.pem'])
            else:
                commands.append(['req', *digest, '-new', '-key', label+'.key', '-subj', '/CN='+subject,
                                 '-config', label+'.cnf', '-out', label+'.csr'])
                issuer = labels[index-1]
                commands.append(['x509', *digest, '-req', '-in', label+'.csr', '-CA', issuer+'.pem',
                                 '-CAkey', issuer+'.key', '-set_serial', serial, '-days', '30',
                                 '-extfile', label+'.cnf', '-extensions', 'cert', '-out', label+'.pem'])
        script = 'set -eu\numask 077\n'+'\n'.join(shlex.join(['/opt/mtc/openssl.sh', *args]) for args in commands)
        command(['docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
                 '--user', f'{os.getuid()}:{os.getgid()}', '-v', str(scratch.resolve())+':/work',
                 '-w', '/work', '--entrypoint', '/bin/sh', image, '-c', script], timeout=1800)
        for label in ('root', 'server'):
            for suffix in ('.pem', '.key'):
                shutil.copyfile(scratch/(label+suffix), out/(label+suffix))
            (out/(label+'.key')).chmod(0o600)
        if depth > 2:
            (out/'intermediates.pem').write_bytes(b''.join(
                (scratch/(label+'.pem')).read_bytes() for label in reversed(labels[1:-1])))
    write(out/'manifest.json', dict(hostname=HOST, profile=profile, depth=depth, files_sha256=hashes(out)))
    return out


def x509_paths(repo):
    return [p.parent for root in (repo/'artifacts/x509', repo/'artifacts/cert-chain-scaling')
            for p in root.rglob('server.pem')]


def certificate_sha256(pem):
    return hashlib.sha256(certificate_der(pem)).hexdigest()


def chromium_ca_policy(root, documents=None):
    root = Path(root)
    expected_der_sha256 = certificate_sha256(root.read_bytes())
    system = platform.system()
    if documents is None:
        documents = []
        if system == 'Darwin':
            paths = (Path('/Library/Managed Preferences/org.chromium.Chromium.plist'),
                     Path('/Library/Managed Preferences')/getpass.getuser()/'org.chromium.Chromium.plist')
            documents = [(path, plistlib.loads(path.read_bytes())) for path in paths if path.is_file()]
        elif system == 'Linux':
            paths = sorted(Path('/etc/chromium/policies/managed').glob('*.json'))
            documents = [(path, json.loads(path.read_text())) for path in paths]
        else:
            raise ValueError('Chromium CACertificates policy is unsupported on '+system)
    values = [(path, data['CACertificates']) for path, data in documents
              if isinstance(data, dict) and 'CACertificates' in data]
    require(values, 'Chromium CACertificates policy is not installed')
    decoded = []
    for path, entries in values:
        require(isinstance(entries, list), 'Invalid CACertificates policy in '+str(path))
        try:
            hashes = tuple(sorted(hashlib.sha256(base64.b64decode(entry, validate=True)).hexdigest()
                                  for entry in entries))
        except (TypeError, ValueError) as error:
            raise ValueError('Invalid CACertificates value in '+str(path)) from error
        decoded.append((path, hashes))
    require(len({hashes for _, hashes in decoded}) == 1,
            'Conflicting CACertificates policies; effective root set is ambiguous')
    require(expected_der_sha256 in decoded[0][1],
            'CACertificates policy does not contain the selected fixture root')
    return dict(x509_trust_mode='chromium-ca-policy', certificate_verification_bypass=False,
                platform_trust_store=False, policy_name='CACertificates',
                policy_root_der_sha256=expected_der_sha256,
                policy_sources=[str(path) for path, _ in decoded], policy_applied=True)


def chromium_ca_policy_report(root, required=False):
    if required:
        return dict(chromium_ca_policy(root), status='TRUSTED')
    try:
        report = dict(chromium_ca_policy(root), status='TRUSTED')
    except (ValueError, OSError) as error:
        report = dict(status='UNTRUSTED_OR_UNAVAILABLE', policy_applied=False,
                      policy_name='CACertificates', certificate_verification_bypass=False,
                      error=str(error))
    return report


def print_credentials_trust(system_trust, policy):
    print('X509 system root trust:         ' + system_trust['status'])
    print('Chromium CACertificates policy: ' + policy['status'])


def nss_database():
    home_db = Path.home()/'.pki/nssdb'
    return home_db if home_db.is_dir() else Path(os.environ.get('XDG_DATA_HOME', str(Path.home()/'.local/share')))/'pki/nssdb'


def nss_certificates(db, *, trusted_only=False, preferred=None):
    listing = command(['certutil', '-L', '-d', 'sql:'+str(db)])
    entries = []
    for line in listing.stdout.splitlines():
        match = re.match(r'^(.*?)\s+([A-Za-z]*,[A-Za-z]*,[A-Za-z]*)\s*$', line)
        if match:
            nickname, trust = match.groups()
            entries.append((nickname, trust))
    require(len({e[0] for e in entries}) == len(entries), 'Ambiguous NSS nicknames; inspect database manually')
    for nickname, trust in sorted(entries, key=lambda e: e[0] != preferred):
        if trusted_only and 'C' not in trust.split(',')[0]:
            continue
        pem = command(['certutil', '-L', '-d', 'sql:'+str(db), '-n', nickname, '-a'])
        yield nickname, trust, certificate_sha256(pem.stdout.encode())


def trust_action(action, root, image='mt-tls-mtc:local'):
    root = Path(root).expanduser()
    require(root.is_file() and not root.is_symlink(), 'Select a regular root certificate with --root PATH')
    root = root.resolve()
    root_bytes = root.read_bytes()
    root_hash = hashlib.sha256(root_bytes).hexdigest()
    system = platform.system()
    require(system in ('Darwin', 'Linux'), 'Trust management supports Darwin and Linux only')
    fingerprint = certificate_sha256(root_bytes)
    require(shutil.which('security' if system == 'Darwin' else 'certutil'),
            'Missing trust backend: install security (macOS) or NSS certutil (Linux) manually')
    def trusted():
        if system == 'Linux':
            db = nss_database()
            require(not (db/'cert8.db').exists() or (db/'cert9.db').exists(),
                    'Legacy NSS database; migrate it manually first')
            return (db/'cert9.db').exists() and any(
                fp == fingerprint and 'C' in flags.split(',')[0]
                for _, flags, fp in nss_certificates(db, trusted_only=True, preferred='Chromium-MTC-lab-'+fingerprint))
        # Verify this exact root independently of any alternative leaf chain.
        result = command(['security', 'verify-cert', '-L', '-p', 'ssl', '-c', root], check=False)
        return result.returncode == 0

    before = trusted()
    evidence = dict(platform=system, root_path=str(root), root_sha256=fingerprint,
                    trusted_before=before, action=action, trusted_after=before)
    try:
        if action != 'trust-status' and not (action == 'trust-x509' and before):
            require(sha(root) == root_hash, 'Selected root changed since fingerprint verification')
            if action == 'trust-x509':
                # Validate the selected root without selecting a leaf/profile/depth.
                with docker_temporary_directory('browser-root-') as temp:
                    Path(temp, 'root.pem').write_bytes(root_bytes)
                    details = docker_openssl(temp, ['x509', '-in', 'root.pem', '-noout',
                                                   '-subject', '-issuer', '-nameopt', 'RFC2253', '-ext', 'basicConstraints'], image).stdout
                    names = dict(line.split('=', 1) for line in details.splitlines() if '=' in line)
                    require('CA:TRUE' in details and names.get('subject') is not None
                            and names['subject'] == names.get('issuer'), 'Selected certificate is not a self-issued CA root')
                    docker_openssl(temp, ['verify', '-no-CApath', '-no-CAstore', '-check_ss_sig',
                                          '-CAfile', 'root.pem', 'root.pem'], image)
                require(sha(root) == root_hash, 'Selected root changed during validation')
            if system == 'Darwin':
                keychain = Path.home()/'Library/Keychains/login.keychain-db'
                require(keychain.is_file(), 'Login keychain missing; configure/unlock it manually')
                if action == 'trust-x509':
                    command(['security', 'add-trusted-cert', '-r', 'trustRoot', '-p', 'ssl',
                             '-k', keychain, root])
                else:
                    listing = command(['security', 'find-certificate', '-a', '-p', keychain], check=False)
                    require(listing.returncode in (0, 44), 'Cannot inspect login keychain: '+listing.stderr)
                    certs = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', listing.stdout, re.S)
                    if any(certificate_sha256(p.encode()) == fingerprint for p in certs):
                        # -Z accepts SHA-256; -t also removes this certificate's user trust settings.
                        command(['security', 'delete-certificate', '-t', '-Z', fingerprint, keychain])
            else:
                db = nss_database(); evidence['database'] = str(db)
                entries = list(nss_certificates(db)) if (db/'cert9.db').exists() else []
                matches = [e for e in entries if e[2] == fingerprint]
                parent = db
                while not parent.exists():
                    parent = parent.parent
                require((action == 'untrust-x509' and not matches) or
                        (os.access(parent, os.W_OK | os.X_OK) and
                         all(os.access(p, os.W_OK) for p in db.glob('*.db'))),
                        'NSS database is not writable. Run as its owning desktop user; '
                        'ask an administrator to repair permissions. No privilege escalation attempted.')
                if not (db/'cert9.db').exists() and action == 'trust-x509':
                    require(not (db/'cert8.db').exists(), 'Legacy NSS database; migrate it manually first')
                    db.mkdir(parents=True, exist_ok=True)
                    command(['certutil', '-N', '--empty-password', '-d', 'sql:'+str(db)])
                if action == 'trust-x509':
                    if matches:
                        for nickname, trust, _ in matches:
                            flags = trust.split(','); flags[0] = flags[0].replace('p', '')
                            if 'C' not in flags[0]: flags[0] += 'C'
                            command(['certutil', '-M', '-d', 'sql:'+str(db), '-n', nickname, '-t', ','.join(flags)])
                    else:
                        nickname = 'Chromium-MTC-lab-'+fingerprint
                        require(not any(e[0] == nickname for e in entries), 'NSS nickname collision; foreign certificate preserved')
                        command(['certutil', '-A', '-d', 'sql:'+str(db), '-n', nickname, '-t', 'C,,', '-i', root])
                else:
                    for nickname, _, _ in matches:
                        # Recheck the exact certificate immediately before deletion by NSS nickname.
                        pem = command(['certutil', '-L', '-d', 'sql:'+str(db), '-n', nickname, '-a'])
                        require(certificate_sha256(pem.stdout.encode()) == fingerprint, 'NSS certificate changed; deletion refused')
                        command(['certutil', '-D', '-d', 'sql:'+str(db), '-n', nickname])
        evidence['trusted_after'] = before if action == 'trust-status' else trusted()
        if action == 'trust-x509':
            require(evidence['trusted_after'], 'Root is still NOT TRUSTED; inspect backend permissions/settings manually')
        elif action == 'untrust-x509':
            require(not evidence['trusted_after'], 'Root remains trusted outside the managed user store; '
                    'inspect system/admin trust manually. Other stores were not modified.')
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        try:
            evidence['trusted_after'] = trusted()
        except (ValueError, OSError, subprocess.SubprocessError):
            evidence['trusted_after'] = None
        evidence['error'] = str(error)
        raise
    finally:
        evidence['status'] = ('UNKNOWN' if evidence['trusted_after'] is None else
                              'TRUSTED' if evidence['trusted_after'] else 'NOT TRUSTED')
        print(json.dumps(evidence, indent=2))
    return 0


def root_trust(x):
    root = Path(x['root']); system = platform.system()
    if system == 'Darwin':
        args = ['security', 'verify-cert', '-L', '-p', 'ssl', '-n', HOST, '-c', x['cert']]
        if x.get('intermediates'):
            # security accepts certificate files; split PEM bundle into a temp audit dir.
            certs = pem_certificates(Path(x['intermediates']).read_bytes())
        else:
            certs = []
        with tempfile.TemporaryDirectory(prefix='mtc-trust-audit-') as temp:
            for i, cert in enumerate(certs):
                p = Path(temp)/f'{i}.pem'; p.write_bytes(cert); args += ['-c', str(p)]
            result = command(args+['-c', str(root)], check=False)
        manual = shlex.join(['bin/browser_client/mt-chromium-setup', 'browser-validation', 'trust-x509', '--root', str(root)])
        return dict(status='TRUSTED' if result.returncode == 0 else 'UNTRUSTED_OR_UNAVAILABLE', method='security verify-cert -L ssl (no explicit trust override)',
                    returncode=result.returncode, diagnostic=(result.stdout+result.stderr)[-2000:], manual_command=manual)
    if system == 'Linux':
        db = nss_database()
        nickname = 'Chromium-MTC-lab-'+sha(root)[:16]
        manual = []
        if not (db/'cert9.db').exists():
            manual += ['mkdir -p '+shlex.quote(str(db)), 'certutil -N --empty-password -d '+shlex.quote('sql:'+str(db))]
        manual += ['certutil -A -d '+shlex.quote('sql:'+str(db))+' -n '+shlex.quote(nickname)+' -t "C,," -i '+shlex.quote(str(root))]
        trusted = False
        if shutil.which('certutil') and (db/'cert9.db').exists():
            listing = command(['certutil', '-L', '-d', 'sql:'+str(db)], check=False)
            for line in listing.stdout.splitlines():
                match = re.match(r'^(.*?)\s+([A-Za-z]*,[A-Za-z]*,[A-Za-z]*)\s*$', line)
                if not match or 'C' not in match[2].split(',')[0]:
                    continue
                pem = command(['certutil', '-L', '-d', 'sql:'+str(db), '-n', match[1], '-a'], check=False)
                try:
                    trusted |= certificate_sha256(pem.stdout.encode()) == certificate_sha256(root.read_bytes())
                except ValueError:
                    pass
        return dict(status='TRUSTED' if trusted else 'UNTRUSTED_OR_UNAVAILABLE', method='Chromium user NSS DB: exact root fingerprint and SSL CA trust', database=str(db), manual_command='\n'.join(manual), note='Requires certutil (NSS tools); no installation performed. Browser control remains authoritative.')
    return dict(status='UNSUPPORTED', manual_command='Use the platform browser trust-store mechanism explicitly.')


def prepare_credentials(repo, output, image, profile=PROFILE, depth=2,
                        x509_fixture_set=None, mtc_fixture=None, mtc_validation=None,
                        optimized_all_profiles=False, progress=None,
                        mtc_trust_mode='landmark'):
    require(profile in PROFILES and depth in (2, 3, 4, 5), "Unsupported profile/depth")
    require((mtc_fixture is None) == (mtc_validation is None), 'Supply both --mtc-fixture and --mtc-validation')
    require(mtc_trust_mode in ('landmark', 'standalone'),
            'Unsupported MTC trust mode')
    require(mtc_trust_mode == 'landmark' or mtc_fixture is not None
            or optimized_all_profiles,
            'Standalone MTC is reuse-only: supply --mtc-fixture and --mtc-validation')
    if optimized_all_profiles:
        require(mtc_fixture is None, 'Optimized credentials select MTC fixtures locally')
        try:
            mtc, ma = preselect_mtc_fixture(
                repo, profile, mtc_trust_mode, require_anchor=False)
        except ValueError:
            fixture = generate_mtc(repo, output, image, profile)
            validation = fixture.with_name(
                fixture.name+'-validation')/'validation.json'
            mtc = prevalidated_mtc(
                fixture, validation, profile, mtc_trust_mode)
            ma = [dict(path=str(fixture), valid=True, selected=True,
                       reason='Generated because no compatible validated '
                              'fixture existed')]
        write(output/'mtc-discovery.json', ma)
        if progress: progress('validating MTC')
        if mtc_trust_mode == 'landmark':
            validated = validate_mtc(Path(mtc['fixture']), profile, image)
        else:
            validated = prevalidated_mtc(
                mtc['fixture'], mtc['validation_evidence'], profile,
                'standalone')
        if 'anchor' in mtc:
            validated.update(anchor=mtc['anchor'],
                             anchor_sha256=mtc['anchor_sha256'],
                             anchor_origin=mtc['anchor_origin'])
        validated['origin'] = 'reused-prechecked'
        mtc = validated
    elif mtc_fixture is not None:
        mtc = prevalidated_mtc(mtc_fixture, mtc_validation, profile,
                               mtc_trust_mode)
        ma = [dict(path=mtc['fixture'], valid=True, origin=mtc['origin'], validation_evidence=mtc['validation_evidence'])]
        write(output/'mtc-discovery.json', ma)
    else:
        mtc_paths = [p.parent for p in (repo/'artifacts/mtc').glob('*/manifest.json')]
        mtc, ma = select_or_generate(mtc_paths, lambda p: validate_mtc(p, profile, image), lambda: generate_mtc(repo, output, image, profile), output/'mtc-discovery.json')
    if not optimized_all_profiles or 'anchor' not in mtc:
        mtc.update(choose_anchor(mtc, output))
    global CA, SELECTED, REQUESTED
    CA, SELECTED, REQUESTED = mtc['ca_id'], mtc['selected_tai'], mtc['requested_tai']
    x509_validator = lambda p: validate_x509(
        p, profile=profile, depth=depth, image=image,
        fixture_set=x509_fixture_set)
    if optimized_all_profiles:
        fixture = precheck_formal_x509_fixture(repo, profile, depth, x509_fixture_set)
        xa = [dict(path=str(fixture.resolve()), valid=True, selected=True,
                   reason='Exact formal matrix profile/D=2 fixture passed local integrity precheck')]
        write(output/'x509-discovery.json', xa)
        if progress: progress('validating X509')
        x = x509_validator(fixture)
        x['origin'] = 'reused-formal-fixture-set'
    elif x509_fixture_set is None:
        x, xa = select_or_generate(
            x509_paths(repo), x509_validator,
            lambda: generate_x509(repo, profile, depth, image),
            output/'x509-discovery.json')
    else:
        x, xa = discover(x509_paths(repo), x509_validator)
        write(output/'x509-discovery.json', xa)
        require(x is not None,
                f'No valid X509 fixture for fixture_set={x509_fixture_set}, '
                f'profile={profile}, depth={depth}')
        x['origin'] = 'reused-formal-fixture-set'
    # Preserve the public CA certificate beside the audit, never its private key.
    ca_copy = output/'x509-root-ca.pem'
    with ca_copy.open('xb') as f:
        f.write(Path(x['root']).read_bytes())
    require(sha(ca_copy) == x['root_sha256'], 'Archived CA certificate hash mismatch')
    x['root_certificate_copy'] = str(ca_copy.resolve())
    x['root_certificate_copy_sha256'] = sha(ca_copy)
    x['root_verification_command'] = shlex.join(['openssl', 'verify', '-check_ss_sig', '-CAfile', str(ca_copy.resolve()), str(ca_copy.resolve())])
    x['root_trust'] = root_trust(x)
    data = dict(timestamp=datetime.now(timezone.utc).isoformat(), mtc=mtc, x509=x, mtc_candidates=ma, x509_candidates=xa)
    write(output/'credentials.json', data)
    return data


def prepare_mtc_dependencies(repo, image, profiles):
    """Prepare reusable N=16 fixtures and canonical anchors before validation."""
    require(profiles and all(profile in PROFILES for profile in profiles),
            'Unsupported MTC dependency profile')
    root = repo/'.mt-state/chromium-mtc'/('mtc-dependencies-'+stamp())
    root.mkdir(parents=True, exist_ok=False)
    records = []
    for profile in profiles:
        generated = False
        profile_output = root/profile
        profile_output.mkdir()
        for mode in ('landmark', 'standalone'):
            origin = 'reused'
            try:
                selected, _ = preselect_mtc_fixture(
                    repo, profile, mode, require_anchor=True)
            except (ValueError, OSError):
                try:
                    selected, _ = preselect_mtc_fixture(
                        repo, profile, mode, require_anchor=False)
                except (ValueError, OSError):
                    if not generated:
                        generate_mtc(repo, profile_output, image, profile)
                        generated = True
                    selected, _ = preselect_mtc_fixture(
                        repo, profile, mode, require_anchor=False)
                    origin = 'generated'
                selected.update(choose_anchor(selected, profile_output))
                selected, _ = preselect_mtc_fixture(
                    repo, profile, mode, require_anchor=True)
                if origin != 'generated':
                    origin = 'anchor-generated'
            fixture = Path(selected['fixture'])
            require(os.access(fixture, os.R_OK | os.X_OK),
                    'Selected MTC fixture is inaccessible to the invoking user: '+str(fixture))
            records.append(dict(
                profile=profile, mode=mode, origin=origin,
                fixture=str(fixture.resolve()),
                validation_evidence=selected['validation_evidence'],
                anchor=selected['anchor'],
                anchor_sha256=selected['anchor_sha256']))
            print(f'[MTC] {profile} {mode}: {origin.upper()}', flush=True)
    write(root/'summary.json', dict(status='PASS', profiles=list(profiles),
                                    tree_size=16, records=records))
    return records


def mutate_anchor(anchor, case):
    data = copy.deepcopy(anchor)
    if case == 'mtc-bad-merkle':
        subtree = next(s for s in data['landmark']['trusted_subtrees'] if s['start'] == 0)
        raw = bytearray.fromhex(subtree['hash']); raw[0] ^= 1; subtree['hash'] = raw.hex()
    elif case == 'mtc-bad-serial':
        for key in ('min_serial', 'max_serial'):
            data[key] += 1; data[key+'_hex'] = f"0x{data[key]:016x}"
        require(data['min_serial'] > 1 << 48, 'Leaf 0 still in range')
    else:
        raise ValueError('Unknown anchor mutation')
    return data


def browser_executable(override=None):
    if override:
        candidates = [Path(override).expanduser()]
    else:
        candidates = [Path.home()/'chromium-mtc-rebuild/src/out/mtc-release/chrome',
                      Path.home()/'Desktop/chromium-mtc/src/out/mtc/Chromium.app/Contents/MacOS/Chromium',
                      Path.home()/'Desktop/chromium-mtc/src/out/mtc-release/chrome',
                      Path.home()/'chromium-mtc-rebuild/src/out/mtc-release/Chromium.app/Contents/MacOS/Chromium',
                      Path.home()/'chromium-mtc-rebuild/src/out/mtc/Chromium.app/Contents/MacOS/Chromium',
                      Path.home()/'Desktop/chromium-mtc/src/out/mtc-release/Chromium.app/Contents/MacOS/Chromium',
                      Path.home()/'chromium-mtc-rebuild/src/out/mtc/chrome',
                      Path.home()/'Desktop/chromium-mtc/src/out/mtc/chrome']
        candidates = [p for p in candidates if p.name == ('Chromium' if platform.system() == 'Darwin' else 'chrome')]
    for p in candidates:
        if p.is_file() and os.access(p, os.X_OK):
            commit = command(['git', '-C', p.parent, 'rev-parse', 'HEAD'], check=False).stdout.strip() or None
            return dict(executable=str(p.resolve()), sha256=sha(p), commit=commit,
                        hash_scope='Launcher/executable only; component libraries are not covered')
    raise ValueError('Existing patched Chromium executable missing; use --chromium PATH. No build attempted.')


def validate_mts1(path, expected_log_number):
    data = Path(path).read_bytes()
    require(len(data) >= 6 and data[:4] == b'MTS1', 'Invalid MTS1 magic')
    count = int.from_bytes(data[4:6], 'big')
    require(count <= 64, 'Invalid MTS1 count')
    require(len(data) == 6 + count * 46, 'Invalid MTS1 length')
    seen = set()
    for offset in range(6, len(data), 46):
        log_number = int.from_bytes(data[offset:offset + 2], 'big')
        start = int.from_bytes(data[offset + 2:offset + 8], 'big')
        end = int.from_bytes(data[offset + 8:offset + 14], 'big')
        size = end - start
        require(log_number != 0 and log_number == expected_log_number,
                'MTS1 log number does not match anchor')
        require(size > 0 and size & (size - 1) == 0 and start % size == 0,
                'Invalid MTS1 subtree interval')
        key = (log_number, start, end)
        require(key not in seen, 'Duplicate MTS1 subtree interval')
        seen.add(key)


def browser_command(executable, profile, case_dir, anchor, url, enable_mtc=False,
                    browser_mode='headless', disable_trust_anchor_ids=False,
                    trusted_subtrees=None, trusted_subtrees_url=None,
                    mtc_ca=None, mtc_ca_root=None):
    require(browser_mode in ('headless', 'headed'), 'Invalid browser mode')
    flags = [str(executable), '--headless=new', '--remote-debugging-port=0',
             '--remote-debugging-address=127.0.0.1', '--no-first-run', '--no-default-browser-check',
             '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-quic',
             '--no-proxy-server',
             '--user-data-dir='+str(profile), '--log-net-log='+str(case_dir/'netlog.json'),
             '--net-log-capture-mode=Everything']
    if browser_mode == 'headed':
        flags.remove('--headless=new')
        flags.remove('--remote-debugging-port=0')
        flags.remove('--remote-debugging-address=127.0.0.1')
        flags.remove('--log-net-log='+str(case_dir/'netlog.json'))
        flags.remove('--net-log-capture-mode=Everything')
    if enable_mtc:
        flags.append('--enable-features=MtcPlants07Lab,VerifyMTCs')
    if disable_trust_anchor_ids:
        flags.append('--disable-features=TLSTrustAnchorIDs')
    if anchor:
        require(mtc_ca and mtc_ca_root,
                'MTC-07 trust config requires CA certificate and representation root')
        flags.append('--mtc-plants07-trust='+str(anchor))
        flags.append('--mtc-plants07-ca='+str(mtc_ca))
        flags.append('--mtc-plants07-ca-root='+str(mtc_ca_root))
    require(not (trusted_subtrees and trusted_subtrees_url),
            'MTC trusted-subtrees FILE and URL modes are mutually exclusive')
    if trusted_subtrees:
        flags.append('--mtc-plants07-trusted-subtrees='+str(trusted_subtrees))
    if trusted_subtrees_url:
        flags.append('--mtc-plants07-trusted-subtrees-url='+str(trusted_subtrees_url))
    return flags + [('about:blank' if browser_mode == 'headless' else url)]


def relevant_netlog(data, url):
    events = data.get('events', [])
    types = {v: k for k, v in data.get('constants', {}).get('logEventTypes', {}).items()}
    graph = {}; roots = set()
    def dependencies(obj):
        found = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k == 'source_dependency' and isinstance(v, dict) and 'id' in v:
                    found.append(v['id'])
                else:
                    found.extend(dependencies(v))
        elif isinstance(obj, list):
            for v in obj:
                found.extend(dependencies(v))
        return found
    for event in events:
        sid = event.get('source', {}).get('id'); params = event.get('params', {})
        if params.get('url') == url:
            roots.add(sid)
        for dep in dependencies(params):
            graph.setdefault(sid, set()).add(dep); graph.setdefault(dep, set()).add(sid)
    todo = list(roots); linked = set(roots)
    while todo:
        for dep in graph.get(todo.pop(), set()) - linked:
            linked.add(dep); todo.append(dep)
    return [(types.get(e.get('type'), e.get('type')), e.get('params', {}), e.get('phase'), e.get('source', {}).get('id'))
            for e in events if e.get('source', {}).get('id') in linked]


def encrypted_extensions_selected(events, selected_tai=None):
    selected_tai = selected_tai if selected_tai is not None else SELECTED
    require(selected_tai is not None, 'MTC fixture identity not selected')
    for name, params, _, _ in events:
        if name != 'SSL_HANDSHAKE_MESSAGE_RECEIVED' or params.get('type') != 8:
            continue
        try:
            raw = base64.b64decode(params['bytes'], validate=True)
            require(raw[0] == 8 and int.from_bytes(raw[1:4], 'big') == len(raw)-4, 'Malformed handshake')
            body = raw[4:]
            extension_data, pos = take_vector(body, 0)
            require(pos == len(body), 'Trailing EncryptedExtensions data')
            pos = 0
            while pos < len(extension_data):
                kind, pos = take_number(extension_data, pos, 2)
                value, pos = take_vector(extension_data, pos)
                if kind == 0xca34:
                    entries, ids_pos = take_vector(value, 0)
                    require(ids_pos == len(value), 'Trailing trust-anchor extension data')
                    entry_pos = 0
                    while entry_pos < len(entries):
                        identifier, entry_pos = take_vector(entries, entry_pos, 1)
                        if identifier == core.relid(selected_tai):
                            return True
        except (ValueError, KeyError, IndexError):
            continue
    return False


def requested_tai_observed(requests, requested_tai):
    expected = core.relid(requested_tai)
    for params in requests:
        value = params.get('trust_anchor_ids')
        if isinstance(value, str):
            identifiers = [item.strip() for item in value.split(',')]
        elif isinstance(value, list) and all(isinstance(item, str)
                                             for item in value):
            identifiers = value
        else:
            continue
        for identifier in identifiers:
            try:
                if core.relid(identifier) == expected:
                    return True
            except (ValueError, TypeError):
                continue
    return False


def classify(case, case_dir, url, process, *, positive_control=False, requested_tai=None,
             selected_tai=None, trusted_subtrees_url=None, expected_group=29):
    requested_tai = requested_tai if requested_tai is not None else REQUESTED
    selected_tai = selected_tai if selected_tai is not None else SELECTED
    require(requested_tai is not None and selected_tai is not None, 'MTC fixture identity not selected')
    server = (case_dir/'server.log').read_text(errors='replace') if (case_dir/'server.log').exists() else ''
    stdout = (case_dir/'chromium.stdout.log').read_text(errors='replace')
    stderr = (case_dir/'chromium.stderr.log').read_text(errors='replace')
    result = dict(name=case, expected_outcome='accept' if case.endswith('positive') else 'reject',
                  observed_outcome='INCONCLUSIVE', **{'pass': False}, reason='', chromium_exit=process,
                  evidence={p.name: str(p) for p in case_dir.iterdir() if p.is_file()})
    def flight(direction, name):
        return bool(re.search(r'^'+re.escape(direction)+r' TLS 1\.3, Handshake[^\n]*, '+name+r'\s*$', server, re.M))
    certificate = flight('>>>', 'Certificate')
    verify = flight('>>>', 'CertificateVerify')
    finished = flight('>>>', 'Finished'); client = flight('<<<', 'Finished')
    result.update(server_authentication_flight_observed=certificate and verify, server_finished_observed=finished,
                  client_finished_observed=client, application_data_observed=False)
    try:
        net = read(case_dir/'netlog.json'); events = relevant_netlog(net, url)
        require(bool(events), 'No target URL-linked NetLog events')
    except Exception as e:
        result['reason'] = str(e); return result
    errors = sorted({p['net_error'] for _, p, _, _ in events if isinstance(p.get('net_error'), int) and p['net_error'] < 0})
    names = {v: k for k, v in net.get('constants', {}).get('netError', {}).items()}
    result['net_errors'] = [dict(code=e, name=names.get(e)) for e in errors]
    requests = [p for name, p, _, _ in events if name == 'SSL_CLIENT_TRUST_ANCHOR_IDS_LIST']
    result['requested_tai_observed'] = requested_tai_observed(
        requests, requested_tai)
    result['selected_tai_observed'] = encrypted_extensions_selected(events, selected_tai)
    ssl_connections = [p for name, p, _, _ in events if name == 'SSL_CONNECT' and p.get('version')]
    negotiated_groups = sorted({p.get('key_exchange_group') for p in ssl_connections
                                if isinstance(p.get('key_exchange_group'), int)})
    negotiated = any(p.get('version') == 'TLS 1.3' and p.get('cipher_suite') == 0x1302 and
                     p.get('key_exchange_group') == expected_group and p.get('is_resumed') is False
                     for p in ssl_connections)
    http = any(name == 'HTTP_TRANSACTION_READ_RESPONSE_HEADERS' and re.search(r'HTTP/\S+ 200', str(p)) for name, p, _, _ in events)
    dom = '<h1>MTC browser test</h1>' in stdout and '<p id="result">TLS browser validation page</p>' in stdout
    result['application_data_observed'] = http and dom
    result['negotiated_canonical_tls'] = negotiated
    result['configured_key_exchange_group'] = expected_group
    result['observed_key_exchange_groups'] = negotiated_groups
    result['target_url'] = url
    received = [p.get('type') for name, p, _, _ in events if name == 'SSL_HANDSHAKE_MESSAGE_RECEIVED']
    sent = [p.get('type') for name, p, _, _ in events if name == 'SSL_HANDSHAKE_MESSAGE_SENT']
    result['netlog_handshakes_received'] = received; result['netlog_handshakes_sent'] = sent
    netflight = all(t in received for t in (11, 15, 20))
    config_error = (
        trusted_subtrees_url is None
        and ('without a valid trust config' in stderr or 'Invalid MTC Plants-07' in stderr)
    )
    cert_error = any(-299 <= e <= -200 for e in errors)
    positive = result['expected_outcome'] == 'accept'
    if positive:
        success = certificate and verify and finished and client and netflight and 20 in sent and negotiated and http and dom and not cert_error and not config_error and process != 'timeout'
        if case == 'mtc-positive':
            success = success and result['requested_tai_observed'] and result['selected_tai_observed']
        result['observed_outcome'] = 'PASS' if success else 'FAIL'
        result['pass'] = bool(success)
        result['reason'] = 'Authenticated target TLS and HTTP corroborated by NetLog, server transcript and DOM' if success else 'Positive acceptance requirements not all established'
    else:
        server_handshake_failure = 'SSL3 alert write:fatal:handshake failure' in server
        server_certificate_unknown = (
            'SSL3 alert read:fatal:certificate unknown' in server
            or 'SSL alert number 46' in server
        )

        if case == 'mtc-no-trust':
            rejected = (
                not certificate
                and not verify
                and not finished
                and not client
                and not http
                and not dom
                and not result['requested_tai_observed']
                and not result['selected_tai_observed']
                and server_handshake_failure
                and -113 in errors
                and 'Invalid MTC Plants-07' not in stderr
                and process != 'timeout'
            )
            success_reason = (
                'Expected no-trust rejection before server authentication flight; '
                'no compatible MTC trust anchor negotiated; positive control passed'
            )
        else:
            rejected = (
                certificate
                and verify
                and finished
                and result['requested_tai_observed']
                and result['selected_tai_observed']
                and cert_error
                and server_certificate_unknown
                and not client
                and not http
                and not dom
                and not config_error
                and process != 'timeout'
            )
            success_reason = (
                'Expected MTC authentication rejection after server authentication '
                'flight; certificate_unknown observed; no client Finished or HTTP; '
                'positive control passed'
            )

        if client or http or dom:
            result.update(
                observed_outcome='FAIL',
                reason='Negative case accepted TLS/application data',
            )
        elif rejected and positive_control:
            result.update(
                observed_outcome='PASS',
                **{'pass': True},
                reason=success_reason,
            )
        else:
            result['reason'] = (
                'Rejection not attributable with sufficient case-specific evidence '
                'and a passing positive control'
            )
    return result


class Server:
    """Same pinned s_server/loopback/readiness pattern as interoperability stage 60."""
    def __init__(self, credentials, case, output, run_root, browser_mode='headless',
                 key_establishment='x25519'):
        self.name = 'mtc-browser-'+uuid.uuid4().hex[:16]
        self.output, self.run_root = output, run_root
        self.credentials, self.case = credentials, case
        self.browser_mode = browser_mode
        self.key_establishment = key_establishment_config(key_establishment)
        self.created = False

    def start(self):
        image = self.credentials['mtc']['image_id']
        command(['docker', 'image', 'inspect', image])  # Never pulls.
        selected = self.credentials['x509' if self.case == 'x509-positive' else 'mtc']
        fixture = Path(selected['fixture'])
        webroot = self.output/'www'
        webroot.mkdir()
        body = browser_page(self.case, self.run_root, self.credentials, self.browser_mode,
                            self.key_establishment['key_establishment']).encode('utf-8')
        (webroot/'page.html').write_bytes(body)
        # -HTTP serves a complete response file, including our explicit MIME type.
        response = ('HTTP/1.0 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n'
                    f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode('ascii') + body
        # Support literal request-target filenames as well as query-stripping versions.
        for name in ('browser-test.html', page_target(self.case, self.run_root)):
            (webroot/name).write_bytes(response)
        args = ['/opt/mtc/openssl.sh', 's_server', '-accept', '4433', '-tls1_3',
                '-groups', self.key_establishment['group'],
                '-ciphersuites', TLS['cipher'], '-num_tickets', '0', '-HTTP', '-state', '-msg',
                '-cert', '/fixtures/'+str(Path(selected['cert']).relative_to(fixture)),
                '-key', '/fixtures/'+str(Path(selected['key']).relative_to(fixture))]
        if self.case != 'x509-positive':
            args += ['-mtc_id', selected['selected_tai']]
        elif selected.get('intermediates'):
            args += ['-cert_chain', '/fixtures/'+str(Path(selected['intermediates']).relative_to(fixture))]
        cmd = ['docker', 'run', '-d', '--pull', 'never', '--name', self.name, '--label', LABEL+'='+str(self.run_root),
               '-p', '127.0.0.1:4433:4433', '-v', str(fixture)+':/fixtures:ro', '-v', str(self.output)+':/results',
               '--workdir', '/results/www',
               '--entrypoint', '/bin/sh', image, '-c', 'exec '+shlex.join(args)+' > /results/server.log 2>&1']
        write(self.output/'server-command.json', dict(command=cmd, image=image))
        write(self.output/'server-owner.json', dict(name=self.name, label=LABEL, owner=str(self.run_root)))
        self.created = True
        command(cmd)
        for _ in range(40):
            log = self.output/'server.log'
            if log.exists() and re.search(r'^ACCEPT\s*$', log.read_text(errors='replace'), re.M):
                return
            state = command(['docker', 'inspect', '-f', '{{.State.Running}}', self.name]).stdout.strip()
            require(state == 'true', 'Server exited before readiness')
            time.sleep(0.25)
        raise ValueError('Server readiness not confirmed')

    def stop(self):
        if not self.created:
            return
        info = command(['docker', 'inspect', self.name], check=False)
        if info.returncode:
            return
        data = json.loads(info.stdout)[0]
        require(data['Config'].get('Labels', {}).get(LABEL) == str(self.run_root), 'Foreign container preserved')
        command(['docker', 'rm', '-f', self.name])


def check_hostname():
    resolution_error = HOST+' must resolve exclusively to 127.0.0.1. Configure /etc/hosts first.'
    try:
        addresses = {entry[4][0] for entry in socket.getaddrinfo(HOST, 4433, type=socket.SOCK_STREAM)}
    except socket.gaierror as error:
        raise ValueError(resolution_error) from error
    require(addresses == {'127.0.0.1'}, resolution_error)


class CdpConnection:
    """Small RFC 6455 client for the loopback-only Chromium DevTools endpoint."""
    def __init__(self, websocket_url, timeout):
        parsed = urlsplit(websocket_url)
        require(parsed.scheme == 'ws' and parsed.hostname in ('127.0.0.1', 'localhost'),
                'Unsafe DevTools WebSocket endpoint')
        self.socket = socket.create_connection((parsed.hostname, parsed.port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode('ascii')
        path = parsed.path + (('?' + parsed.query) if parsed.query else '')
        request = (f'GET {path} HTTP/1.1\r\nHost: {parsed.hostname}:{parsed.port}\r\n'
                   f'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n'
                   'Sec-WebSocket-Version: 13\r\n\r\n')
        self.socket.sendall(request.encode('ascii'))
        response = b''
        while b'\r\n\r\n' not in response and len(response) < 16384:
            response += self.socket.recv(4096)
        require(response.startswith(b'HTTP/1.1 101 '), 'Chromium rejected DevTools WebSocket upgrade')
        expected = base64.b64encode(hashlib.sha1(
            (key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode('ascii')).digest())
        headers, self.buffer = response.split(b'\r\n\r\n', 1)
        headers = headers.lower()
        require(b'sec-websocket-accept: ' + expected.lower() in headers,
                'Invalid DevTools WebSocket handshake')
        self.next_id = 1
        self.events = []

    def close(self):
        try:
            self.socket.close()
        except OSError:
            pass

    def _exact(self, size):
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        while len(result) < size:
            block = self.socket.recv(size - len(result))
            require(block, 'DevTools WebSocket closed unexpectedly')
            result += block
        return result

    def _send(self, payload):
        payload = payload.encode('utf-8'); mask = os.urandom(4)
        length = len(payload)
        header = bytes((0x81, 0x80 | min(length, 127)))
        if length >= 126:
            header = bytes((0x81, 0xfe if length < 65536 else 0xff))
            header += struct.pack('!H' if length < 65536 else '!Q', length)
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        self.socket.sendall(header + mask + masked)

    def _receive(self):
        first, second = self._exact(2)
        opcode = first & 0x0f; length = second & 0x7f
        if length == 126:
            length = struct.unpack('!H', self._exact(2))[0]
        elif length == 127:
            length = struct.unpack('!Q', self._exact(8))[0]
        if second & 0x80:
            mask = self._exact(4)
        else:
            mask = None
        payload = self._exact(length)
        if mask:
            payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        if opcode == 0x9:
            return self._receive()
        require(opcode == 0x1, 'Unexpected DevTools WebSocket frame')
        return json.loads(payload)

    def command(self, method, params=None):
        identifier = self.next_id; self.next_id += 1
        self._send(json.dumps(dict(id=identifier, method=method, params=params or {}), separators=(',', ':')))
        while True:
            message = self._receive()
            if message.get('id') == identifier:
                require('error' not in message, f'CDP {method} failed: {message.get("error")}')
                return message.get('result', {})
            self.events.append(message)

    def wait_event(self, method, deadline):
        while True:
            for index, event in enumerate(self.events):
                if event.get('method') == method:
                    return self.events.pop(index)
            self.socket.settimeout(max(0.01, deadline - time.monotonic()))
            require(time.monotonic() < deadline, f'Timed out waiting for CDP {method}')
            message = self._receive()
            if message.get('method') == method:
                return message
            self.events.append(message)

    def discard_events(self, *methods):
        methods = set(methods)
        self.events = [event for event in self.events if event.get('method') not in methods]

    def wait_navigation_load(self, frame_id, loader_id, navigation_timestamp, deadline):
        """Require both a post-navigate load event and the matching loader lifecycle event."""
        load_event = None
        lifecycle_event = None
        deferred = []
        pending, self.events = self.events, []
        try:
            while load_event is None or lifecycle_event is None:
                require(time.monotonic() < deadline, 'Timed out waiting for correlated experimental navigation load')
                if not pending:
                    self.socket.settimeout(max(0.01, deadline-time.monotonic()))
                    pending = [self._receive()]
                event = pending.pop(0)
                method = event.get('method'); params = event.get('params', {})
                if (method == 'Page.loadEventFired'
                        and isinstance(params.get('timestamp'), (int, float))
                        and params['timestamp'] >= navigation_timestamp):
                    load_event = event
                elif (method == 'Page.lifecycleEvent' and params.get('name') == 'load'
                      and params.get('frameId') == frame_id
                      and (loader_id is None or params.get('loaderId') == loader_id)):
                    lifecycle_event = event
                else:
                    deferred.append(event)
            return dict(load_event=load_event, lifecycle_event=lifecycle_event)
        finally:
            # Preserve unrelated evidence exactly once and in arrival order.
            self.events = deferred + pending + self.events


def cdp_page(profile, deadline):
    active = Path(profile)/'DevToolsActivePort'
    while time.monotonic() < deadline:
        if active.is_file():
            lines = active.read_text(errors='replace').splitlines()
            if lines and lines[0].isdigit():
                port = int(lines[0])
                try:
                    with urlopen(f'http://127.0.0.1:{port}/json/list', timeout=0.5) as response:
                        targets = json.load(response)
                    pages = [item for item in targets if item.get('type') == 'page'
                             and item.get('url') == 'about:blank' and item.get('webSocketDebuggerUrl')]
                    if len(pages) == 1:
                        return CdpConnection(pages[0]['webSocketDebuggerUrl'], max(0.1, deadline-time.monotonic()))
                except (OSError, ValueError, json.JSONDecodeError):
                    pass
        time.sleep(0.05)
    raise ValueError('Chromium DevTools endpoint did not become ready before stabilization timeout')


def stabilize_cdp(connection, deadline, settle_seconds=CDP_STABILIZATION_SETTLE_SECONDS):
    """Verify a responsive, fully loaded neutral page twice; no NetLog readiness is inferred."""
    probes = []
    connection.command('Page.enable')
    connection.command('Page.setLifecycleEventsEnabled', {'enabled': True})
    connection.command('Performance.enable')
    connection.command('Runtime.enable')
    while len(probes) < 2:
        require(time.monotonic() < deadline, 'Chromium did not reach neutral-page stability before timeout')
        result = connection.command('Runtime.evaluate', dict(
            expression='JSON.stringify({url:location.href,state:document.readyState})', returnByValue=True))
        value = json.loads(result.get('result', {}).get('value', '{}'))
        require(value == {'url': 'about:blank', 'state': 'complete'},
                'Chromium neutral page is not completely loaded')
        probes.append(dict(monotonic=time.monotonic(), **value))
        if len(probes) == 1:
            remaining = deadline-time.monotonic()
            require(remaining >= settle_seconds, 'Insufficient stabilization timeout')
            time.sleep(settle_seconds)
    return probes


def run_browser(cmd, output, timeout, *, profile=None, target_url=None, before_navigation=None):
    check_hostname()
    # Only this child process group is signalled; no PID-name matching.
    with (output/'chromium.stdout.log').open('xb') as stdout, (output/'chromium.stderr.log').open('xb') as stderr:
        started = time.monotonic()
        child = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, start_new_session=True)
        cdp = None
        primary_error = None
        cleanup_errors = []
        def terminate():
            try:
                if child.poll() is not None:
                    return
            except Exception as error:
                cleanup_errors.append('poll child: '+str(error))
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except Exception as error:
                cleanup_errors.append('SIGTERM process group: '+str(error))
                try:
                    child.terminate()
                except Exception as fallback_error:
                    cleanup_errors.append('terminate child: '+str(fallback_error))
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except Exception as error:
                    cleanup_errors.append('SIGKILL process group: '+str(error))
                    try:
                        child.kill()
                    except Exception as fallback_error:
                        cleanup_errors.append('kill child: '+str(fallback_error))
                try:
                    child.wait(timeout=5)
                except Exception as error:
                    cleanup_errors.append('wait after kill: '+str(error))
            except Exception as error:
                cleanup_errors.append('wait after terminate: '+str(error))
        try:
            # From this point every failure, including evidence I/O, is covered by cleanup.
            write(output/'browser-process.json', dict(pid=child.pid, process_group=child.pid, command=cmd))
            if target_url is not None:
                require(profile is not None and before_navigation is not None,
                        'CDP navigation requires profile and pre-navigation callback')
                deadline = started + timeout
                stabilization_started = started
                cdp = cdp_page(profile, deadline)
                probes = stabilize_cdp(cdp, deadline)
                stabilization_ms = (time.monotonic()-stabilization_started)*1000
                write(output/'browser-stabilization.json', dict(
                    status='PASS', criterion='cdp-about-blank-readiness-with-settle-interval',
                    limitation=('NetLog is finalized after Chromium exits; this barrier verifies CDP and '
                                'neutral-page readiness, not NetworkChangeNotifier internal state. '
                                'The effective loopback-only listening socket must also be verified by Ubuntu preflight.'),
                    cdp_configured_address='127.0.0.1',
                    settle_seconds=CDP_STABILIZATION_SETTLE_SECONDS,
                    probes=probes, stabilization_ms=stabilization_ms))
                before_navigation()
                navigation_started = time.monotonic()
                cdp.discard_events('Page.loadEventFired', 'Page.lifecycleEvent')
                metrics = cdp.command('Performance.getMetrics').get('metrics', [])
                navigation_timestamp = next((item.get('value') for item in metrics
                                             if item.get('name') == 'Timestamp'), None)
                require(isinstance(navigation_timestamp, (int, float)),
                        'CDP did not provide a navigation timestamp')
                navigation = cdp.command('Page.navigate', dict(url=target_url))
                frame_id = navigation.get('frameId'); loader_id = navigation.get('loaderId')
                require(isinstance(frame_id, str) and frame_id,
                        'CDP Page.navigate did not identify the experimental frame')
                require(loader_id is None or (isinstance(loader_id, str) and loader_id),
                        'CDP Page.navigate returned an invalid loader identifier')
                loads = cdp.wait_navigation_load(
                    frame_id, loader_id, navigation_timestamp, deadline)
                document = cdp.command('Runtime.evaluate', dict(
                    expression=('JSON.stringify({url:location.href,'
                                'html:document.documentElement.outerHTML})'), returnByValue=True))
                observed = json.loads(document.get('result', {}).get('value', '{}'))
                dom = observed.get('html')
                require(isinstance(dom, str) and dom, 'CDP did not return the navigated document')
                stdout.write(dom.encode('utf-8')); stdout.flush()
                write(output/'cdp-navigation.json', dict(
                    target_url=target_url, observed_url=observed.get('url'), page_navigate=navigation,
                    frame_id=frame_id, loader_id=loader_id,
                    navigation_timestamp=navigation_timestamp,
                    load_event_observed=bool(loads['load_event']),
                    matching_lifecycle_load_observed=bool(loads['lifecycle_event']),
                    document_observed=True,
                    navigation_wall_ms=(time.monotonic()-navigation_started)*1000))
                cdp.command('Browser.close')
                result = child.wait(timeout=max(0.01, deadline-time.monotonic()))
            else:
                result = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            result = 'timeout'
        except Exception as error:
            primary_error = error
            evidence = output/('cdp-navigation.json' if (output/'browser-stabilization.json').is_file()
                              else 'browser-stabilization.json')
            if not evidence.exists():
                try:
                    write(evidence, dict(status='FAIL', target_url=target_url,
                                         error=f'{type(error).__name__}: {error}'))
                except Exception as evidence_error:
                    cleanup_errors.append('write failure evidence: '+str(evidence_error))
            raise
        finally:
            if cdp is not None:
                try:
                    cdp.close()
                except Exception as error:
                    cleanup_errors.append('close CDP: '+str(error))
            terminate()
            timing = dict(pid=child.pid, browser_process_wall_ms=(time.monotonic()-started)*1000)
            stabilization = output/'browser-stabilization.json'
            try:
                if stabilization.is_file() and read(stabilization).get('status') == 'PASS':
                    timing['stabilization_ms'] = read(stabilization)['stabilization_ms']
                if cleanup_errors:
                    timing['cleanup_errors'] = cleanup_errors
                write(output/'browser-timing.json', timing)
            except Exception:
                if primary_error is None:
                    raise
            if cleanup_errors and primary_error is None:
                raise ValueError('Chromium cleanup failed: '+'; '.join(cleanup_errors))
    return result


def x509_spki_pin(selected, image):
    with docker_temporary_directory('browser-spki-') as temp:
        shutil.copyfile(selected['cert'], Path(temp)/'leaf.pem')
        script = ('set -eu\numask 077\n'
                  '/opt/mtc/openssl.sh x509 -in leaf.pem -pubkey -noout > public.pem\n'
                  '/opt/mtc/openssl.sh pkey -pubin -in public.pem -outform DER -out spki.der\n'
                  '/opt/mtc/openssl.sh dgst -sha256 -binary -out digest.bin spki.der\n'
                  '/opt/mtc/openssl.sh base64 -A -in digest.bin')
        pin = command(['docker', 'run', '--rm', '--pull', 'never', '--network', 'none',
                       '--user', f'{os.getuid()}:{os.getgid()}', '-v', temp+':/work', '-w', '/work',
                       '--entrypoint', '/bin/sh', image, '-c', script]).stdout.strip()
        require(len(base64.b64decode(pin, validate=True)) == 32, 'Invalid leaf SPKI SHA-256 pin')
        return pin


def run_case(case, credentials, browser, output, run_root, timeout, positive_control,
             browser_mode='headless', capture=None, x509_spki=None, trusted_subtrees=None,
             trusted_subtrees_url=None, key_establishment='x25519'):
    require(x509_spki is None or (case == 'x509-positive' and capture is None),
            'SPKI capability bypass is only for standalone x509-positive')
    output.mkdir()
    anchor = None
    if case.startswith('mtc-') and case != 'mtc-no-trust':
        anchor = Path(credentials['mtc']['anchor'])
        require(sha(anchor) == credentials['mtc']['anchor_sha256'], 'Positive anchor changed')
        if case in ('mtc-bad-merkle', 'mtc-bad-serial'):
            anchor = output/'derived-anchor.json'
            write(anchor, mutate_anchor(read(credentials['mtc']['anchor']), case))
    url = 'https://'+HOST+':4433/'+page_target(case, run_root)
    selected_group = key_establishment_config(key_establishment)
    server = Server(credentials, case, output, run_root, browser_mode=browser_mode,
                    key_establishment=key_establishment)
    try:
        if capture is not None:
            require(browser_mode == 'headless', 'PCAP validation requires headless mode')
            check_hostname()
        if capture is not None:
            capture.prepare_keylog()
        with tempfile.TemporaryDirectory(prefix='mtc-browser-profile-', dir=output) as profile:
            cmd = browser_command(
                browser['executable'],
                Path(profile),
                output,
                anchor,
                url,
                enable_mtc=case.startswith('mtc-'),
                browser_mode=browser_mode,
                disable_trust_anchor_ids=case == 'x509-positive',
                trusted_subtrees=trusted_subtrees if anchor else None,
                trusted_subtrees_url=trusted_subtrees_url if anchor else None,
                mtc_ca=credentials['mtc']['mtc_ca'] if anchor else None,
                mtc_ca_root=credentials['mtc']['mtc_ca_root'] if anchor else None,
            )
            if x509_spki is not None:
                cmd.insert(-1, '--ignore-certificate-errors-spki-list='+x509_spki)
            if capture is not None:
                cmd.insert(-1, '--ssl-key-log-file='+str(capture.keylog_path.resolve()))
            write(output/'chromium-command.json', dict(
                command=cmd, startup_url=cmd[-1], target_url=url, timeout_seconds=timeout))
            if browser_mode == 'headless':
                def begin_experiment():
                    server.start()
                    if capture is not None:
                        capture.start()
                exit_code = run_browser(cmd, output, timeout, profile=Path(profile),
                                        target_url=url, before_navigation=begin_experiment)
            else:
                server.start()
                if capture is not None:
                    capture.start()
                exit_code = run_browser(cmd, output, timeout)
        # Flush server logs after browser exits; preserve files before removing container.
        if capture is not None:
            capture.stop()
        server.stop(); server.created = False
        result = classify(case, output, url, exit_code, positive_control=positive_control,
                          requested_tai=credentials['mtc']['requested_tai'],
                          selected_tai=credentials['mtc']['selected_tai'],
                          trusted_subtrees_url=trusted_subtrees_url,
                          expected_group=selected_group['netlog_group'])
        result.update(key_establishment=key_establishment,
                      key_establishment_label=selected_group['key_establishment_label'],
                      tls_group=selected_group['group'],
                      signature_profile=credentials['mtc']['profile'],
                      mtc_trust_mode=credentials['mtc']['mode'],
                      requested_tai=credentials['mtc']['requested_tai'],
                      selected_tai=credentials['mtc']['selected_tai'],
                      mtc_verification_evidence=(
                          'authenticated TLS 1.3 plus observed requested/selected '
                          'MTC trust-anchor identity'))
        if x509_spki is not None:
            result.update(x509_trust_mode='spki-capability-bypass', normal_trusted_x509_baseline=False)
        timing = read(output/'browser-timing.json')
        result['browser_process_wall_ms'] = timing.get('browser_process_wall_ms')
        result['stabilization_ms'] = timing.get('stabilization_ms')
        if browser_mode == 'headed':
            # Keep the automated classifier intact; inspection lacks NetLog and DOM evidence.
            result.update(browser_mode='headed', observed_outcome='INSPECTION', **{'pass': False},
                          reason='Visible browser inspection only; no automated PASS. '
                                 'NetLog and DOM evidence are unavailable. The owned browser is closed at the timeout limit.')
        return result
    finally:
        try:
            if capture is not None:
                capture.stop()
        finally:
            server.stop()


def blocked_summary(output, reason, browser=None, key_establishment='x25519'):
    selected_group = key_establishment_config(key_establishment)
    credentials = read(output/'credentials.json') if (output/'credentials.json').is_file() else None
    return dict(overall_pass=False, status='BLOCKED', timestamp=datetime.now(timezone.utc).isoformat(),
                hostname=HOST, tls=selected_group, key_establishment=key_establishment,
                chromium=browser, credentials=credentials, reason=reason,
                cases=[dict(name=c, expected_outcome='accept' if c.endswith('positive') else 'reject',
                            observed_outcome='INCONCLUSIVE', **{'pass': False}, reason='Not executed: '+reason,
                            server_authentication_flight_observed=None, server_finished_observed=None,
                            client_finished_observed=None, application_data_observed=None, net_errors=[],
                            evidence={'credentials': str(output/'credentials.json')}) for c in CASES])


def new_result(repo):
    root = repo/'artifacts/results'/('chromium-browser-validation-'+stamp())
    root.mkdir(parents=True, exist_ok=False)
    write(root/'owner.json', dict(workflow=LABEL, root=str(root.resolve())))
    return root.resolve()


def owned_results(repo):
    for root in sorted((repo/'artifacts/results').glob('chromium-browser-validation-*')):
        if root.is_dir() and not root.is_symlink() and (root/'owner.json').is_file():
            if read(root/'owner.json') == dict(workflow=LABEL, root=str(root.resolve())):
                yield root


def functional_mode_status(repo, trust_mode):
    require(trust_mode in ('landmark', 'standalone'),
            'Unsupported MTC trust mode')
    roots = sorted((Path(repo)/'artifacts/results').glob(
        'chromium-browser-validation-*'), reverse=True)
    for root in roots:
        summary_path = root/'summary.json'
        if not summary_path.is_file():
            continue
        try:
            summary = read(summary_path)
        except (OSError, ValueError, TypeError):
            continue
        if summary.get('mtc_trust_mode') != trust_mode:
            continue
        try:
            credentials = read(root/'credentials.json')
            result = read(root/'mtc-positive/result.json')
            require(credentials.get('mtc', {}).get('mode') == trust_mode,
                    'Credential mode does not match summary')
            require(result.get('mtc_trust_mode') == trust_mode,
                    'Result mode does not match summary')
            require(result.get('name') == 'mtc-positive',
                    'Missing mode-specific positive result')
            required = (
                'server_authentication_flight_observed',
                'server_finished_observed', 'client_finished_observed',
                'application_data_observed', 'requested_tai_observed',
                'selected_tai_observed', 'negotiated_canonical_tls')
            require(all(result.get(field) is True for field in required),
                    'Mode-specific authenticated TLS evidence is incomplete')
            evidence = result.get('evidence')
            require(isinstance(evidence, dict), 'Missing evidence inventory')
            for name in ('netlog.json', 'server.log', 'chromium.stdout.log',
                         'chromium.stderr.log'):
                require(name in evidence and Path(evidence[name]).is_file(),
                        'Missing evidence file: '+name)
            require(result.get('pass') is True
                    and result.get('observed_outcome') == 'PASS',
                    result.get('reason') or 'Mode-specific positive run failed')
            return 'PASS', None
        except (OSError, ValueError, KeyError, TypeError) as error:
            return 'FAIL', str(error)
    return 'NOT RUN', None


def cleanup(repo):
    # Abandoned processes are not killed by stored PID (PID reuse risk). Report them.
    for root in owned_results(repo):
        for record in root.glob('*/server-owner.json'):
            owner = read(record)
            info = command(['docker', 'inspect', owner['name']], check=False)
            if info.returncode:
                continue
            data = json.loads(info.stdout)[0]
            require(data['Config'].get('Labels', {}).get(LABEL) == str(root.resolve()), 'Foreign container preserved')
            command(['docker', 'rm', '-f', owner['name']])
        for profile in root.glob('*/mtc-browser-profile-*'):
            print('Preserved orphan profile (inspect process ownership before removal): '+str(profile))
    print('Owned containers cleaned; all evidence preserved. Normal runs clean their own process groups/profiles.')


def standalone_operation_allowed(action, case, mtc_fixture,
                                 optimized_all_profiles):
    return bool(
        (action == 'credentials'
         and (mtc_fixture is not None or optimized_all_profiles))
        or (action == 'run' and mtc_fixture is not None
            and case in ('mtc-positive', 'mtc-no-trust',
                         'mtc-bad-serial')))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'credentials', 'prepare-mtc-dependencies', 'status', 'run', 'cleanup',
                                           'trust-status', 'trust-x509', 'untrust-x509'))
    parser.add_argument('case', nargs='?', choices=(*CASES, 'all'))
    parser.add_argument('--root', type=Path, help='Exact PEM root required for trust-status/trust-x509/untrust-x509; no fixture discovery')
    parser.add_argument('--profile', choices=PROFILES, default=PROFILE)
    parser.add_argument('--profiles', nargs='+', choices=PROFILES)
    parser.add_argument('--key-establishment', choices=tuple(KEY_ESTABLISHMENTS), default='x25519',
                        help='Group restricted at the server and verified in NetLog (default: x25519)')
    parser.add_argument('--depth', type=int, choices=(2, 3, 4, 5), default=2)
    parser.add_argument('--mtc-fixture', type=Path, help='Explicit prevalidated MTC fixture; requires --mtc-validation')
    parser.add_argument('--mtc-validation', type=Path, help='Existing validation.json for the selected MTC fixture')
    parser.add_argument('--mtc-trust-mode', choices=('landmark', 'standalone'),
                        default='landmark',
                        help='Plants-07 trust mode (default: landmark)')
    parser.add_argument('--x509-fixture-set')
    parser.add_argument('--chromium', type=Path)
    parser.add_argument('--mtc-trusted-subtrees', type=Path,
                        help='Optional prevalidated RP trusted-subtrees.mts1 override for MTC cases')
    parser.add_argument('--mtc-trusted-subtrees-url',
                        help='Optional RP HTTP(S) endpoint providing trusted-subtrees.mts1 for MTC cases')
    parser.add_argument('--x509-spki-capability', action='store_true',
                        help='Standalone x509-positive capability test with leaf SPKI trust bypass; not a trusted baseline')
    parser.add_argument('--x509-chromium-ca-policy', action='store_true',
                        help='Use an externally installed Chromium CACertificates policy as the X.509 trust anchor; no certificate bypass')
    parser.add_argument('--browser-mode', choices=('headless', 'headed'), default='headless',
                        help='headless: automated validation (default); headed: bounded visual inspection, never automated PASS')
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--image', default='mt-tls-mtc:local', help='Existing image used only for generation fallback')
    parser.add_argument('--optimized-all-profiles', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--precheck-index', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--precheck-total', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--docker-count-file', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    require((args.mtc_fixture is None) == (args.mtc_validation is None), 'Supply both --mtc-fixture and --mtc-validation')
    require(args.mtc_fixture is None or args.action in ('run', 'credentials'), 'Explicit MTC evidence requires run or credentials')
    require(args.mtc_trusted_subtrees is None or
            (args.action == 'run' and (args.case == 'all' or args.case in CASES[:4])),
            '--mtc-trusted-subtrees requires run with an MTC case or all')
    require(args.mtc_trusted_subtrees_url is None or
            (args.action == 'run' and (args.case == 'all' or args.case in CASES[:4])),
            '--mtc-trusted-subtrees-url requires run with an MTC case or all')
    require(not (args.mtc_trusted_subtrees is not None and
                 args.mtc_trusted_subtrees_url is not None),
            '--mtc-trusted-subtrees and --mtc-trusted-subtrees-url are mutually exclusive')
    require(args.mtc_trust_mode == 'landmark' or
            standalone_operation_allowed(
                args.action, args.case, args.mtc_fixture,
                args.optimized_all_profiles),
            'Standalone MTC supports mtc-positive, mtc-no-trust and '
            'mtc-bad-serial runs, or credentials preparation, with explicit '
            'prevalidated fixture/evidence; '
            'mtc-bad-merkle and all remain landmark-only')
    require(args.mtc_trust_mode == 'landmark' or
            (args.mtc_trusted_subtrees is None
             and args.mtc_trusted_subtrees_url is None),
            'Standalone MTC forbids trusted-subtree overrides')
    trust_operation = args.action in ('trust-status', 'trust-x509', 'untrust-x509')
    require((args.root is not None) == trust_operation, '--root PATH is required only for trust-status/trust-x509/untrust-x509')
    require(not args.x509_fixture_set or args.action in ('run', 'credentials'),
            '--x509-fixture-set requires run or credentials')
    require(not args.x509_spki_capability or (args.action == 'run' and args.case == 'x509-positive'),
            '--x509-spki-capability requires run x509-positive')
    require(not args.x509_chromium_ca_policy or args.action == 'credentials' or
            (args.action == 'run' and args.case == 'x509-positive'),
            '--x509-chromium-ca-policy requires credentials or run x509-positive')
    require(not (args.x509_spki_capability and args.x509_chromium_ca_policy),
            'SPKI capability bypass and Chromium CA policy modes are mutually exclusive')
    require(5 <= args.timeout <= 300, 'Timeout must be between 5 and 300 seconds')
    require((args.action == 'run') == bool(args.case), 'run requires CASE; other actions take no case')
    require(not (args.case == 'all' and args.browser_mode == 'headed'), 'Run all requires headless automated validation')
    require(not args.optimized_all_profiles or
            (args.action == 'credentials' and args.precheck_index and args.precheck_total and
             args.docker_count_file is not None),
            'Optimized all-profile credentials require bounded progress/count metadata')
    require(args.profiles is None or args.action == 'prepare-mtc-dependencies',
            '--profiles requires prepare-mtc-dependencies')
    if args.action == 'prepare-mtc-dependencies':
        require(args.case is None, 'prepare-mtc-dependencies takes no case')
        prepare_mtc_dependencies(REPO, args.image, args.profiles or (args.profile,))
        return 0
    if args.action in ('trust-status', 'trust-x509', 'untrust-x509'):
        return trust_action(args.action, args.root, args.image)
    if args.action == 'plan':
        print('PRINT ONLY: discover -> strictly validate -> reuse; generate only if no valid candidate.')
        print('Search: artifacts/mtc, artifacts/x509, artifacts/cert-chain-scaling')
        selected_group = key_establishment_config(args.key_establishment)
        print('Identity: '+HOST+'; '+args.profile+'; X509 D='+str(args.depth)
              +'; MTC N=16 '+args.mtc_trust_mode+' leaf 0')
        print('Key establishment: '+selected_group['key_establishment_label']+' ('+selected_group['group']+')')
        print('Cases: '+', '.join(CASES)); print('TLS: '+json.dumps(selected_group))
        if args.browser_mode == 'headless':
            print('Existing patched Chromium only. Each case: fresh profile, bounded headless run, NetLog/server/DOM evidence.')
        else:
            print('Visible browser inspection only: fresh profile, bounded headed run, server evidence; no NetLog, DOM or automated PASS.')
        print('No trust installation. No build/fetch/sync. Normal resume cannot reach this namespace.'); return 0
    if args.action == 'status':
        roots = list(owned_results(REPO))
        if not roots:
            print('NO BROWSER VALIDATION RESULTS'); return 0
        last = roots[-1]; print('Latest: '+str(last))
        if (last/'credentials.json').exists():
            data = read(last/'credentials.json'); print('MTC: '+data['mtc']['fixture']); print('X509: '+data['x509']['fixture'])
            trust = root_trust(data['x509']); print('Current X509 root trust: '+trust['status'])
            if trust['status'] != 'TRUSTED': print('Explicit manual action:\n'+trust['manual_command'])
        if (last/'summary.json').exists(): print(json.dumps(read(last/'summary.json'), indent=2))
        return 0
    if args.action == 'cleanup':
        cleanup(REPO); return 0
    # Serialize credential fallback and case runs without touching other workflows.
    lock = REPO/'.mt-state/chromium-browser-validation.lock'
    lock.parent.mkdir(exist_ok=True)
    try: lock.mkdir()
    except FileExistsError: raise ValueError('Browser validation locked; inspect active run before retrying')
    output = None
    browser = None
    started = time.monotonic()
    progress_prefix = (f'[PRECHECK] {args.precheck_index}/{args.precheck_total} {args.profile}'
                       if args.optimized_all_profiles else None)
    def credential_progress(stage):
        if progress_prefix:
            print(f'{progress_prefix}: {stage}...', flush=True)
    try:
        output = new_result(REPO); print('Result directory: '+str(output), flush=True)
        credential_progress('selecting fixtures')
        credentials = prepare_credentials(
            REPO, output, args.image, args.profile, args.depth,
            args.x509_fixture_set, args.mtc_fixture, args.mtc_validation,
            optimized_all_profiles=args.optimized_all_profiles,
            progress=credential_progress,
            mtc_trust_mode=args.mtc_trust_mode)
        if args.action == 'credentials':
            credential_progress('checking CACertificates')
            policy_metadata = chromium_ca_policy_report(
                credentials['x509']['root'], required=args.x509_chromium_ca_policy)
            write(output/'chromium-ca-policy.json', policy_metadata)
        else:
            policy_metadata = (chromium_ca_policy(credentials['x509']['root'])
                               if args.x509_chromium_ca_policy else None)
        trust = credentials['x509']['root_trust']
        print('MTC '+credentials['mtc']['origin']+': '+credentials['mtc']['fixture'])
        print('X509 '+credentials['x509']['origin']+': '+credentials['x509']['fixture'])
        if args.action == 'credentials':
            print_credentials_trust(trust, policy_metadata)
        else:
            print('X509 root trust: '+trust['status'])
        if (args.action == 'run' and args.case in ('x509-positive', 'all')
                and not args.x509_spki_capability
                and not args.x509_chromium_ca_policy
                and trust['status'] != 'TRUSTED'):
            print('Explicit manual action (not executed):\n'+trust['manual_command'])
            write(output/'summary.json', blocked_summary(output, 'X509 root trust not established',
                                                         key_establishment=args.key_establishment))
            return 2
        if args.action == 'credentials':
            if args.docker_count_file is not None:
                with args.docker_count_file.open('a') as counter:
                    counter.write(str(DOCKER_RUN_COUNT)+'\n')
            if progress_prefix:
                print(f'{progress_prefix}: PASS ({time.monotonic()-started:.1f}s; '
                      f'docker runs={DOCKER_RUN_COUNT})', flush=True)
            return 0
        if args.mtc_trusted_subtrees is not None:
            anchor_config = read(credentials['mtc']['anchor'])
            validate_mts1(args.mtc_trusted_subtrees, anchor_config['log_number'])
        spki = x509_spki_pin(credentials['x509'], args.image) if args.x509_spki_capability else None
        browser = browser_executable(args.chromium)
        # Bind only, never probe TLS. Refuse any incumbent server, even another workflow.
        with socket.socket() as sock:
            try: sock.bind(('127.0.0.1', 4433))
            except OSError: raise ValueError('Port 4433 occupied. Stop its owner explicitly; this workflow will not replace it.')
        cases = CASES if args.case == 'all' else (('mtc-positive', args.case) if args.case in CASES[1:4] else (args.case,))
        results = []; positive_pass = False
        selected_group = key_establishment_config(args.key_establishment)
        summary = dict(overall_pass=False, timestamp=datetime.now(timezone.utc).isoformat(), chromium=browser,
                       hostname=HOST, tls=selected_group, key_establishment=args.key_establishment,
                       mtc_trust_mode=args.mtc_trust_mode,
                       credentials=credentials, cases=results)
        if args.x509_spki_capability:
            summary.update(x509_trust_mode='spki-capability-bypass',
                           normal_trusted_x509_baseline=False,
                           certificate_verification_bypass=True,
                           leaf_spki_sha256_base64=spki)
        elif args.x509_chromium_ca_policy:
            summary.update(policy_metadata,
                           fixture_root_pem_sha256=credentials['x509']['root_sha256'])
        if args.browser_mode == 'headed':
            summary.update(browser_mode='headed', validation_mode='visual_inspection')
            print(f'Visible inspection only; each owned browser closes after at most {args.timeout} seconds. No automated PASS.', flush=True)
        for case in cases:
            # Recheck immutable input fingerprints before every invocation.
            for selected, keys in [(credentials['mtc'], [('cert','cert_sha256'),('key','key_sha256'),('trust','trust_sha256'),('anchor','anchor_sha256')]),
                                   (credentials['x509'], [('cert','certificate_sha256'),('key','key_sha256'),('root','root_sha256')])]:
                for pathkey, hashkey in keys: require(sha(selected[pathkey]) == selected[hashkey], 'Credential changed: '+pathkey)
            try:
                result = run_case(case, credentials, browser, output/case, output, args.timeout, positive_pass,
                                  browser_mode=args.browser_mode, x509_spki=spki,
                                  trusted_subtrees=args.mtc_trusted_subtrees,
                                  trusted_subtrees_url=args.mtc_trusted_subtrees_url,
                                  key_establishment=args.key_establishment)
            except Exception as e:
                result = next(r for r in blocked_summary(output, str(e), browser,
                    key_establishment=args.key_establishment)['cases'] if r['name'] == case)
                result['reason'] = 'Execution incomplete: '+str(e)
                (output/case).mkdir(exist_ok=True)
            if args.x509_spki_capability:
                result.update(x509_trust_mode='spki-capability-bypass',
                              normal_trusted_x509_baseline=False,
                              certificate_verification_bypass=True)
            elif args.x509_chromium_ca_policy:
                result.update(policy_metadata,
                              fixture_root_pem_sha256=credentials['x509']['root_sha256'])
            write(output/case/'result.json', result); results.append(result)
            if case == 'mtc-positive': positive_pass = result['pass']
            print(case+': '+result['observed_outcome']+' — '+result['reason'], flush=True)
        summary['overall_pass'] = all(r['pass'] for r in results)
        write(output/'summary.json', summary)
        if args.browser_mode == 'headed':
            return 2  # Inspection does not establish automated validation success.
        return 0 if summary['overall_pass'] else 1
    except Exception as e:
        if output and not (output/'summary.json').exists():
            failure = blocked_summary(output, str(e), browser, key_establishment=args.key_establishment)
            if args.x509_spki_capability:
                failure.update(x509_trust_mode='spki-capability-bypass', normal_trusted_x509_baseline=False)
            write(output/'summary.json', failure)
        raise
    finally:
        lock.rmdir()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('ERROR: '+str(error), file=sys.stderr)
        sys.exit(1)
