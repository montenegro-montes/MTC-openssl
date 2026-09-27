#!/usr/bin/env python3
"""Explicit, evidence-gated browser battery; never builds or installs trust."""
import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE))
from export_chromium_anchor import Reader, parse_landmark, core

HOST = 'server.mtc.example.com'
PROFILE = 'ecdsa-p256'
REQUESTED = '32473.101.2.1.1'
SELECTED = '32473.101.1.1.1'
CA = '32473.101'
CASES = ('mtc-positive', 'mtc-no-trust', 'mtc-bad-merkle', 'mtc-bad-serial', 'x509-positive')
TLS = dict(version='TLS 1.3', group='X25519', cipher='TLS_AES_256_GCM_SHA384',
           tickets=False, client_authentication=False, port=4433)
LABEL = 'mtc.browser-validation'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


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


def crypto():
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization, hashes as algorithms
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID
    return x509, serialization, algorithms, ec, ExtendedKeyUsageOID


def validity_utc(cert):
    # cryptography before 42 exposes naive UTC datetimes only.
    def value(name):
        modern = getattr(cert, name + '_utc', None)
        if modern is not None:
            return modern
        legacy = getattr(cert, name)
        return legacy.replace(tzinfo=timezone.utc) if legacy.tzinfo is None else legacy.astimezone(timezone.utc)
    return value('not_valid_before'), value('not_valid_after')


def web_leaf(cert_path, key_path, *, now=None):
    x509, ser, _, ec, eku = crypto()
    require(not Path(cert_path).is_symlink() and not Path(key_path).is_symlink(), 'Symlink credential rejected')
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    require(HOST in sans, 'Wrong SAN: browser hostname absent')
    require(not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, 'CA leaf rejected')
    require(cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature, 'Missing Digital Signature KU')
    require(eku.SERVER_AUTH in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value, 'Missing serverAuth EKU')
    now = now or datetime.now(timezone.utc)
    not_before, not_after = validity_utc(cert)
    require(not_before <= now <= not_after, 'Expired/not-yet-valid certificate')
    pub = cert.public_key()
    require(isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP256R1), 'Leaf is not ECDSA P-256')
    key = ser.load_pem_private_key(Path(key_path).read_bytes(), password=None)
    encode = lambda k: k.public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
    require(encode(pub) == encode(key.public_key()), 'Certificate/key mismatch')
    return cert, dict(SAN=sans, KU=['Digital Signature'], EKU=['serverAuth'],
                      not_before=not_before.isoformat(), not_after=not_after.isoformat(),
                      hostname_validation=True, key_match=True)


def validate_mtc(fixture):
    fixture = Path(fixture)
    manifest = read(fixture / 'manifest.json')
    require(manifest.get('server_hostname') == HOST, 'MTC manifest hostname mismatch')
    require(PROFILE in manifest.get('profiles', []) and 16 in manifest.get('sizes', []), 'MTC profile/tree size mismatch')
    directory = fixture / 'batch16/mtc' / PROFILE
    meta = read(directory / 'manifest.json')
    require(meta.get('profile') == PROFILE and meta.get('tree_size') == 16 and
            meta.get('draft') == core.DRAFT and meta.get('merkle_hash') == 'SHA-256', 'MTC metadata mismatch')
    check_saved_hashes(directory, read(directory / 'fixture-sha256.json'))
    cert_path, key_path = directory / 'landmark-0000.pem', fixture / 'population' / PROFILE / '0.key'
    cert, leaf = web_leaf(cert_path, key_path)
    require(cert.serial_number == 1 << 48, 'MTC credential is not log 1 leaf 0')
    raw = (directory / 'trust.bin').read_bytes()
    anchor = parse_landmark(raw)
    require(anchor['ca_id'] == CA and anchor['landmark']['tree_size'] == 16 and
            anchor['min_serial'] == 1 << 48 and anchor['max_serial'] == (1 << 48) + 15 and
            anchor['landmark']['requested_trust_anchor_id'] == REQUESTED and
            anchor['landmark']['selected_trust_anchor_id'] == SELECTED, 'MTC trust identity mismatch')
    # Authenticate the checkpoint, not just its file hash or JSON syntax.
    x509, ser, alg, ec, _ = crypto()
    r = Reader(raw); r.take(4); r.vector(1)
    signers = [(r.vector(1).decode(), r.vector(2)) for _ in range(r.number(1))]
    r.number(2); r.number(8); r.number(8); r.number(4)
    size, timestamp, root_hash = r.number(6), r.number(8), r.take(32)
    require(timestamp <= int(time.time()), 'Future checkpoint timestamp')
    sr = Reader(r.vector()); verified = set()
    while sr.pos < len(sr.data):
        ident, signature = sr.vector(1), sr.vector()
        require(ident not in verified, 'Duplicate checkpoint signer')
        matched = [(name, spki) for name, spki in signers if core.relid(name) == ident]
        require(len(matched) == 1, 'Unknown checkpoint signer')
        name, spki = matched[0]; public = ser.load_der_public_key(spki)
        require(isinstance(public, ec.EllipticCurvePublicKey) and isinstance(public.curve, ec.SECP256R1), 'Checkpoint signer profile mismatch')
        public.verify(signature, core.message(name, CA, 0, size, root_hash, timestamp), ec.ECDSA(alg.SHA256()))
        verified.add(ident)
    require(verified == {core.relid(name) for name, _ in signers}, 'Incomplete checkpoint authentication')
    der = cert.public_bytes(ser.Encoding.DER)
    outer, tbs = core.certificate_parts(der)
    require(outer[1][2] == core.ALG and tbs[2][2] == core.ALG and tbs[3][2] == core.name(CA), 'MTC algorithm/issuer mismatch')
    require(outer[2][1][0] == 0, 'Invalid MTC bit string')
    pr = Reader(outer[2][1][1:]); extensions = pr.vector(); start, end = pr.number(6), pr.number(6)
    path = pr.vector(); signatures = pr.vector(); pr.finish()
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
            c.get('profile') == PROFILE and c.get('tree_size') == 16 and c.get('mtc_mode') == 'landmark' and c.get('success') is True
            for c in d.get('cells', [])), 'Existing functional evidence does not PASS')
        if 'fixture_hashes' in d:
            check_saved_hashes(fixture, d['fixture_hashes'], complete=True)
        evidence = p
    image = (read(evidence) if evidence else manifest).get('provenance', {}).get('image_id')
    require(isinstance(image, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'Missing pinned MTC image')
    return dict(fixture=str(fixture.resolve()), cert=str(cert_path.resolve()), key=str(key_path.resolve()),
                trust=str((directory/'trust.bin').resolve()), profile=PROFILE, tree_size=16, mode='landmark', leaf=0,
                hostname=HOST, validation_evidence=str(evidence.resolve()) if evidence else None,
                complete_evidence=bool(evidence and 'fixture_hashes' in read(evidence)),
                fixture_hash_status='MATCH' if evidence and 'fixture_hashes' in read(evidence) else 'LOCAL_HASHES_AND_CRYPTO_VERIFIED',
                requested_tai=REQUESTED, selected_tai=SELECTED, image_id=image,
                cert_sha256=sha(cert_path), key_sha256=sha(key_path), trust_sha256=sha(directory/'trust.bin'), **leaf)


def validate_x509(fixture, *, openssl='openssl'):
    fixture = Path(fixture)
    cert_path, key_path, root_path = [fixture / n for n in ('server.pem', 'server.key', 'root.pem')]
    cert, leaf = web_leaf(cert_path, key_path)
    x509, _, _, _, _ = crypto()
    require(not root_path.is_symlink(), 'Symlink root rejected')
    root = x509.load_pem_x509_certificate(root_path.read_bytes())
    require(root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, 'Root is not a CA')
    require(root.subject == root.issuer, 'Root is not self-issued')
    command([openssl, 'verify', '-check_ss_sig', '-CAfile', root_path, root_path])
    intermediate = fixture / 'intermediates.pem'
    args = [openssl, 'verify', '-CAfile', root_path, '-purpose', 'sslserver', '-verify_hostname', HOST]
    if intermediate.is_file() and intermediate.stat().st_size:
        args += ['-untrusted', intermediate]
    command(args + [cert_path])
    manifest = fixture / 'manifest.json'
    complete = False
    if manifest.is_file():
        d = read(manifest)
        if d.get('files_sha256'):
            check_saved_hashes(fixture, d['files_sha256']); complete = True
    return dict(fixture=str(fixture.resolve()), cert=str(cert_path.resolve()), key=str(key_path.resolve()),
                root=str(root_path.resolve()), intermediates=str(intermediate.resolve()) if intermediate.is_file() and intermediate.stat().st_size else None,
                certificate_sha256=sha(cert_path), key_sha256=sha(key_path), root_sha256=sha(root_path),
                profile=PROFILE, hostname=HOST, complete_evidence=complete,
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
    raw = Path(mtc['trust']).read_bytes(); expected = parse_landmark(raw)
    expected['source'] = dict(trust_file='trust.bin', trust_file_bytes=len(raw), trust_file_sha256=hashlib.sha256(raw).hexdigest())
    meta = read(Path(mtc['trust']).with_name('manifest.json'))
    for key in ('profile', 'draft', 'trust_anchor_draft', 'implementation_algorithm', 'merkle_hash'):
        expected[key] = meta.get(key)
    return expected


def choose_anchor(mtc, output):
    expected = expected_anchor(mtc); fixture = Path(mtc['fixture'])
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
        command([sys.executable, HERE/'export_chromium_anchor.py', '--trust', mtc['trust'], '--output', anchor])
        require(read(anchor) == expected, 'Exported anchor mismatch')
    return dict(anchor=str(anchor.resolve()), anchor_sha256=sha(anchor), anchor_origin=origin, anchor_candidates=audit)


def generate_mtc(repo, output, image):
    fixture = repo/'artifacts/mtc'/('browser-'+HOST.replace('.', '-')+'-'+PROFILE+'-n16-'+stamp())
    validation = fixture.with_name(fixture.name+'-validation')
    for action, extra in [('generate', ['--output', fixture]), ('validate', ['--fixtures', fixture, '--output', validation])]:
        result = command([sys.executable, HERE/'fixtures.py', action, *extra, '--server-hostname', HOST, '--image', image, '--execute'], timeout=1800)
        (output/(action+'-mtc.stdout.log')).write_text(result.stdout)
        (output/(action+'-mtc.stderr.log')).write_text(result.stderr)
    return fixture


def generate_x509(repo):
    # The shared chain builder fixes SAN=server/localhost; a small browser-specific
    # direct-root fixture is needed instead of altering unrelated campaign PKI.
    x509, ser, alg, ec, _ = crypto()
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    out = repo/'artifacts/x509'/('chromium-'+HOST.replace('.', '-')+'-'+PROFILE+'-'+stamp())
    out.mkdir(parents=True, exist_ok=False)
    now = datetime.now(timezone.utc)
    root_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Chromium MTC comparison lab '+out.name[-8:])])
    def builder(subject, issuer, key):
        return x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=30))
    root = builder(name, name, root_key).add_extension(x509.BasicConstraints(ca=True, path_length=0), True).add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True).sign(root_key, alg.SHA256())
    leaf = builder(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]), name, leaf_key).add_extension(x509.BasicConstraints(ca=False, path_length=None), True).add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), False).add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False).sign(root_key, alg.SHA256())
    for label, cert, key in [('root', root, root_key), ('server', leaf, leaf_key)]:
        (out/(label+'.pem')).write_bytes(cert.public_bytes(ser.Encoding.PEM))
        p = out/(label+'.key')
        fd = os.open(p, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    write(out/'manifest.json', dict(hostname=HOST, profile=PROFILE, files_sha256=hashes(out)))
    return out


def root_trust(x):
    root = Path(x['root']); system = platform.system()
    if system == 'Darwin':
        args = ['security', 'verify-cert', '-L', '-p', 'ssl', '-n', HOST, '-c', x['cert']]
        if x.get('intermediates'):
            # security accepts certificate files; split PEM bundle into a temp audit dir.
            certs = crypto()[0].load_pem_x509_certificates(Path(x['intermediates']).read_bytes())
        else:
            certs = []
        with tempfile.TemporaryDirectory(prefix='mtc-trust-audit-') as temp:
            for i, cert in enumerate(certs):
                p = Path(temp)/f'{i}.pem'; p.write_bytes(cert.public_bytes(crypto()[1].Encoding.PEM)); args += ['-c', str(p)]
            result = command(args+['-c', str(root)], check=False)
        manual = 'sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain '+shlex.quote(str(root))
        return dict(status='TRUSTED' if result.returncode == 0 else 'UNTRUSTED_OR_UNAVAILABLE', method='security verify-cert -L ssl (no explicit trust override)',
                    returncode=result.returncode, diagnostic=(result.stdout+result.stderr)[-2000:], manual_command=manual)
    if system == 'Linux':
        home_db = Path.home()/'.pki/nssdb'
        db = home_db if home_db.is_dir() else Path(os.environ.get('XDG_DATA_HOME', str(Path.home()/'.local/share')))/'pki/nssdb'
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
                    x509, _, alg, _, _ = crypto()
                    trusted |= x509.load_pem_x509_certificate(pem.stdout.encode()).fingerprint(alg.SHA256()) == x509.load_pem_x509_certificate(root.read_bytes()).fingerprint(alg.SHA256())
                except ValueError:
                    pass
        return dict(status='TRUSTED' if trusted else 'UNTRUSTED_OR_UNAVAILABLE', method='Chromium user NSS DB: exact root fingerprint and SSL CA trust', database=str(db), manual_command='\n'.join(manual), note='Requires certutil (NSS tools); no installation performed. Browser control remains authoritative.')
    return dict(status='UNSUPPORTED', manual_command='Use the platform browser trust-store mechanism explicitly.')


def prepare_credentials(repo, output, image):
    try:
        crypto()
    except ImportError as error:
        raise ValueError('Python cryptography is required for credential validation; no generation attempted') from error
    mtc_paths = [p.parent for p in (repo/'artifacts/mtc').glob('*/manifest.json')]
    mtc, ma = select_or_generate(mtc_paths, validate_mtc, lambda: generate_mtc(repo, output, image), output/'mtc-discovery.json')
    mtc.update(choose_anchor(mtc, output))
    xpaths = []
    for root in (repo/'artifacts/x509', repo/'artifacts/cert-chain-scaling'):
        xpaths += [p.parent for p in root.rglob('server.pem')]
    x, xa = select_or_generate(xpaths, validate_x509, lambda: generate_x509(repo), output/'x509-discovery.json')
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
                      Path.home()/'Desktop/chromium-mtc/src/out/mtc-release/chrome']
    for p in candidates:
        if p.is_file() and os.access(p, os.X_OK):
            commit = command(['git', '-C', p.parent, 'rev-parse', 'HEAD'], check=False).stdout.strip() or None
            return dict(executable=str(p.resolve()), sha256=sha(p), commit=commit,
                        hash_scope='Launcher/executable only; component libraries are not covered')
    raise ValueError('Existing patched Chromium executable missing; use --chromium PATH. No build attempted.')


def browser_command(executable, profile, case_dir, anchor, url, enable_mtc=False):
    flags = [str(executable), '--headless=new', '--dump-dom', '--no-first-run', '--no-default-browser-check',
             '--disable-background-networking', '--disable-component-update', '--disable-sync', '--disable-quic',
             '--no-proxy-server', '--host-resolver-rules=MAP '+HOST+' 127.0.0.1',
             '--user-data-dir='+str(profile), '--log-net-log='+str(case_dir/'netlog.json'),
             '--net-log-capture-mode=Everything']
    if enable_mtc:
        flags.append('--enable-features=MtcPlants05Lab,VerifyMTCs')
    if anchor:
        flags.append('--mtc-plants05-trust='+str(anchor))
    return flags + [url]


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


def encrypted_extensions_selected(events):
    for name, params, _, _ in events:
        if name != 'SSL_HANDSHAKE_MESSAGE_RECEIVED' or params.get('type') != 8:
            continue
        try:
            raw = base64.b64decode(params['bytes'], validate=True)
            require(raw[0] == 8 and int.from_bytes(raw[1:4], 'big') == len(raw)-4, 'Malformed handshake')
            r = Reader(raw[4:]); extensions = Reader(r.vector()); r.finish()
            while extensions.pos < len(extensions.data):
                kind, value = extensions.number(2), extensions.vector()
                if kind == 0xca34:
                    ids = Reader(value); entries = Reader(ids.vector()); ids.finish()
                    while entries.pos < len(entries.data):
                        if entries.vector(1) == core.relid(SELECTED):
                            return True
        except (ValueError, KeyError, IndexError):
            continue
    return False


def classify(case, case_dir, url, process, *, positive_control=False):
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
    result['requested_tai_observed'] = any(REQUESTED in str(p) for p in requests)
    result['selected_tai_observed'] = encrypted_extensions_selected(events)
    ssl_connections = [p for name, p, _, _ in events if name == 'SSL_CONNECT' and p.get('version')]
    negotiated = any(p.get('version') == 'TLS 1.3' and p.get('cipher_suite') == 0x1302 and
                     p.get('key_exchange_group') == 29 and p.get('is_resumed') is False for p in ssl_connections)
    http = any(name == 'HTTP_TRANSACTION_READ_RESPONSE_HEADERS' and re.search(r'HTTP/\S+ 200', str(p)) for name, p, _, _ in events)
    dom = 'TLS_AES_256_GCM_SHA384' in stdout and ('s_server' in stdout or 'SSL-Session' in stdout)
    result['application_data_observed'] = http and dom
    result['negotiated_canonical_tls'] = negotiated
    result['target_url'] = url
    received = [p.get('type') for name, p, _, _ in events if name == 'SSL_HANDSHAKE_MESSAGE_RECEIVED']
    sent = [p.get('type') for name, p, _, _ in events if name == 'SSL_HANDSHAKE_MESSAGE_SENT']
    result['netlog_handshakes_received'] = received; result['netlog_handshakes_sent'] = sent
    netflight = all(t in received for t in (11, 15, 20))
    config_error = 'without a valid trust config' in stderr or 'Invalid MTC Plants-05' in stderr
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
                and 'Invalid MTC Plants-05' not in stderr
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
    def __init__(self, credentials, case, output, run_root):
        self.name = 'mtc-browser-'+uuid.uuid4().hex[:16]
        self.output, self.run_root = output, run_root
        self.credentials, self.case = credentials, case
        self.created = False

    def start(self):
        image = self.credentials['mtc']['image_id']
        command(['docker', 'image', 'inspect', image])  # Never pulls.
        selected = self.credentials['x509' if self.case == 'x509-positive' else 'mtc']
        fixture = Path(selected['fixture'])
        args = ['/opt/mtc/openssl.sh', 's_server', '-accept', '4433', '-tls1_3', '-groups', 'X25519',
                '-ciphersuites', TLS['cipher'], '-num_tickets', '0', '-www', '-state', '-msg',
                '-cert', '/fixtures/'+str(Path(selected['cert']).relative_to(fixture)),
                '-key', '/fixtures/'+str(Path(selected['key']).relative_to(fixture))]
        if self.case != 'x509-positive':
            args += ['-mtc_id', SELECTED]
        elif selected.get('intermediates'):
            args += ['-cert_chain', '/fixtures/'+str(Path(selected['intermediates']).relative_to(fixture))]
        cmd = ['docker', 'run', '-d', '--pull', 'never', '--name', self.name, '--label', LABEL+'='+str(self.run_root),
               '-p', '127.0.0.1:4433:4433', '-v', str(fixture)+':/fixtures:ro', '-v', str(self.output)+':/results',
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


def run_browser(cmd, output, timeout):
    # Only this child process group is signalled; no PID-name matching.
    with (output/'chromium.stdout.log').open('xb') as stdout, (output/'chromium.stderr.log').open('xb') as stderr:
        child = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, start_new_session=True)
        write(output/'browser-process.json', dict(pid=child.pid, process_group=child.pid, command=cmd))
        result = None
        try:
            result = child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            result = 'timeout'
        finally:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)
    return result


def run_case(case, credentials, browser, output, run_root, timeout, positive_control):
    output.mkdir()
    anchor = None
    if case.startswith('mtc-') and case != 'mtc-no-trust':
        anchor = Path(credentials['mtc']['anchor'])
        require(sha(anchor) == credentials['mtc']['anchor_sha256'], 'Positive anchor changed')
        if case in ('mtc-bad-merkle', 'mtc-bad-serial'):
            anchor = output/'derived-anchor.json'
            write(anchor, mutate_anchor(read(credentials['mtc']['anchor']), case))
    url = 'https://'+HOST+':4433/?mtc_case='+case+'&run='+run_root.name
    server = Server(credentials, case, output, run_root)
    try:
        server.start()
        with tempfile.TemporaryDirectory(prefix='mtc-browser-profile-', dir=output) as profile:
            cmd = browser_command(
                browser['executable'],
                Path(profile),
                output,
                anchor,
                url,
                enable_mtc=case.startswith('mtc-'),
            )
            write(output/'chromium-command.json', dict(command=cmd, timeout_seconds=timeout))
            exit_code = run_browser(cmd, output, timeout)
        # Flush server logs after browser exits; preserve files before removing container.
        server.stop(); server.created = False
        return classify(case, output, url, exit_code, positive_control=positive_control)
    finally:
        server.stop()


def blocked_summary(output, reason, browser=None):
    credentials = read(output/'credentials.json') if (output/'credentials.json').is_file() else None
    return dict(overall_pass=False, status='BLOCKED', timestamp=datetime.now(timezone.utc).isoformat(),
                hostname=HOST, tls=TLS, chromium=browser, credentials=credentials, reason=reason,
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'credentials', 'status', 'run', 'cleanup'))
    parser.add_argument('case', nargs='?', choices=(*CASES, 'all'))
    parser.add_argument('--chromium', type=Path)
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--image', default='mt-tls-mtc:local', help='Existing image used only for generation fallback')
    args = parser.parse_args(argv)
    require(5 <= args.timeout <= 300, 'Timeout must be between 5 and 300 seconds')
    require((args.action == 'run') == bool(args.case), 'run requires CASE; other actions take no case')
    if args.action == 'plan':
        print('PRINT ONLY: discover -> strictly validate -> reuse; generate only if no valid candidate.')
        print('Search: artifacts/mtc, artifacts/x509, artifacts/cert-chain-scaling')
        print('Identity: '+HOST+'; ECDSA P-256; MTC N=16 landmark leaf 0')
        print('Cases: '+', '.join(CASES)); print('TLS: '+json.dumps(TLS))
        print('Existing patched Chromium only. Each case: fresh profile, bounded headless run, NetLog/server/DOM evidence.')
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
    try:
        output = new_result(REPO); print('Result directory: '+str(output), flush=True)
        credentials = prepare_credentials(REPO, output, args.image)
        trust = credentials['x509']['root_trust']
        print('MTC '+credentials['mtc']['origin']+': '+credentials['mtc']['fixture'])
        print('X509 '+credentials['x509']['origin']+': '+credentials['x509']['fixture'])
        print('X509 root trust: '+trust['status'])
        if trust['status'] != 'TRUSTED':
            print('Explicit manual action (not executed):\n'+trust['manual_command'])
            write(output/'summary.json', blocked_summary(output, 'X509 root trust not established'))
            return 2
        if args.action == 'credentials': return 0
        browser = browser_executable(args.chromium)
        # Bind only, never probe TLS. Refuse any incumbent server, even another workflow.
        with socket.socket() as sock:
            try: sock.bind(('127.0.0.1', 4433))
            except OSError: raise ValueError('Port 4433 occupied. Stop its owner explicitly; this workflow will not replace it.')
        cases = CASES if args.case == 'all' else (('mtc-positive', args.case) if args.case in CASES[1:4] else (args.case,))
        results = []; positive_pass = False
        summary = dict(overall_pass=False, timestamp=datetime.now(timezone.utc).isoformat(), chromium=browser,
                       hostname=HOST, tls=TLS, credentials=credentials, cases=results)
        for case in cases:
            # Recheck immutable input fingerprints before every invocation.
            for selected, keys in [(credentials['mtc'], [('cert','cert_sha256'),('key','key_sha256'),('trust','trust_sha256'),('anchor','anchor_sha256')]),
                                   (credentials['x509'], [('cert','certificate_sha256'),('key','key_sha256'),('root','root_sha256')])]:
                for pathkey, hashkey in keys: require(sha(selected[pathkey]) == selected[hashkey], 'Credential changed: '+pathkey)
            try:
                result = run_case(case, credentials, browser, output/case, output, args.timeout, positive_pass)
            except Exception as e:
                result = next(r for r in blocked_summary(output, str(e), browser)['cases'] if r['name'] == case)
                result['reason'] = 'Execution incomplete: '+str(e)
                (output/case).mkdir(exist_ok=True)
            write(output/case/'result.json', result); results.append(result)
            if case == 'mtc-positive': positive_pass = result['pass']
            print(case+': '+result['observed_outcome']+' — '+result['reason'], flush=True)
        summary['overall_pass'] = all(r['pass'] for r in results)
        write(output/'summary.json', summary)
        return 0 if summary['overall_pass'] else 1
    except Exception as e:
        if output and not (output/'summary.json').exists():
            write(output/'summary.json', blocked_summary(output, str(e), browser))
        raise
    finally:
        lock.rmdir()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('ERROR: '+str(error), file=sys.stderr)
        sys.exit(1)
