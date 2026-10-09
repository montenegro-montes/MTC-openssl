#!/usr/bin/env python3
"""Offline, byte-exact credential component audit for Chromium fixtures."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
sys.path.insert(0, str(REPO / 'src/mtc'))

import core
import browser_validation as bv

PROFILES = ('ecdsa-p256', 'ecdsa-p384', 'mldsa44', 'mldsa65', 'mldsa87')
SCENARIOS = ('x509', 'mtc-landmark', 'mtc-standalone')
FIELDS = (
    'profile', 'scenario', 'fixture', 'credential', 'credential_sha256',
    'artifact_sha256',
    'credential_bytes', 'certificate_count', 'certificate_der_bytes',
    'certificate_der_sizes', 'cryptographic_signature_bytes',
    'public_key_structure_bytes', 'merkle_inclusion_proof_bytes',
    'merkle_proof_hash_count', 'metadata_and_encoding_bytes', 'anchor',
    'anchor_sha256', 'anchor_provisioning_bytes', 'component_status',
    'component_unavailable_reason', 'measurements_csv',
    'tls_server_certificate_bytes', 'tls_certificate_framing_bytes',
    'reconciliation_difference_bytes', 'reconciliation_status',
    'reconciliation_reason')


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _proof_components(encoded):
    """Measure a proof only after the project's canonical parser accepts it."""
    core.proof_extensions(encoded)
    position = 0

    def vector(width):
        nonlocal position
        length = int.from_bytes(encoded[position:position + width], 'big')
        position += width
        value = encoded[position:position + length]
        position += length
        return value

    vector(2)  # Extensions are validated by proof_extensions().
    position += 12  # start and end uint48 values.
    inclusion = vector(2)
    signatures = core.decode_subtree_signature_block(vector(3))
    if position != len(encoded):
        raise ValueError('trailing MTCProof data')
    return inclusion, signatures


def analyze_mtc(profile, scenario, selected):
    mode = scenario.removeprefix('mtc-')
    credential = Path(selected['cert']).resolve()
    raw = core.from_pem(credential.read_bytes())
    outer, _ = core.certificate_parts(raw)
    bit_string = outer[2][1]
    if not bit_string or bit_string[0] != 0:
        raise ValueError('MTC certificate signatureValue is not an octet-aligned BIT STRING')
    proof = bit_string[1:]
    inclusion, signatures = _proof_components(proof)
    signature_bytes = sum(len(signature) for _, signature in signatures)
    cryptographic = len(inclusion) + signature_bytes
    anchor = Path(selected['anchor']).resolve()
    row = dict.fromkeys(FIELDS)
    row.update(
        profile=profile, scenario=scenario,
        fixture=str(Path(selected['fixture']).resolve()), credential=str(credential),
        credential_sha256=sha256(credential),
        artifact_sha256={str(credential): sha256(credential),
                         str(anchor): sha256(anchor)},
        credential_bytes=len(raw), certificate_count=1,
        certificate_der_bytes=len(raw), certificate_der_sizes=[len(raw)],
        cryptographic_signature_bytes=signature_bytes,
        public_key_structure_bytes=0,
        merkle_inclusion_proof_bytes=len(inclusion),
        merkle_proof_hash_count=len(inclusion) // 32,
        metadata_and_encoding_bytes=len(raw) - cryptographic,
        anchor=str(anchor), anchor_sha256=sha256(anchor),
        anchor_provisioning_bytes=anchor.stat().st_size,
        component_status='available', component_unavailable_reason=None,
        reconciliation_status='not-requested',
        reconciliation_reason='No measurements CSV was supplied.')
    # Landmark proofs contain no subtree signatures; standalone proofs do.
    if mode == 'landmark' and signatures:
        raise ValueError('landmark credential unexpectedly contains subtree signatures')
    if mode == 'standalone' and not signatures:
        raise ValueError('standalone credential contains no cryptographic signatures')
    return row


def analyze_x509(profile, fixture):
    fixture = Path(fixture).resolve()
    credential = fixture / 'server.pem'
    pem_values = bv.pem_certificates(credential.read_bytes())
    intermediates = fixture / 'intermediates.pem'
    if intermediates.is_file():
        pem_values.extend(bv.pem_certificates(intermediates.read_bytes()))
    certificates = [x509.load_pem_x509_certificate(value) for value in pem_values]
    ders = [certificate.public_bytes(Encoding.DER) for certificate in certificates]
    signatures = sum(len(certificate.signature) for certificate in certificates)
    public_keys = sum(len(certificate.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
                      for certificate in certificates)
    total = sum(map(len, ders))
    artifacts = {str(credential): sha256(credential),
                 str(fixture / 'root.pem'): sha256(fixture / 'root.pem')}
    if intermediates.is_file():
        artifacts[str(intermediates)] = sha256(intermediates)
    row = dict.fromkeys(FIELDS)
    row.update(
        profile=profile, scenario='x509', fixture=str(fixture),
        credential=str(credential), credential_sha256=sha256(credential),
        artifact_sha256=artifacts,
        credential_bytes=total, certificate_count=len(ders),
        certificate_der_bytes=total, certificate_der_sizes=list(map(len, ders)),
        cryptographic_signature_bytes=signatures,
        public_key_structure_bytes=public_keys,
        merkle_inclusion_proof_bytes=None, merkle_proof_hash_count=None,
        metadata_and_encoding_bytes=total - signatures - public_keys,
        anchor=str((fixture / 'root.pem').resolve()),
        anchor_sha256=sha256(fixture / 'root.pem'),
        anchor_provisioning_bytes=len(bv.certificate_der(
            (fixture / 'root.pem').read_bytes())),
        component_status='available',
        component_unavailable_reason='Merkle proof fields do not apply to X.509.',
        reconciliation_status='not-requested',
        reconciliation_reason='No measurements CSV was supplied.')
    return row


def tls_certificate_message_bytes(row):
    """TLS 1.3 Certificate: header, context, list, and per-entry framing."""
    return row['credential_bytes'] + 4 + 1 + 3 + 5 * row['certificate_count']


def reconcile(rows, measurements):
    measurements = Path(measurements).resolve()
    with measurements.open(newline='') as source:
        observed = list(csv.DictReader(source))
    for row in rows:
        matches = [item for item in observed
                   if item.get('signature_profile') == row['profile']
                   and item.get('case') == row['scenario']
                   and item.get('status') == 'PASS'
                   and (not item.get('credential') or
                        Path(item['credential']).resolve() == Path(row['credential']))
                   and item.get('tls_server_certificate_bytes')]
        row['measurements_csv'] = str(measurements)
        values = {int(item['tls_server_certificate_bytes']) for item in matches}
        if not matches:
            row.update(reconciliation_status='unavailable',
                       reconciliation_reason='No compatible PASS measurement has an analyzable server Certificate.')
            continue
        if len(values) != 1:
            row.update(reconciliation_status='unavailable',
                       reconciliation_reason='Compatible measurements contain inconsistent Certificate sizes.')
            continue
        observed_bytes = values.pop()
        expected = tls_certificate_message_bytes(row)
        framing = expected - row['credential_bytes']
        difference = observed_bytes - expected
        row.update(tls_server_certificate_bytes=observed_bytes,
                   tls_certificate_framing_bytes=framing,
                   reconciliation_difference_bytes=difference,
                   reconciliation_status='reconciled' if difference == 0 else 'difference',
                   reconciliation_reason=(
                       'Exact: credential DER plus TLS 1.3 Certificate framing; excludes CertificateVerify.'
                       if difference == 0 else
                       'Observed Certificate differs from fixture DER plus standard empty-entry TLS framing; '
                       'inspect per-certificate entry extensions and fixture identity.'))


def analyze(repo, depth, measurements=None):
    rows = []
    for profile in PROFILES:
        x509_fixture = bv.precheck_formal_x509_fixture(
            repo, profile, depth, 'chromium-x509-depth-matrix-v1')
        rows.append(analyze_x509(profile, x509_fixture))
        for mode in ('landmark', 'standalone'):
            selected, _ = bv.preselect_mtc_fixture(repo, profile, mode)
            rows.append(analyze_mtc(profile, 'mtc-' + mode, selected))
    if measurements:
        reconcile(rows, measurements)
    return rows


def write_outputs(output, rows, depth):
    output.mkdir(parents=True, exist_ok=False)
    serializable = [{key: (json.dumps(value, sort_keys=True)
                           if key in ('certificate_der_sizes', 'artifact_sha256') else value)
                     for key, value in row.items()} for row in rows]
    with (output / 'credential-components.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader(); writer.writerows(serializable)
    document = dict(schema=1, generated_at=datetime.now(timezone.utc).isoformat(),
                    x509_depth=depth,
                    definitions={
                        'credential_bytes': 'DER bytes sent as CertificateEntry certificate_data.',
                        'cryptographic_signature_bytes': 'Encoded certificate signature values for X.509; MTCProof subtree signature values for MTC.',
                        'public_key_structure_bytes': 'Full DER SubjectPublicKeyInfo values; MTC transmits a hash instead, so this is zero.',
                        'metadata_and_encoding_bytes': 'Credential bytes excluding the mutually exclusive cryptographic signature, public-key and Merkle-proof bytes.',
                        'anchor_provisioning_bytes': 'Out-of-band anchor artifact; never counted as TLS traffic.',
                        'tls_server_certificate_bytes': 'Entire TLS handshake Certificate message, including its four-byte handshake header.'},
                    rows=rows)
    (output / 'credential-components.json').write_text(
        json.dumps(document, indent=2, sort_keys=True) + '\n')
    lines = ['# Chromium credential-size audit', '',
             f'X.509 depth: D={depth}. Rows: {len(rows)}.', '',
             '| Profile | Scenario | Credential bytes | Signatures | SPKI | Merkle proof | Hashes | Other DER/encoding | TLS reconciliation |',
             '|---|---:|---:|---:|---:|---:|---:|---:|---|']
    for row in rows:
        show = lambda value: 'unavailable' if value is None else str(value)
        lines.append('| {profile} | {scenario} | {credential_bytes} | {signature} | {spki} | {proof} | {hashes} | {other} | {status} |'.format(
            profile=row['profile'], scenario=row['scenario'],
            credential_bytes=row['credential_bytes'],
            signature=row['cryptographic_signature_bytes'],
            spki=row['public_key_structure_bytes'],
            proof=show(row['merkle_inclusion_proof_bytes']),
            hashes=show(row['merkle_proof_hash_count']),
            other=row['metadata_and_encoding_bytes'],
            status=row['reconciliation_status']))
    lines += ['', 'Anchor sizes are out-of-band provisioning costs, not TLS bytes.',
              'X.509 signature values above are certificate signatures, never TLS CertificateVerify.',
              'A reconciliation difference is retained rather than forced to zero.']
    (output / 'summary.md').write_text('\n'.join(lines) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--depth', type=int, choices=(2, 3, 4, 5), required=True)
    parser.add_argument('--measurements', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    output = args.output or REPO / 'artifacts/results' / (
        'chromium-credential-size-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
    rows = analyze(REPO, args.depth, args.measurements)
    write_outputs(output, rows, args.depth)
    print(output)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
