#!/usr/bin/env python3
"""Offline exact-byte TLS 1.3 verification. Never captures, builds or starts TLS.

Restricted to one non-resumed server-auth handshake, AES-256-GCM/SHA384,
no HRR, client authentication, early data or tickets. Unsupported shapes stop.
"""
import argparse
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import tempfile

from validate_mtc import Reader, core, require, save, sha
from semantics import trust_mapping, MTC_EXT, CODEPOINT


class Pairs(list):
    """Preserve repeated jsonraw fields; ordinary dict decoding loses messages."""


def fields(node, name):
    if isinstance(node, Pairs):
        for key, value in node:
            if key == name:
                yield value
            yield from fields(value, name)
    elif isinstance(node, list):
        for value in node:
            yield from fields(value, name)


def raw_field(packet, name):
    values = list(fields(packet, name))
    require(len(values) == 1, 'missing/ambiguous raw field: '+name)
    return bytes.fromhex(values[0][0])


def exact_messages(raw_json):
    packets = json.loads(raw_json, object_pairs_hook=Pairs)
    require(
        isinstance(packets, list) and not isinstance(packets, Pairs),
        'expected jsonraw packet array'
    )

    messages = []

    for number, packet in enumerate(packets, 1):
        values = list(fields(packet, 'tls.handshake_raw'))
        if not values:
            continue

        src = raw_field(packet, 'ip.src_raw')
        dst = raw_field(packet, 'ip.dst_raw')
        sport = raw_field(packet, 'tcp.srcport_raw')
        dport = raw_field(packet, 'tcp.dstport_raw')

        for value in values:
            require(
                isinstance(value, list)
                and len(value) >= 3
                and isinstance(value[0], str),
                'unavailable raw handshake bytes'
            )

            raw = bytes.fromhex(value[0])

            # TShark jsonraw can expose both fragmentary and fully
            # reassembled representations of the same TLS Handshake
            # message. Only complete messages belong in the transcript.
            if len(raw) < 4:
                continue

            declared_length = int.from_bytes(raw[1:4], 'big')

            if len(raw) != declared_length + 4:
                continue

            require(
                value[2] == len(raw),
                'jsonraw byte length mismatch'
            )

            messages.append(
                dict(
                    raw=raw,
                    direction=(src, sport, dst, dport),
                    packet=number
                )
            )

    require(
        [m['raw'][0] for m in messages] == [1, 2, 8, 11, 15, 20, 20],
        'NOT_READY_EXACT_TRANSCRIPT_BYTES_UNAVAILABLE: expected exactly '
        'CH SH EE Certificate CV server-Finished client-Finished; '
        'unsupported or incomplete capture'
    )

    forward = messages[0]['direction']
    reverse = (forward[2], forward[3], forward[0], forward[1])

    require(
        forward != reverse,
        'ambiguous endpoints'
    )

    require(
        [m['direction'] for m in messages]
        == [forward] + [reverse] * 5 + [forward],
        'multiple streams or incorrect handshake directions'
    )

    return messages


def extensions(reader):
    r = Reader(reader.vector())
    out = {}
    while r.pos < len(r.data):
        kind = r.number(2)
        require(kind not in out, 'duplicate extension')
        value = r.vector()
        out[kind] = dict(length=len(value), data=value)
    r.end()
    reader.end()
    return out


def hello(raw, server=False):
    r = Reader(raw[4:])
    require(r.take(2) == b'\x03\x03', 'unexpected legacy version')
    random = r.take(32)
    session = r.vector(1)
    if server:
        require(random.hex() != 'cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c', 'HRR unsupported')
        require(r.number(2) == 0x1302 and r.number(1) == 0, 'requires TLS_AES_256_GCM_SHA384')
    else:
        suites = r.vector()
        require(len(suites) % 2 == 0 and b'\x13\x02' in [suites[i:i+2] for i in range(0,len(suites),2)], 'cipher was not offered')
        require(r.vector(1) == b'\0', 'unexpected compression methods')
    ext = extensions(r)
    require(41 not in ext and 42 not in ext, 'PSK/early data unsupported')
    if server:
        require(ext.get(43, {}).get('data') == b'\x03\x04', 'not TLS 1.3')
    return random, session, ext


def certificate(raw):
    r = Reader(raw[4:])
    require(r.vector(1) == b'', 'client certificate context unsupported')
    entries = Reader(r.vector(3))
    r.end()
    der = entries.vector(3)
    ext = extensions(entries)  # Enforces exactly one CertificateEntry.
    _, tbs = core.certificate_parts(der)
    return der, tbs[6][2], ext, int.from_bytes(tbs[1][1], 'big') >> 48


def signed_input(transcript):
    return b' '*64 + b'TLS 1.3, server CertificateVerify\0' + hashlib.sha384(transcript).digest()


def hkdf_expand_label(secret, label, context, length):
    label = b'tls13 '+label
    require(len(label) <= 255 and len(context) <= 255 and 0 < length <= 255*48, 'HKDF bounds')
    info = length.to_bytes(2, 'big')+bytes([len(label)])+label+bytes([len(context)])+context
    result = b''
    block = b''
    for i in range(1, (length+47)//48+1):
        block = hmac.new(secret, block+info+bytes([i]), hashlib.sha384).digest()
        result += block
    return result[:length]


def finished(secret, transcript):
    require(len(secret) == 48, 'SHA384 handshake secret must have 48 bytes')
    key = hkdf_expand_label(secret, b'finished', b'', 48)
    return hmac.new(key, hashlib.sha384(transcript).digest(), hashlib.sha384).digest()


def keylog_secrets(text, client_random):
    out = {}
    wanted = {'CLIENT_HANDSHAKE_TRAFFIC_SECRET', 'SERVER_HANDSHAKE_TRAFFIC_SECRET'}
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        row = line.split()
        if row[0] not in wanted:
            continue
        require(len(row) == 3, 'malformed handshake keylog entry')
        try:
            random, secret = bytes.fromhex(row[1]), bytes.fromhex(row[2])
        except ValueError:
            raise ValueError('nonhex handshake keylog entry') from None
        if random != client_random:
            continue
        require(len(secret) == 48, 'handshake secret has wrong length')
        require(row[0] not in out or out[row[0]] == secret, 'conflicting handshake secret')
        out[row[0]] = secret
    return out


def certificate_verify(openssl, scheme, spki, message, signature):
    if not openssl:
        return dict(status='NOT_EXECUTED', verified=None, reason='Supply --openssl with the existing provider-enabled executable to verify the signature independently.')
    # Narrow explicit mapping; never infer a digest from a profile label.
    pq = {
        0x0904: '2.16.840.1.101.3.4.3.17',  # ML-DSA-44
        0x0905: '2.16.840.1.101.3.4.3.18',  # ML-DSA-65
        0x0906: '2.16.840.1.101.3.4.3.19',  # ML-DSA-87
        0x0911: '2.16.840.1.101.3.4.3.20',  # SLH-DSA-SHA2-128s
        0x0913: '2.16.840.1.101.3.4.3.22',  # SLH-DSA-SHA2-192s
        0x0915: '2.16.840.1.101.3.4.3.24',  # SLH-DSA-SHA2-256s
    }
    ec = {0x0403: ('1.2.840.10045.3.1.7', 'sha256'), 0x0503: ('1.3.132.0.34', 'sha384'), 0x0603: ('1.3.132.0.35', 'sha512')}
    alg = core.items(core.content(spki, 48))[0][2]
    digest = None
    if scheme in pq:
        require(alg == core.seq(core.oid(pq[scheme])), 'CertificateVerify scheme/SPKI algorithm mismatch')
    elif scheme in ec:
        curve, digest = ec[scheme]
        require(alg == core.seq(core.oid('1.2.840.10045.2.1'), core.oid(curve)), 'CertificateVerify scheme/SPKI curve mismatch')
    else:
        return dict(status='NOT_IMPLEMENTED', verified=None, reason='SignatureScheme not supported by this offline verifier')
    with tempfile.TemporaryDirectory(prefix='mtc-cv-') as tmp:
        tmp = Path(tmp)
        for name, data in [('key.der', spki), ('message.bin', message), ('signature.bin', signature)]:
            (tmp/name).write_bytes(data)
        command = [openssl, 'pkeyutl', '-verify', '-rawin', '-pubin', '-keyform', 'DER', '-inkey', str(tmp/'key.der'), '-in', str(tmp/'message.bin'), '-sigfile', str(tmp/'signature.bin')]
        if digest:
            command += ['-digest', digest]
        try:
            result = subprocess.run(command, capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return dict(status='NOT_EXECUTED', verified=None, reason='Provider-enabled OpenSSL unavailable or timed out')
        if result.returncode == 0:
            return dict(status='PASS', verified=True, method='independent OpenSSL verification of exact TLS signed input and wire SPKI')
        diagnostic = (result.stdout+result.stderr).lower()
        if b'signature verification failure' in diagnostic:
            return dict(status='FAIL', verified=False, reason='Independent CertificateVerify signature mismatch')
        return dict(status='NOT_EXECUTED', verified=None, reason='OpenSSL/provider could not complete signature verification')


def verify(args):
    capture = args.capture
    meta = json.loads((capture/'metadata.json').read_text())
    pcap = (capture/'handshake.pcap').read_bytes()
    keys = (capture/'tls.keys').read_bytes()
    require(sha(pcap) == meta['pcap_sha256'] and sha(keys) == meta['keylog_sha256'], 'capture/keylog hash mismatch')
    report = dict(claim='implemented-subset conformance', scope='independent offline TLS transcript checks; not object conformance',
                  pcap_sha256=sha(pcap), keylog_sha256=sha(keys), metadata_sha256=sha((capture/'metadata.json').read_bytes()),
                  exact_transcript_status='NOT_READY_EXACT_TRANSCRIPT_BYTES_UNAVAILABLE',
                  certificate_verify_independent_verification=dict(status='NOT_EXECUTED', verified=None),
                  server_finished_verified=None, client_finished_verified=None)
    here = Path(__file__).resolve().parent
    report['verifier_source_sha256'] = {name: sha((here/name).read_bytes()) for name in ('verify_tls_transcript.py','semantics.py','validate_mtc.py')}
    report['core_source_sha256'] = sha(Path(core.__file__).read_bytes())
    command = [args.tshark, '-n', '-r', str(capture/'handshake.pcap'), '-d', 'tcp.port==4433,tls',
               '-o', 'tls.keylog_file:'+str((capture/'tls.keys').resolve()),
               '-o', 'tcp.desegment_tcp_streams:TRUE', '-o', 'tls.desegment_ssl_records:TRUE', '-T', 'jsonraw']
    try:
        version = subprocess.run([args.tshark, '--version'], capture_output=True, timeout=5)
        report['tshark_version'] = version.stdout.decode(errors='replace').splitlines()[0] if version.stdout else 'unavailable'
        result = subprocess.run(command, capture_output=True, timeout=30)
        require(result.returncode == 0, 'offline tshark did not expose raw data')
        messages = exact_messages(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        report.update(overall='NOT_EXECUTED', reason=str(error))
        return report
    raw = [m['raw'] for m in messages]
    random, session, ch_ext = hello(raw[0])
    _, server_session, _ = hello(raw[1], server=True)
    require(session == server_session, 'session ID echo mismatch')
    der, spki, cert_ext, log = certificate(raw[3])
    require(sha(der) == meta['fixture_sha256'], 'wire DER does not match metadata fixture digest')
    r = Reader(raw[4][4:]); scheme = r.number(2); signature = r.vector(); r.end()
    require(bool(signature), 'empty CertificateVerify signature')
    secrets = keylog_secrets(keys.decode(), random)
    report.update(exact_transcript_status='AVAILABLE', exact_byte_source='live offline tshark jsonraw; duplicate fields preserved',
                  jsonraw_sha256=sha(result.stdout), mtc_wire_sha256=sha(der), spki_sha256=sha(spki),
                  handshake_messages=[dict(type=m['raw'][0], length=len(m['raw']), sha256=sha(m['raw']), jsonraw_packet_index=m['packet']) for m in messages],
                  certificate_verify_scheme=hex(scheme), certificate_verify_signed_input_sha256=sha(signed_input(b''.join(raw[:4]))))
    report['certificate_verify_independent_verification'] = certificate_verify(args.openssl, scheme, spki, signed_input(b''.join(raw[:4])), signature)
    for role, index in [('server', 5), ('client', 6)]:
        secret = secrets.get(role.upper()+'_HANDSHAKE_TRAFFIC_SECRET')
        if secret is None:
            item = dict(status='NOT_EXECUTED', verified=None, reason='Matching handshake traffic secret unavailable')
        else:
            require(len(raw[index][4:]) == 48, 'Finished verify_data must have SHA384 length')
            ok = hmac.compare_digest(finished(secret, b''.join(raw[:index])), raw[index][4:])
            item = dict(status='PASS' if ok else 'FAIL', verified=ok, hash='SHA384', method='independent HKDF-Expand-Label and HMAC over exact transcript')
        report[role+'_finished_independent_verification'] = item
        report[role+'_finished_verified'] = item['verified']
    from crypto_profiles import crypto_profile
    # Native subset fixes landmark number to one. This is source/config context,
    # not a field extracted from the MTCProof (which carries no landmark number).
    ee = extensions(Reader(raw[2][4:]))
    report['trust_anchors_semantic_mapping'] = trust_mapping(ch_ext.get(MTC_EXT, {}).get('data', b''), ee.get(MTC_EXT, {}).get('data', b''), [cert_ext.get(MTC_EXT)], crypto_profile(meta['profile'])['ca_id'], meta['mode'], log, 1,
                                                     multi_candidate=bool(meta.get('server_pair')))
    layers = [report['certificate_verify_independent_verification'], report['server_finished_independent_verification'], report['client_finished_independent_verification']]
    if report['trust_anchors_semantic_mapping']['status'] == 'FAIL':
        report.update(overall='FAIL', reason='Trust anchor semantic mapping failed')
        return report
    report['overall'] = 'FAIL' if any(x['status'] == 'FAIL' for x in layers) else ('PASS' if all(x['status'] == 'PASS' for x in layers) else 'PARTIAL')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture', type=Path)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--tshark', default='tshark')
    p.add_argument('--openssl', help='Optional existing provider-enabled executable; never starts Docker')
    a = p.parse_args()
    if a.output.exists():
        p.error('Output exists; choose a fresh report outside historical capture directories')
    protected = Path(__file__).resolve().parents[2]/'artifacts/protocol-validation'
    if a.output.resolve().is_relative_to(protected) or a.output.resolve().is_relative_to(a.capture.resolve()):
        p.error('Write the supplemental report outside protocol-validation evidence directories')
    try:
        report = verify(a)
    except Exception as error:
        report = dict(overall='FAIL', claim='implemented-subset conformance', error=str(error))
    save(a.output, report)
    print(report['overall'], a.output)
    return 1 if report['overall'] == 'FAIL' else 0


if __name__ == '__main__':
    raise SystemExit(main())
