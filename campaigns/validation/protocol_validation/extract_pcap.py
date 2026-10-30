#!/usr/bin/env python3
"""Decode one TLS capture using tshark PDML structured fields.

The extractor never uses fixtures as payload. The exact MTC DER is taken
from the decrypted/reassembled TLS Certificate message exposed by tshark.

Wireshark/tshark 4.0.x may leave the container field ``tls.handshake`` with
an empty ``value`` attribute even though all decoded child fields are
available. Therefore this extractor validates the structured PDML fields
instead of requiring raw bytes on the parent handshake node.
"""

import argparse
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

from validate_mtc import Reader, require, sha, save
import core
from semantics import trust_mapping, MTC_EXT, CODEPOINT


def xml_fields(node, name):
    return node.findall(".//field[@name='%s']" % name)


def one_xml_field(node, name):
    values = xml_fields(node, name)
    require(len(values) == 1, 'expected exactly one PDML field ' + name)
    return values[0]


def field_int(node, name):
    field = one_xml_field(node, name)
    show = field.get('show')
    if show:
        try:
            return int(show, 0)
        except ValueError:
            pass
    value = field.get('value')
    require(value is not None and value != '', 'missing numeric PDML field ' + name)
    return int(value, 16)


def field_bytes(node, name, allow_empty=False):
    field = one_xml_field(node, name)
    value = field.get('value')
    if value is None or value == '':
        require(allow_empty, 'missing/empty byte PDML field ' + name)
        return b''
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ValueError('non-hex PDML field ' + name) from error


def extension_map(handshake):
    """Return TLS extension metadata scoped to one handshake node."""
    out = {}
    for wrapper in handshake.iter('field'):
        children = list(wrapper)
        kind_field = next(
            (child for child in children
             if child.get('name') == 'tls.handshake.extension.type'),
            None,
        )
        if kind_field is None:
            continue

        show = kind_field.get('show')
        value = kind_field.get('value')
        if show:
            try:
                kind = int(show, 0)
            except ValueError:
                require(bool(value), 'TLS extension type missing from PDML')
                kind = int(value, 16)
        else:
            require(bool(value), 'TLS extension type missing from PDML')
            kind = int(value, 16)

        require(kind not in out, 'duplicate TLS extension ' + hex(kind))

        length_field = next(
            (child for child in children
             if child.get('name') == 'tls.handshake.extension.len'),
            None,
        )
        require(length_field is not None, 'TLS extension length missing')

        length_show = length_field.get('show')
        if length_show:
            length = int(length_show, 0)
        else:
            length_value = length_field.get('value')
            require(bool(length_value), 'TLS extension length missing')
            length = int(length_value, 16)

        data_field = next(
            (child for child in children
             if child.get('name') == 'tls.handshake.extension.data'),
            None,
        )

        data = None
        if data_field is not None:
            data_value = data_field.get('value')
            if data_value:
                data = bytes.fromhex(data_value)
            elif length == 0:
                data = b''

        out[kind] = dict(length=length, data=data)

    return out


def signal(value, expected, alternative=None, preferred=None):
    require(value is not None, 'missing trust-anchor extension payload')
    r = Reader(value)
    ids = Reader(r.vector())
    r.end()
    values = []
    while ids.pos < len(ids.data):
        values.append(ids.vector(1))
    ids.end()
    matches = (values == preferred if preferred is not None else
               values == [expected] or (alternative is not None and values == [alternative]))
    require(matches, 'wrong/ambiguous trust anchor selection')


def extract(a):
    meta = json.loads((a.capture / 'metadata.json').read_text())
    require(
        meta['status'] == 'CAPTURED_NOT_PROTOCOL_VALIDATED',
        'capture did not complete',
    )

    for name, digest in meta['evidence_sha256'].items():
        require(
            sha((a.capture / name).read_bytes()) == digest,
            'endpoint evidence hash mismatch',
        )

    for file, key in [('handshake.pcap', 'pcap_sha256'), ('tls.keys', 'keylog_sha256')]:
        require(
            sha((a.capture / file).read_bytes()) == meta[key],
            'capture/keylog integrity mismatch',
        )

    cmd = [
        a.tshark,
        '-n',
        '-r', str(a.capture / 'handshake.pcap'),
        '-d', 'tcp.port==4433,tls',
        '-o', 'tls.keylog_file:' + str((a.capture / 'tls.keys').resolve()),
        '-o', 'tcp.desegment_tcp_streams:TRUE',
        '-o', 'tls.desegment_ssl_records:TRUE',
        '-o', 'tls.desegment_ssl_application_data:TRUE',
        '-T', 'pdml',
    ]

    result = subprocess.run(cmd, capture_output=True)
    (a.output / 'tshark.stderr').write_bytes(result.stderr)
    require(result.returncode == 0, 'tshark failed; inspect stderr')
    (a.output / 'traffic.pdml').write_bytes(result.stdout)

    root = ET.fromstring(result.stdout)
    messages = []
    records = []
    streams = set()
    packets = []
    sequence = 0

    for packet in root.findall('packet'):
        number_field = packet.find(".//field[@name='frame.number']")
        require(number_field is not None, 'packet missing frame.number')
        number = number_field.get('show')

        stream = packet.find(".//field[@name='tcp.stream']")
        if stream is not None:
            streams.add(stream.get('show'))
            packets.append(number)

        for record in packet.findall(".//field[@name='tls.record']"):
            sequence += 1
            length = record.find(".//field[@name='tls.record.length']")
            records.append(dict(
                record_number=sequence,
                packet=number,
                length=length.get('show') if length is not None else None,
            ))

        for node in packet.findall(".//field[@name='tls.handshake']"):
            kind = node.find("./field[@name='tls.handshake.type']")
            length = node.find("./field[@name='tls.handshake.length']")
            if kind is None:
                continue
            require(length is not None, 'handshake message missing length in PDML')

            typ = int(kind.get('show'))
            body_length = int(length.get('show'))
            row = dict(
                packet=number,
                tcp_stream=stream.get('show') if stream is not None else None,
                type=typ,
                length=body_length,
                total_bytes=body_length + 4,
                record_numbers_in_packet=[
                    record['record_number']
                    for record in records
                    if record['packet'] == number
                ],
            )
            messages.append((row, node))

    require(bool(records), 'UNRESOLVED: tshark did not expose TLS record fields')
    require(len(streams) == 1, 'expected exactly one TCP stream')

    def one(typ):
        values = [(row, node) for row, node in messages if row['type'] == typ]
        require(len(values) == 1, 'expected one handshake type ' + str(typ))
        return values[0]

    # ClientHello
    ch_row, ch = one(1)
    ch_ext = extension_map(ch)

    p = __import__('crypto_profiles').crypto_profile(meta['profile'])
    anchor = core.relid(
        p['ca_id'] + ('.1.1.1' if meta['mode'] == 'landmark' else '')
    )

    require(MTC_EXT in ch_ext, f'missing provisional {CODEPOINT} ClientHello signal')
    signal(ch_ext[MTC_EXT]['data'], anchor,
           core.relid(p['ca_id'] + '.2.1.1') if meta['mode'] == 'landmark' else None)
    require(41 not in ch_ext and 42 not in ch_ext, 'resumption or early data offered')

    # ServerHello
    sh_row, sh = one(2)
    sh_ext = extension_map(sh)
    cipher = field_int(sh, 'tls.handshake.ciphersuite')
    version = field_bytes(sh, 'tls.handshake.extensions.supported_version')
    require(cipher == 0x1302 and version == b'\x03\x04', 'wrong cipher/TLS version')
    require(41 not in sh_ext, 'resumption selected')

    group = field_int(sh, 'tls.handshake.extensions_key_share_group')
    key_exchange = field_bytes(sh, 'tls.handshake.extensions_key_share_key_exchange')
    require(group == 29, 'not X25519')
    require(len(key_exchange) == 32, 'wrong X25519 key length')

    # EncryptedExtensions
    ee_row, ee = one(8)
    ee_ext = extension_map(ee)
    require(MTC_EXT in ee_ext, f'missing provisional {CODEPOINT} EncryptedExtensions signal')
    pair_available = ([core.relid(meta['server_pair_landmark_id']),core.relid(p['ca_id'])]
                      if meta.get('server_pair') else None)
    signal(ee_ext[MTC_EXT]['data'], anchor, preferred=pair_available)

    # Certificate
    cert_row, cert_node = one(11)
    request_context_length = field_int(
        cert_node,
        'tls.handshake.certificate_request_context_length',
    )
    require(request_context_length == 0, 'unexpected certificate request context')

    cert_fields = xml_fields(cert_node, 'tls.handshake.certificate')
    cert_length_fields = xml_fields(cert_node, 'tls.handshake.certificate_length')
    require(
        len(cert_fields) == 1 and len(cert_length_fields) == 1,
        'expected one MTC leaf CertificateEntry',
    )

    cert_value = cert_fields[0].get('value')
    require(bool(cert_value), 'UNRESOLVED: tshark did not expose certificate DER bytes')
    der = bytes.fromhex(cert_value)

    cert_length_show = cert_length_fields[0].get('show')
    require(
        cert_length_show is not None and int(cert_length_show) == len(der),
        'certificate DER length mismatch',
    )

    cert_ext = extension_map(cert_node)
    require(MTC_EXT in cert_ext, 'missing experimental CertificateEntry confirmation')
    require(
        cert_ext[MTC_EXT]['length'] == 0 and cert_ext[MTC_EXT]['data'] == b'',
        'missing/nonempty experimental CertificateEntry confirmation',
    )

    with (a.output / 'mtc-wire.bin').open('xb') as f:
        f.write(der)

    # CertificateVerify
    cv_row, cv = one(15)
    scheme = field_int(cv, 'tls.handshake.sig_hash_alg')
    signature = field_bytes(cv, 'tls.handshake.client_cert_vrfy.sig')
    signature_length = field_int(cv, 'tls.handshake.client_cert_vrfy.sig_len')
    require(bool(signature), 'empty CertificateVerify')
    require(len(signature) == signature_length, 'CertificateVerify signature length mismatch')

    # Handshake order and exclusions
    types = [row['type'] for row, _ in messages]
    require(
        types.count(20) == 2 and 13 not in types and 4 not in types,
        'expected two Finished, no client auth or tickets',
    )
    require(
        types.index(1) < types.index(2) < types.index(8) < types.index(11)
        < types.index(15) < types.index(20),
        'wrong handshake order',
    )

    finished = [row for row, _ in messages if row['type'] == 20]
    require(all(row['length'] > 0 for row in finished), 'empty Finished message')

    # Exact wire object and endpoint evidence
    outer, tbs = core.certificate_parts(der)
    payload_length = len(outer[2][1]) - 1

    receiver = a.capture / 'receiver-reserialized.der'
    receiver_match = None
    if receiver.exists():
        require(
            sha(receiver.read_bytes()) == meta['receiver_reserialized_sha256'],
            'receiver evidence hash mismatch',
        )
        receiver_match = receiver.read_bytes() == der
        require(receiver_match, 'receiver reserialization differs from wire')

    client = json.loads((a.capture / 'client-result.json').read_text())
    server = json.loads((a.capture / 'server-result.json').read_text())
    require(
        client['passed'] is True and server['returncode'] == 0,
        'endpoint acceptance missing',
    )

    sender_match = sha(der) == meta['fixture_sha256']
    require(sender_match, 'sender/wire mismatch')
    if a.sender:
        require(a.sender.read_bytes() == der, 'supplied sender fixture differs from capture')
    server_selection = None
    if meta.get('server_pair'):
        server_log = a.capture / 'server.log'
        require(sha(server_log.read_bytes()) == meta['evidence_sha256']['server.log'],
                'server selection log changed')
        selected_id = (meta['server_pair_landmark_id'] if meta['mode'] == 'landmark'
                       else p['ca_id'])
        reason = 'requested-'+meta['mode']
        selection_line = f'MTC server certificate selected: id={selected_id} reason={reason}'
        require(server_log.read_text(errors='replace').count(selection_line) == 1,
                'server credential selection reason missing or ambiguous')
        server_selection = dict(id=selected_id, reason=reason,
                                evidence='server.log and sender/wire certificate match')
    mapping = trust_mapping(
        ch_ext[MTC_EXT]['data'], ee_ext[MTC_EXT]['data'], [cert_ext[MTC_EXT]],
        p['ca_id'], meta['mode'], int.from_bytes(tbs[1][1], 'big') >> 48,
        int(meta['server_pair_landmark_id'].rsplit('.',1)[1]) if meta.get('server_pair') else 1,
        multi_candidate=bool(meta.get('server_pair')))
    if meta.get('server_pair'):
        require(mapping['status'] == 'PASS_EXPERIMENTAL_CODEPOINT',
                'server-pair trust-anchor semantics failed: '+mapping['reason'])

    return dict(
        overall='PASS',
        scope='captured TLS framing and endpoint acceptance; run offline object validation next',
        draft=core.DRAFT,
        claim='implemented-subset conformance',
        metadata=meta,
        tcp_stream=next(iter(streams)),
        records=records,
        handshake_messages=[row for row, _ in messages],
        certificate_message_length=cert_row['length'],
        certificate_verify_length=cv_row['length'],
        certificate_verify_scheme=scheme,
        mtc_payload_length=payload_length,
        certificate_der_length=len(der),
        mtc_completion_packets=[cert_row['packet']],
        tcp_stream_packets=packets,
        fragment_packet_limitation=(
            'completion packet is where tshark exposes reassembled/decrypted structured fields; '
            'all stream packet IDs retained in PDML'
        ),
        pdml_extraction_mode=(
            'structured tshark fields; tls.handshake parent value is not required'
        ),
        mtc_wire_sha256=sha(der),
        pcap_sha256=meta['pcap_sha256'],
        fixture_sha256=meta['fixture_sha256'],
        sender_wire_match=sender_match,
        server_selection=server_selection,
        receiver_reserialized_wire_match=receiver_match,
        receiver_raw_sha256=None,
        receiver_limitation=(
            '-showcerts reserializes the received X509; original raw input not retained'
        ),
        trust_anchors_semantic_mapping=mapping,
        endpoint_authentication=True,
        tls_version='TLSv1.3',
        cipher='TLS_AES_256_GCM_SHA384',
        key_exchange='X25519',
        unresolved=[
            f'Provisional {CODEPOINT} supports initial single-log group and exact individual-ID selection; general groups, automatic retry and complete trust_anchors behavior remain outside the implementation',
            'CertificateVerify/Finished cryptographic acceptance is endpoint evidence, not independent transcript verification',
        ],
    )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('capture', type=Path)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--sender', type=Path)
    p.add_argument('--tshark', default='tshark')
    a = p.parse_args()

    if a.output.exists():
        p.error('Extraction output exists; choose a new path')

    a.output.mkdir(parents=True)

    try:
        report = extract(a)
    except Exception as error:
        report = dict(
            overall='UNRESOLVED' if 'UNRESOLVED' in str(error) else 'FAIL',
            error=str(error),
        )

    save(a.output / 'extraction.json', report)
    print(report['overall'], a.output)
    raise SystemExit(0 if report['overall'] == 'PASS' else 1)


if __name__ == '__main__':
    main()
