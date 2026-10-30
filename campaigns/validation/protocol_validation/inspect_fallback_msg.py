"""Check the no-match server flight recorded by s_server -msg."""
import argparse
from pathlib import Path
import ssl

from inspect_sclient_msg import (client_hello_ids, extension,
                                 first_certificate_entry, messages, one)
from semantics import MTC_EXT, decode_list


def inspect(transcript, expected_der):
    if transcript.count(
            'MTC server certificate selected: id=32473.101 reason=fallback-standalone') != 1:
        raise ValueError('Missing or ambiguous fallback selection log')
    found = messages(transcript)
    requested = client_hello_ids(one(found, '<<<', 'ClientHello'))
    if requested != [(32473, 102)]:
        raise ValueError(f'Unexpected mismatched ClientHello IDs: {requested}')
    available = decode_list(
        extension(one(found, '>>>', 'EncryptedExtensions'), MTC_EXT),
        available=True)
    if available != [(32473, 101, 1, 1, 1), (32473, 101)]:
        raise ValueError(f'Unexpected EE IDs: {available}')
    der, cert_extensions = first_certificate_entry(
        one(found, '>>>', 'Certificate'))
    if der != expected_der:
        raise ValueError('Fallback certificate differs from Standalone fixture')
    if extension(cert_extensions, MTC_EXT, required=False) is not None:
        raise ValueError('No-match fallback emitted a CertificateEntry marker')
    return requested, available


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('transcript', type=Path)
    parser.add_argument('--expected-cert', type=Path, required=True)
    args = parser.parse_args()
    der = ssl.PEM_cert_to_DER_cert(args.expected_cert.read_text())
    requested, available = inspect(
        args.transcript.read_text(errors='replace'), der)
    print('CH requested IDs:', ', '.join('.'.join(map(str, x)) for x in requested))
    print('EE available IDs:', ', '.join('.'.join(map(str, x)) for x in available))
    print('PASS: fallback Standalone; no first CertificateEntry marker')
