"""Inspect one OpenSSL s_client -msg transcript without a packet capture."""
import argparse
from pathlib import Path
import re
import ssl

from semantics import MTC_EXT, decode_list


def messages(transcript):
    found = {}
    direction = name = None
    hex_lines = []

    def finish():
        if not hex_lines or direction is None:
            return
        raw = bytes.fromhex(' '.join(hex_lines))
        if len(raw) < 4 or len(raw) != 4 + int.from_bytes(raw[1:4], 'big'):
            raise ValueError(f'Invalid {name} handshake length')
        found.setdefault((direction, name), []).append(raw[4:])

    for line in transcript.splitlines():
        header = re.match(
            r'^(<<<|>>>) TLS 1\.3, Handshake \[length [0-9a-fA-F]+\], ([A-Za-z]+)',
            line)
        if header:
            finish()
            direction, name = header.groups()
            hex_lines = []
        elif line.startswith(('<<< ', '>>> ')):
            finish()
            direction = name = None
            hex_lines = []
        elif direction and re.fullmatch(r'\s+(?:[0-9a-fA-F]{2}\s*)+', line):
            hex_lines.append(line.strip())
    finish()
    return found


def extension(data, ext_type, required=True):
    if len(data) < 2 or int.from_bytes(data[:2], 'big') != len(data)-2:
        raise ValueError('Invalid extension vector')
    pos = 2
    matches = []
    while pos < len(data):
        if pos + 4 > len(data):
            raise ValueError('Truncated extension header')
        kind = int.from_bytes(data[pos:pos+2], 'big')
        size = int.from_bytes(data[pos+2:pos+4], 'big')
        pos += 4
        if pos + size > len(data):
            raise ValueError('Truncated extension')
        if kind == ext_type:
            matches.append(data[pos:pos+size])
        pos += size
    if not matches and not required:
        return None
    if len(matches) != 1:
        raise ValueError(f'Expected one extension 0x{ext_type:04x}')
    return matches[0]


def one(found, direction, name):
    items = found.get((direction, name), [])
    if len(items) != 1:
        raise ValueError(f'Expected one {direction} {name}')
    return items[0]


def client_hello_ids(ch):
    if len(ch) < 35:
        raise ValueError('Truncated ClientHello')
    pos = 34
    session_length = ch[pos]
    pos += 1 + session_length
    if pos + 2 > len(ch):
        raise ValueError('Truncated ClientHello session')
    cipher_length = int.from_bytes(ch[pos:pos+2], 'big')
    pos += 2 + cipher_length
    if pos >= len(ch):
        raise ValueError('Truncated ClientHello ciphers')
    compression_length = ch[pos]
    pos += 1 + compression_length
    return decode_list(extension(ch[pos:], MTC_EXT))


def first_certificate_entry(cert):
    if len(cert) < 4:
        raise ValueError('Truncated Certificate')
    context_length = cert[0]
    pos = 1 + context_length
    if pos + 3 > len(cert):
        raise ValueError('Truncated Certificate context')
    list_length = int.from_bytes(cert[pos:pos+3], 'big')
    pos += 3
    if list_length != len(cert)-pos or pos + 3 > len(cert):
        raise ValueError('Invalid Certificate list')
    der_length = int.from_bytes(cert[pos:pos+3], 'big')
    pos += 3
    if pos + der_length + 2 > len(cert):
        raise ValueError('Truncated first CertificateEntry')
    der = cert[pos:pos+der_length]
    pos += der_length
    extensions_length = int.from_bytes(cert[pos:pos+2], 'big')
    pos += 2
    if pos + extensions_length > len(cert):
        raise ValueError('Truncated first CertificateEntry extensions')
    return der, cert[pos-2:pos+extensions_length]


def inspect(transcript, expected_mode, expected_der):
    found = messages(transcript)
    requested = client_hello_ids(one(found, '>>>', 'ClientHello'))
    expected_request = ([(32473, 101, 2, 1, 1)] if expected_mode == 'landmark'
                        else [(32473, 101)])
    if requested != expected_request:
        raise ValueError(f'Unexpected ClientHello IDs: {requested}')

    ee = one(found, '<<<', 'EncryptedExtensions')
    available = decode_list(extension(ee, MTC_EXT), available=True)
    expected_available = [(32473, 101, 1, 1, 1), (32473, 101)]
    if available != expected_available:
        raise ValueError(f'Unexpected EE IDs: {available}')

    der, cert_extensions = first_certificate_entry(
        one(found, '<<<', 'Certificate'))
    if der != expected_der:
        raise ValueError('Sent certificate differs from selected fixture')
    marker = extension(cert_extensions, MTC_EXT)
    if marker:
        raise ValueError('First CertificateEntry marker is not empty')
    return requested, available


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('transcript', type=Path)
    parser.add_argument('--mode', choices=('landmark', 'standalone'), required=True)
    parser.add_argument('--expected-cert', type=Path, required=True)
    args = parser.parse_args()
    pem = args.expected_cert.read_text()
    der = ssl.PEM_cert_to_DER_cert(pem)
    requested, available = inspect(
        args.transcript.read_text(errors='replace'), args.mode, der)
    print('CH requested IDs:', ', '.join('.'.join(map(str, x)) for x in requested))
    print('EE available IDs:', ', '.join('.'.join(map(str, x)) for x in available))
    print('PASS: sent certificate and empty first CertificateEntry marker')
