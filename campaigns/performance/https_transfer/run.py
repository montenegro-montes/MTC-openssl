#!/usr/bin/env python3
"""Opt-in HTTPS transfer experiment using existing MTC OpenSSL and fixtures."""
import argparse
import csv
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time

OPENSSL = '/opt/mtc/openssl.sh'
COMMON = ['-tls1_3', '-groups', 'X25519', '-ciphersuites', 'TLS_AES_256_GCM_SHA384']
PROFILES = ('ecdsa-p256', 'mldsa65')
MODES = ('x509', 'mtc-landmark', 'mtc-standalone')
OBJECTS = {'1k.bin': 1024, '10k.bin': 10240, '100k.bin': 102400, '1m.bin': 1048576}
FIELDS = ['profile', 'auth_mode', 'object_size_bytes', 'run', 'is_warmup',
          'handshake_ok', 'http_status', 'ttfb_ms', 'total_ms',
          'response_body_bytes', 'body_ok', 'returncode', 'error']


def payload(size):
    return (bytes(range(256)) * ((size + 255) // 256))[:size]


def commands(root, profile, mode):
    population = root / 'population' / profile
    fixture = root / 'batch16/mtc' / profile
    manifest = json.loads((fixture / 'manifest.json').read_text())
    if manifest['tree_size'] != 16 or manifest.get('profile', manifest.get('crypto_family')) != profile:
        raise ValueError(f'Wrong N/profile: {fixture}')
    server = [OPENSSL, 's_server', '-accept', '127.0.0.1:4433',
              '-key', str(population / '0.key'), '-num_tickets', '0', '-WWW', *COMMON]
    client = [OPENSSL, 's_client', '-connect', '127.0.0.1:4433',
              '-servername', 'server', '-verify_hostname', 'server',
              '-verify_return_error', '-no_ticket', '-ign_eof', *COMMON]
    if mode == 'x509':
        server += ['-cert', str(population / '0.pem')]
        client += ['-CAfile', str(population / 'ca.pem')]
    else:
        kind = mode.removeprefix('mtc-')
        server += ['-cert', str(fixture / f'{kind}-0000.pem'), '-mtc_id',
                   manifest['ca_id'] + ('.1.1.1' if kind == 'landmark' else '')]
        client += ['-mtc_trust', str(fixture / ('trust.bin' if kind == 'landmark' else 'authority.bin'))]
        if kind == 'landmark':
            server += ['-mtc_landmark']
            client += ['-mtc_landmark']
    for command in (server, client):
        for index, option in enumerate(command):
            if option in ('-key', '-cert', '-CAfile', '-mtc_trust'):
                if not Path(command[index + 1]).is_file():
                    raise FileNotFoundError(command[index + 1])
    return server, client


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def http_response(response, size):
    """Separate the known s_client stdout close diagnostic, never truncate blindly."""
    start = response.find(b'HTTP/1.')
    http = bytes(response[start:]) if start >= 0 else b''
    header, separator, body = http.partition(b'\r\n\r\n')
    trailer = b''
    # Non-quiet s_client shares stdout with application data. Accept only its
    # exact terminal diagnostic at the expected boundary; compare all payload
    # bytes independently below. Unknown/excess data remains a validation error.
    if separator and len(body) == size + len(b'closed\n') and body[size:] == b'closed\n':
        body, trailer = body[:size], body[size:]
    return header, separator, body, trailer


def sample(command, name, size, log_path):
    """Gate GET on verified TLS diagnostics; drain both pipes without blocking."""
    row = dict(handshake_ok=False, http_status='', ttfb_ms='', total_ms='',
               response_body_bytes=0, body_ok=False, returncode='', error='')
    start = time.perf_counter()
    response = bytearray()
    diagnostics = bytearray()
    sent = False
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, bufsize=0)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 'response')
            selector.register(process.stderr, selectors.EVENT_READ, 'diagnostics')
            while selector.get_map():
                if time.perf_counter() - start > 90:
                    raise TimeoutError('90s sample timeout (including handshake diagnostic gate)')
                for key, _ in selector.select(timeout=0.1):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    if key.data == 'diagnostics':
                        diagnostics.extend(chunk)
                    else:
                        response.extend(chunk)
                        if sent and row['ttfb_ms'] == '' and b'HTTP/1.' in response:
                            row['ttfb_ms'] = (time.perf_counter() - start) * 1000
                    if not sent:
                        text = (diagnostics + response).decode(errors='replace')
                        verified = ('Verify return code: 0 (ok)' in text if '-mtc_trust' not in command
                                    else 'MTC verification: OK' in text)
                        ready = (verified and 'Verify return code: 0 (ok)' in text
                                 and 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384' in text
                                 and re.search(r'(?:Peer|Server) Temp Key: X25519', text))
                        if ready:
                            row['handshake_ok'] = True
                            diagnostics.extend(response)
                            response.clear()
                            process.stdin.write(f'GET /{name} HTTP/1.0\r\nHost: server\r\nConnection: close\r\n\r\n'.encode('ascii'))
                            process.stdin.flush()
                            sent = True
            row['total_ms'] = (time.perf_counter() - start) * 1000
            row['returncode'] = process.wait(timeout=3)
        header, separator, body, trailer = http_response(response, size)
        if trailer:
            diagnostics.extend(b'\nS_CLIENT_STDOUT_TRAILER: ' + repr(trailer).encode('ascii') + b'\n')
        match = re.match(rb'HTTP/1\.[01] ([0-9]{3})(?: |\r|$)', header)
        if match:
            row['http_status'] = int(match[1])
        row['response_body_bytes'] = len(body) if separator else 0
        row['body_ok'] = bool(separator) and body == payload(size)
        if not (row['handshake_ok'] and row['http_status'] == 200
                and row['body_ok'] and row['returncode'] == 0):
            row['error'] = 'TLS, HTTP, payload or process validation failed'
    except (OSError, TimeoutError, subprocess.TimeoutExpired) as error:
        row['error'] = str(error)
        row['total_ms'] = (time.perf_counter() - start) * 1000
        _, separator, body, _ = http_response(response, size)
        row['response_body_bytes'] = len(body) if separator else 0
    finally:
        stop(process)
        row['returncode'] = process.returncode
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
        log_path.write_bytes(diagnostics)
        if row['error']:
            log_path.with_suffix('.stdout.bin').write_bytes(response)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mtc-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--execute', action='store_true')
    args = parser.parse_args()
    if not args.execute:
        print('PLAN ONLY: 2 profiles x 3 modes x 4 sizes x (5 warmups + 30 measurements) = 840 connections')
        return
    root, output = args.mtc_root.resolve(), args.output.resolve()
    matrix = {(profile, mode): commands(root, profile, mode)
              for profile in PROFILES for mode in MODES}
    if not Path(OPENSSL).is_file():
        parser.error(f'Missing existing MTC OpenSSL: {OPENSSL}')
    output.mkdir(parents=True, exist_ok=False)
    objects = output / 'objects'
    objects.mkdir()
    logs = output / 'logs'
    logs.mkdir()
    for name, size in OBJECTS.items():
        (objects / name).write_bytes(payload(size))
    (output / 'commands.json').write_text(json.dumps(
        {f'{p}/{m}': {'server': s, 'client': c} for (p, m), (s, c) in matrix.items()}, indent=2) + '\n')
    failed = 0
    with (output / 'samples.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        stream.flush()
        for profile in PROFILES:
            for name, size in OBJECTS.items():
                for warmup, count in ((True, 5), (False, 30)):
                    for run in range(1, count + 1):
                        offset = (run - 1) % len(MODES)
                        for mode in MODES[offset:] + MODES[:offset]:
                            server_command, client_command = matrix[profile, mode]
                            prefix = f'{profile}-{mode}-{name}-{warmup}-{run}'
                            server_log = logs / f'{prefix}-server.log'
                            # All unchanged commands bind the same port. Stop each
                            # server before switching mode; startup is outside sample().
                            with server_log.open('xb') as log:
                                server = subprocess.Popen(
                                    server_command, cwd=objects, stdout=log,
                                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
                                try:
                                    deadline = time.monotonic() + 25
                                    while b'ACCEPT' not in server_log.read_bytes():
                                        if server.poll() is not None or time.monotonic() > deadline:
                                            raise RuntimeError(f'Server readiness failed: {server_log}')
                                        time.sleep(0.1)
                                    row = sample(client_command, name, size,
                                                 logs / f'{prefix}.log')
                                    writer.writerow(dict(profile=profile, auth_mode=mode,
                                                         object_size_bytes=size, run=run,
                                                         is_warmup=warmup, **row))
                                    stream.flush()
                                    failed += bool(row['error'])
                                    if server.poll() is not None:
                                        raise RuntimeError(f'Server exited: {server_log}')
                                finally:
                                    stop(server)
                print(f'{profile} {name}: finished', flush=True)
    print(f'{output}/samples.csv; failed samples: {failed}')
    if failed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
