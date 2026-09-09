"""Integration tests against real s_client/s_server; temporary fixtures only."""
from contextlib import contextmanager
from pathlib import Path
import hashlib
import socket
import struct
import subprocess
import tempfile
import time

BASE = '/opt/openssl/bin/openssl'
MT = '/opt/openssl-mt/bin/openssl'
BUNDLE = '/opt/mt/bin/mt_bundle'
CERTS = Path('/work/certs')
passed = 0


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=15, **kwargs)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


@contextmanager
def server(certdir, extra=(), binary=MT, raw_payload=None):
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
    with tempfile.TemporaryFile(mode='w+') as log:
        command = [binary, 's_server', '-accept', f'127.0.0.1:{port}',
                                 '-tls1_3', '-cert', str(certdir / 'server.pem'),
                                 '-key', str(certdir / 'server.key'), '-www', '-quiet',
                                 '-groups', 'X25519', '-num_tickets', '0', *map(str, extra)]
        if raw_payload is not None:
            command = ['/opt/mt/bin/mt_test_server', str(port), str(certdir / 'server.pem'),
                       str(certdir / 'server.key'), str(raw_payload)]
        proc = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    log.seek(0)
                    raise AssertionError('Server startup failed: ' + log.read())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise AssertionError('Server readiness timeout')
            yield port
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def client(port, certdir, root=None, extra=(), binary=MT):
    args = [binary, 's_client', '-connect', f'127.0.0.1:{port}', '-servername', 'server',
            '-verify_hostname', 'server', '-CAfile', str(certdir / 'ca.pem'),
            '-verify_return_error', '-tls1_3', '-groups', 'X25519', '-ign_eof', '-no_ticket']
    if root is not None:
        args += ['-merkle_root', str(root)]
    return run([*args, *extra], input='GET / HTTP/1.0\r\n\r\n')


def check(name, result, ok, marker=None):
    global passed
    log = result.stdout + result.stderr
    require((result.returncode == 0) == ok, f'{name}: unexpected exit {result.returncode}\n{log}')
    if ok:
        require('Verify return code: 0 (ok)' in log and 'HTTP/1.0 200' in log, name + ': no verified HTTP response\n' + log)
    else:
        require('HTTP/1.0 200' not in log, name + ': application data accepted')
    if marker:
        require(marker in log, name + ': missing expected diagnostic ' + marker + '\n' + log)
    passed += 1
    print('PASS', name, flush=True)


with tempfile.TemporaryDirectory(prefix='mt-tls-tests-') as directory:
    temp = Path(directory)
    for scenario in ('classic', 'pq'):
        certdir = CERTS / scenario
        bundle = temp / scenario
        result = run([BUNDLE, bundle, certdir / 'server.pem', certdir / 'ca.pem'])
        require(result.returncode == 0, 'Bundle generation: ' + result.stderr)
        root, proof = bundle / 'root.bin', bundle / 'proof-0000.bin'
        wrong_root = temp / f'{scenario}-wrong-root.bin'
        b = bytearray(root.read_bytes()); b[-1] ^= 1; wrong_root.write_bytes(b)
        wrong_proof = temp / f'{scenario}-wrong-proof.bin'
        b = bytearray(proof.read_bytes()); b[-1] ^= 1; wrong_proof.write_bytes(b)
        with server(certdir, ['-merkle_proof', proof]) as port:
            for i in range(2):
                check(f'{scenario} valid Merkle {i}', client(port, certdir, root), True, 'Merkle verification: OK')
            check(f'{scenario} wrong root', client(port, certdir, wrong_root), False, 'Merkle verification FAILED')
            check(f'{scenario} wrong hostname', client(port, certdir, root, ['-verify_hostname', 'wrong.invalid']), False, 'hostname mismatch')
            # DANE-EE can use a different certificate verification path; reject it.
            cert_der = subprocess.check_output([BASE, 'x509', '-in', str(certdir / 'server.pem'), '-outform', 'DER'])
            record = '3 0 1 ' + hashlib.sha256(cert_der).hexdigest()
            check(f'{scenario} incompatible DANE', client(port, certdir, root,
                  ['-dane_tlsa_domain', 'server', '-dane_tlsa_rrdata', record]), False, 'incompatible option')
            other_ca = CERTS / ('pq' if scenario == 'classic' else 'classic') / 'ca.pem'
            check(f'{scenario} wrong CA', client(port, certdir, root, ['-CAfile', str(other_ca)]), False, 'certificate verify failed')
            check(f'{scenario} expired certificate', client(port, certdir, root, ['-attime', '4102444800']), False, 'certificate has expired')
            check(f'{scenario} ordinary client compatibility', client(port, certdir, binary=BASE), True)
        with server(certdir, ['-merkle_proof', proof, '-groups', 'P-256']) as port:
            result = client(port, certdir, root, ['-groups', 'X25519:P-256', '-msg'])
            check(f'{scenario} HelloRetryRequest', result, True, 'Merkle verification: OK')
            require(result.stdout.count('ClientHello') == 2, 'Expected two ClientHello messages')
        with server(certdir, ['-merkle_proof', wrong_proof]) as port:
            check(f'{scenario} altered sibling', client(port, certdir, root), False, 'Merkle verification FAILED')
        with server(certdir, ['-merkle_proof', bundle / 'proof-0001.bin']) as port:
            check(f'{scenario} proof for different leaf', client(port, certdir, root), False, 'Merkle verification FAILED')
        with server(certdir, binary=BASE) as port:
            check(f'{scenario} missing proof', client(port, certdir, root), False, 'missing proof')
            check(f'{scenario} unchanged baseline', client(port, certdir, binary=BASE), True)
        # A separate test-only peer bypasses sender validation and injects arbitrary bytes.
        payload = proof.read_bytes()
        malformed = {'truncated': payload[:-1], 'trailing': payload + b'\0',
                     'version': b'MTP2' + payload[4:],
                     'index': payload[:8] + struct.pack('!I', 2) + payload[12:],
                     'depth': payload[:44] + b'\xff' + payload[45:]}
        for name, value in malformed.items():
            raw = temp / f'{scenario}-{name}.bin'
            raw.write_bytes(value)
            with server(certdir, raw_payload=raw) as port:
                check(f'{scenario} wire {name}', client(port, certdir, root), False, 'malformed proof')
        for flags in (['-reconnect'], ['-adv'], ['-sess_in', '/missing'], ['-psk', 'aa'], ['-early_data', '/missing'], ['-enable_server_rpk']):
            # Must reject configuration before opening a connection or session file.
            result = client(1, certdir, root, flags)
            check(f'{scenario} incompatible {flags[0]}', result, False, 'incompatible option')
    check('identity required', run([MT, 's_client', '-merkle_root', temp / 'classic/root.bin']),
          False, 'requires -verify_hostname or -verify_ip')
    # Invalid root file is rejected before connecting.
    invalid = temp / 'invalid-root.bin'; invalid.write_bytes(b'bad')
    check('invalid root file', client(1, CERTS / 'classic', invalid), False, 'Merkle configuration FAILED')
print(f'TLS tests: {passed} PASS')
