from contextlib import contextmanager
from pathlib import Path
import hashlib
import json
import socket
import struct
import subprocess
import tempfile
import time
from scenarios import OPENSSL, BATCH, SCENARIOS, server_args, client_args
from prepare import command, tree, bundle, dates
count = 0

@contextmanager
def server(scenario, extra=(), raw=None, cert=None, key=None):
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    args = server_args(scenario, port) + list(map(str, extra))
    if raw is not None:
        args = ['/opt/compact/test_peer', str(port), str(cert), str(key), str(raw)]
    with tempfile.TemporaryFile(mode='w+') as log:
        p = subprocess.Popen(args, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if p.poll() is not None:
                    log.seek(0); raise AssertionError('Server failed: ' + log.read())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1): break
                except OSError: time.sleep(.025)
            else: raise AssertionError('server not ready')
            yield port
        finally:
            p.terminate()
            try: p.wait(timeout=3)
            except subprocess.TimeoutExpired: p.kill(); p.wait()

def test(name, scenario, port, ok, extra=()):
    global count
    p = subprocess.run(client_args(scenario, '127.0.0.1', port) + list(map(str, extra)),
                       input='GET / HTTP/1.0\r\n\r\n', text=True, capture_output=True, timeout=10)
    log = p.stdout + p.stderr
    assert (p.returncode == 0) == ok, name + '\n' + log
    assert ('HTTP/1.0 200' in log) == ok, name + ': unexpected application data\n' + log
    if ok:
        marker = 'Compact verification: OK' if '-compact-' in scenario else ('Merkle verification: OK' if scenario.endswith('-mt') else 'Verify return code: 0 (ok)')
        assert marker in log, name + ': missing verification'
        metrics = [json.loads(line[len('LAB_METRICS '):]) for line in log.splitlines() if line.startswith('LAB_METRICS ')]
        assert len(metrics) == 1 and not metrics[0]['reused']
        assert metrics[0]['server_cert_type'] == (2 if '-compact-' in scenario else 0)
        assert metrics[0]['certificate_verify_message_bytes'] > 0
        assert metrics[0]['certificate_message_bytes'] > 0
    count += 1; print('PASS', name, flush=True)

with tempfile.TemporaryDirectory() as temp:
    temp = Path(temp)
    for scenario in SCENARIOS:
        with server(scenario) as port: test(scenario, scenario, port, True)
    for base in ['classic', 'pq']:
        warm, cold = base + '-compact-warm', base + '-compact-cold'
        c = Path('/work/certs') / base; b = BATCH / base
        signed = (b/'root.signed').read_bytes(); payload = (b/'bundle-0000.bin').read_bytes()
        cert, key = c/'server.pem', c/'server.key'
        with server(warm) as port:
            test(base+' wrong identity', warm, port, False, ['-verify_hostname','wrong.invalid'])
            other = 'pq' if base == 'classic' else 'classic'
            test(base+' wrong authority', warm, port, False, ['-compact_authority',Path('/work/certs')/other/'ca.pem'])
            test(base+' wrong authority cold', cold, port, False, ['-compact_authority',Path('/work/certs')/other/'ca.pem'])
            test(base+' unknown cached root', warm, port, False, ['-compact_root',BATCH/other/'root.signed'])
            for flags in [['-reconnect'], ['-psk','aa'], ['-adv'], ['-sess_in','/missing'], ['-early_data','/missing']]:
                test(base+' rejects '+flags[0], warm, port, False, flags)
        for mode in [warm, cold]:
            with server(mode, ['-groups', 'P-256']) as port:
                test(base+' HRR '+mode, mode, port, True, ['-groups','X25519:P-256'])
        wrong_signed = temp / (base+'bad-cache.bin'); wrong_signed.write_bytes(signed[:-1]+bytes([signed[-1]^1]))
        test(base+' invalid cached signature',warm,1,False,['-compact_root',wrong_signed])
        with server(base) as port:
            test(base+' no downgrade to X509', warm, port, False)
        # A valid proof for the last leaf exercises left siblings and a different key/name.
        info = json.loads((b/'manifest.json').read_text()); last = info['leaves'] - 1
        if last:
            with server(warm, ['-cert',b/'issued'/f'{last}.pem','-key',b/'issued'/f'{last}.key','-compact_bundle',b/f'bundle-{last:04d}.bin']) as port:
                test(base+' other valid leaf', warm, port, True, ['-verify_hostname',f'member-{last}.lab'])
            with server(warm, ['-cert',b/'issued'/'1.pem','-key',b/'issued'/'1.key']) as port:
                test(base+' wrong RPK despite valid credential', warm, port, False)
        # Raw peer intentionally bypasses sender-side validation.
        bad = bytearray(payload); bad[-3] ^= 1
        variants = {'valid':payload, 'missing':b'', 'truncated':payload[:-1], 'trailing':payload+b'\0',
                    'version':b'MCB9'+payload[4:], 'credential_length':payload[:4]+b'\xff\xff'+payload[6:], 'sibling':bytes(bad)}
        # Structurally valid credential with altered identity but unchanged proof.
        bad = bytearray(payload); bad[12] ^= 1; variants['credential_mutation'] = bytes(bad)
        for name, value in variants.items():
            raw = temp/(base+name+'.bin'); raw.write_bytes(value)
            with server(warm, raw=raw, cert=cert, key=key) as port:
                test(base+' raw '+name, warm, port, name == 'valid')
        for name, value in [('valid',signed), ('bad_signature',signed[:-1]+bytes([signed[-1]^1]))]:
            raw = temp/(base+'cold'+name+'.bin')
            raw.write_bytes(payload[:-2]+struct.pack('!H',len(value))+value)
            with server(cold, raw=raw, cert=cert, key=key) as port:
                test(base+' cold '+name, cold, port, name == 'valid')
        # Re-sign malicious credentials/roots with the configured authority: signature
        # correctness alone must not bypass purpose, identity or validity policy.
        credential = (b/'credential-0000.bin').read_bytes(); namelen = struct.unpack('!H',credential[4:6])[0]
        for name in ['expired_credential','wrong_purpose','future_root','expired_root']:
            value = bytearray(credential); header = bytearray(signed[:88]); now = int(time.time())
            if name == 'expired_credential': value[14+namelen:22+namelen] = struct.pack('!Q',now-1)
            if name == 'wrong_purpose': value[-1] = 0
            root, proofs = tree([bytes(value)])
            header[4:8] = struct.pack('!I',1); header[8:40] = root
            if name == 'future_root': header[40:56] = struct.pack('!QQ',now+3600,now+7200)
            if name == 'expired_root': header[40:56] = struct.pack('!QQ',now-3600,now-1)
            path = temp/'header'; path.write_bytes(header)
            args = ['pkeyutl','-sign','-rawin','-inkey',c/'ca.key','-in',path]
            if base == 'classic': args += ['-digest','sha256']
            signature = command(*args); new_signed = bytes(header)+struct.pack('!H',len(signature))+signature
            raw = temp/(base+name+'.bin'); raw.write_bytes(bundle(bytes(value),proofs[0])[:-2]+struct.pack('!H',len(new_signed))+new_signed)
            with server(cold, raw=raw, cert=cert, key=key) as port: test(base+' signed '+name,cold,port,False)
    print(f'Compact TLS: {count} PASS')
