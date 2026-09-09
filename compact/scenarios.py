import os
from pathlib import Path
OPENSSL = '/opt/openssl-compact/bin/openssl'
BATCH = Path(os.environ.get('COMPACT_BATCH', '/work/compact/batch16'))
SCENARIOS = ['classic', 'pq', 'classic-mt', 'pq-mt', 'classic-compact-warm', 'classic-compact-cold', 'pq-compact-warm', 'pq-compact-cold']

def base(scenario): return 'pq' if scenario.startswith('pq') else 'classic'

def server_args(scenario, port):
    cert = Path('/work/certs') / base(scenario)
    args = [OPENSSL, 's_server', '-accept', str(port), '-tls1_3', '-groups', 'X25519',
            '-ciphersuites', 'TLS_AES_256_GCM_SHA384', '-cert', str(cert / 'server.pem'),
            '-key', str(cert / 'server.key'), '-num_tickets', '0', '-www', '-quiet']
    if scenario.endswith('-mt'):
        args += ['-merkle_proof', str(BATCH / base(scenario) / 'x509-merkle/proof-0000.bin')]
    if '-compact-' in scenario:
        args += ['-compact_bundle', str(BATCH / base(scenario) / 'bundle-0000.bin'),
                 '-compact_signed_root', str(BATCH / base(scenario) / 'root.signed')]
    return args

def client_args(scenario, host, port):
    cert = Path('/work/certs') / base(scenario)
    args = [OPENSSL, 's_client', '-connect', f'{host}:{port}', '-servername', 'server',
            '-verify_hostname', 'server', '-verify_return_error', '-tls1_3', '-groups', 'X25519',
            '-ciphersuites', 'TLS_AES_256_GCM_SHA384', '-no_ticket', '-ign_eof', '-lab_metrics']
    if '-compact-' in scenario:
        args += ['-compact_authority', str(cert / 'ca.pem')]
        if scenario.endswith('-warm'): args += ['-compact_root', str(BATCH / base(scenario) / 'root.signed')]
        else: args += ['-compact_cold']
    else:
        args += ['-CAfile', str(cert / 'ca.pem')]
        if scenario.endswith('-mt'): args += ['-merkle_root', str(BATCH / base(scenario) / 'x509-merkle/root.bin')]
    return args
