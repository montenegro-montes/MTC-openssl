"""Fail-closed offline checks on endpoint evidence."""
import json
import math
import re
from .common import require

DIRECTIONAL = ['server_certificate_message_bytes', 'client_certificate_message_bytes',
               'server_certificate_verify_message_bytes', 'client_certificate_verify_message_bytes']


def parse_metrics(text):
    matches = re.findall(r'^PROFILE_METRICS (\{.*\})$', text, re.MULTILINE)
    require(len(matches) == 1, 'Expected one client metric record')
    return json.loads(matches[0])


def validate(case, client_log, server_log, client, server):
    require('Verification: OK' in client_log and 'Verify return code: 0 (ok)' in client_log, 'Peer verification failed')
    require('New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384' in client_log, 'TLS version/cipher/fresh-session mismatch')
    require('Peer Temp Key: X25519' in client_log or 'Server Temp Key: X25519' in client_log, 'Group mismatch')
    require('SSL_accept:SSLv3/TLS read finished' in server_log, 'Server did not authenticate client Finished')
    require(client['side'] == 'client' and server['side'] == 'server', 'Endpoint roles mismatch')
    require(client['profile_valid'] == 1 and server['profile_valid'] == 1, 'Native profile invalid')
    require(not client['reused'] and not server['reused'], 'Resumed session')
    require(bool(re.fullmatch('[0-9a-fA-F]{64}', client['client_random'])), 'Invalid client_random')
    require(client['client_random'] == server['client_random'], 'Endpoint pairing mismatch')
    for k in DIRECTIONAL:
        require(type(client[k]) is int and client[k] >= 0 and client[k] == server[k], 'Directional mismatch: ' + k)
    mutual = case['authentication'] == 'mutual'
    for k in ['client_certificate_message_bytes', 'client_certificate_verify_message_bytes']:
        require((client[k] > 0) if mutual else (client[k] == 0), 'Client authentication mode mismatch: ' + k)
    for k in ['server_certificate_message_bytes', 'server_certificate_verify_message_bytes']:
        require(client[k] > 0, 'Missing server authentication: ' + k)
    for endpoint in [client, server]:
        for old, new in [('certificate_message_bytes', 'server_certificate_message_bytes'),
                         ('certificate_verify_message_bytes', 'server_certificate_verify_message_bytes')]:
            require(endpoint[old] == endpoint[new], 'Legacy instrumentation semantics changed')
        for k in ['handshake_wall_ms', 'handshake_cpu_ms']:
            require(math.isfinite(float(endpoint[k])) and float(endpoint[k]) >= 0, 'Invalid timing: ' + k)
    require(client['handshake_read_bytes'] == server['handshake_written_bytes'] and
            client['handshake_written_bytes'] == server['handshake_read_bytes'], 'Handshake directional byte mismatch')
    if case['credential'] == 'mtc-landmark':
        require('MTC_VERIFY' in client_log, 'Missing client MTC verification')
        if mutual:
            require('MTC_VERIFY' in server_log, 'Missing server MTC verification')
    if mutual:
        require('SSL_accept:SSLv3/TLS read client certificate' in server_log and
                'SSL_accept:SSLv3/TLS read certificate verify' in server_log, 'Mutual authentication missing')
    result = {k: client[k] for k in DIRECTIONAL}
    result.update(client_random=client['client_random'],
                  certificate_total_bytes=sum(client[k] for k in DIRECTIONAL[:2]),
                  certificate_verify_total_bytes=sum(client[k] for k in DIRECTIONAL[2:]),
                  handshake_total_bytes=client['handshake_read_bytes'] + client['handshake_written_bytes'],
                  tls_bio_total_bytes=client['transport_read_bytes'] + client['transport_written_bytes'])
    for endpoint, values in [('client', client), ('server', server)]:
        result[endpoint + '_handshake_wall_ms'] = values['handshake_wall_ms']
        result[endpoint + '_cpu_ms'] = values['handshake_cpu_ms']
    for k in ['tcp_connect_wall_ms_native', 'connection_establishment_wall_ms_native']:
        value = client[k]
        require(math.isfinite(float(value)) and float(value) >= 0, 'Invalid native connection timing')
        result[k] = value
    for role, text in [('client', client_log), ('server', server_log)]:
        for prefix, field, suffix in [('MTC_SETUP', 'mtc_setup_ms', 'mtc_setup_ms'),
                                      ('MTC_VERIFY', 'mtc_credential_auth_ms', 'mtc_verify_ms')]:
            values = [float(json.loads(x)[field]) for x in re.findall(r'^' + prefix + r' (\{.*\})$', text, re.MULTILINE)]
            result[role + '_' + suffix] = sum(values) if values else None
    return result
