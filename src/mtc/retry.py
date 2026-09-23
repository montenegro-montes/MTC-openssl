"""Bounded external trust-anchor retry, TAI-04 section 4.3.

No TLS state is held here. Each subprocess owns exactly one native connection.
Server indications are untrusted discovery input, never new trust material.
"""
import argparse
import json
import math
from pathlib import Path
import subprocess
import tempfile
import uuid

MAX_RETRIES = 1
MAX_ID_BYTES = 80


def decode_id(raw):
    if not 1 <= len(raw) <= MAX_ID_BYTES:
        raise ValueError('invalid ID length')
    parts, value, first = [], 0, True
    for byte in raw:
        if first and byte == 0x80:
            raise ValueError('noncanonical ID')
        value = (value << 7) | (byte & 127)
        first = not byte & 128
        if first:
            if value > 0xffffffff:
                raise ValueError('ID component exceeds local limit')
            parts.append(value)
            value = 0
    if not first:
        raise ValueError('unfinished ID')
    return '.'.join(map(str, parts))


def encode_id(ident):
    parts = ident.split('.')
    if any(not p.isascii() or not p.isdecimal() or str(int(p)) != p for p in parts):
        raise ValueError('noncanonical textual ID')
    out = bytearray()
    for part in parts:
        value = int(part)
        if value > 0xffffffff:
            raise ValueError('ID component exceeds local limit')
        encoded = [value & 127]
        value >>= 7
        while value:
            encoded.append((value & 127) | 128)
            value >>= 7
        out.extend(reversed(encoded))
    decode_id(out)
    return bytes(out)


def is_individual_landmark_id(ident):
    """Recognize a canonical CA-prefix.1.log.landmark, never a .2 group.

    This is structural classification only, not proof of CA ownership/trust.
    The retry target remains bound to the native authenticated config ID.
    """
    parts = tuple(map(int, decode_id(encode_id(ident)).split('.')))
    return len(parts) >= 4 and parts[-3] == 1 and parts[-2] > 0 and parts[-1] > 0


def available_ids(hex_data):
    if not isinstance(hex_data, str) or len(hex_data) > 2 * 83:
        raise ValueError('available list exceeds singleton bound')
    raw = bytes.fromhex(hex_data)
    if len(raw) < 4 or int.from_bytes(raw[:2], 'big') != len(raw) - 2:
        raise ValueError('invalid list length')
    if raw[2] != len(raw) - 3:
        raise ValueError('expected exactly one nonempty ID')
    return [decode_id(raw[3:])]


def events(log, prefix):
    result = [json.loads(line[len(prefix):]) for line in log.splitlines()
              if line.startswith(prefix)]
    if any(not isinstance(record, dict) for record in result):
        raise ValueError('invalid event shape')
    return result


def classify_attempt(completed, requested):
    """Only the explicit native EE mismatch can enable a retry."""
    log = completed.stdout + '\n' + completed.stderr
    try:
        results = events(log, 'MTC_RETRY_RESULT ')
        offered = events(log, 'MTC_RETRY_EE ')
        ch = events(log, 'MTC_RETRY_CH ')
        errors = events(log, 'MTC_RETRY_ERROR ')
        timing = events(log, 'MTC_RETRY_TIMING ')
        if len(results) != 1 or len(ch) != 1 or len(timing) != 1 or errors:
            raise ValueError('missing/ambiguous native evidence')
        native = results[0]
        measured = timing[0]
        if decode_id(bytes.fromhex(ch[0]['requested_id_hex'])) != requested:
            raise ValueError('ClientHello does not advertise requested ID')
        connection = native['connection_id']
        if not isinstance(connection, str) or len(connection) != 64 or len(bytes.fromhex(connection)) != 32:
            raise ValueError('invalid connection ID')
        if measured.get('connection_id') != connection:
            raise ValueError('timing connection ID mismatch')
        metric_names = (
            'retry_tcp_connect_wall_ms_native',
            'retry_tls_attempt_wall_ms',
            'retry_attempt_wall_ms_native',
        )
        for name in metric_names:
            value = measured.get(name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError('invalid timing value')
            if not math.isfinite(value) or value < 0:
                raise ValueError('invalid timing value')
        byte_names = ('tls_bytes_read', 'tls_bytes_written', 'tls_bytes_total')
        for name in byte_names:
            value = measured.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError('invalid TLS byte counter')
        if measured['tls_bytes_total'] != measured['tls_bytes_read'] + measured['tls_bytes_written']:
            raise ValueError('inconsistent TLS byte counters')
        if len(offered) != 1:
            raise ValueError('missing/ambiguous available list')
        ids = available_ids(offered[0]['available_list_hex'])
        success = (completed.returncode == 0 and native['result'] == 'PASS'
                   and native['session_reused'] is False
                   and native['tls_version'] == 'TLSv1.3'
                   and 'MTC verification: OK' in log
                   and offered[0]['reason'] == 'compatible')
        mismatch = (completed.returncode != 0 and native['result'] == 'FAIL'
                    and offered[0]['reason'] == 'trust_anchor_mismatch')
        return dict(result='PASS' if success else 'FAIL',
                    reason='authenticated' if success else ('trust_anchor_mismatch' if mismatch else 'authentication_failure'),
                    server_supported_ids=ids,
                    **{k: native[k] for k in
                       ('connection_id', 'session_reused', 'tls_version', 'cipher', 'negotiated_group')},
                    **{k: measured[k] for k in metric_names + byte_names})
    except (ValueError, KeyError, TypeError):
        return dict(result='FAIL', reason='invalid_or_missing_native_evidence',
                    server_supported_ids=[], connection_id=None)


def transaction(initial_id, trusted_id, attempt):
    """attempt() returns only after its process exits and socket/SSL are gone."""
    encode_id(initial_id)
    encode_id(trusted_id)
    report = dict(transaction_id=uuid.uuid4().hex, initial_trust_anchor_id=initial_id,
                  server_supported_ids=[], retry_selected_id=None,
                  attempt_count=0, retry_count=0, attempt_1_result=None,
                  attempt_2_result=None, final_result='FAIL',
                  attempt_1_connection_id=None, attempt_2_connection_id=None,
                  selected_landmark=trusted_id if is_individual_landmark_id(trusted_id) else None,
                  attempts=[])
    requested = initial_id
    for index in range(MAX_RETRIES + 1):
        record = attempt(requested)
        record['requested_id'] = requested
        report['attempts'].append(record)
        report['attempt_count'] += 1
        report['retry_count'] = index
        report[f'attempt_{index + 1}_result'] = record['result']
        report[f'attempt_{index + 1}_connection_id'] = record['connection_id']
        if index == 0:
            report['server_supported_ids'] = record['server_supported_ids']
        elif record['connection_id'] is not None and record['connection_id'] == report['attempt_1_connection_id']:
            record.update(result='FAIL', reason='reused_connection_identity')
            report['attempt_2_result'] = 'FAIL'
            break
        if record['result'] == 'PASS':
            if record['server_supported_ids'] != [trusted_id]:
                record.update(result='FAIL', reason='unexpected_authenticated_anchor')
                report[f'attempt_{index + 1}_result'] = 'FAIL'
                break
            report['final_result'] = 'PASS'
            break
        if index == MAX_RETRIES or record['reason'] != 'trust_anchor_mismatch':
            break
        if trusted_id not in record['server_supported_ids']:
            report['failure_reason'] = 'no_common_locally_trusted_anchor'
            break
        requested = trusted_id
        report['retry_selected_id'] = trusted_id

    totals = (
        ('retry_tcp_connect_wall_ms_native',
         'retry_total_tcp_connect_wall_ms_native'),
        ('retry_tls_attempt_wall_ms',
         'retry_total_tls_attempt_wall_ms'),
        ('retry_attempt_wall_ms_native',
         'retry_total_attempt_wall_ms_native'),
        ('tls_bytes_read', 'retry_total_tls_bytes_read'),
        ('tls_bytes_written', 'retry_total_tls_bytes_written'),
        ('tls_bytes_total', 'retry_total_tls_bytes'),
    )
    for source, target in totals:
        values = [record.get(source) for record in report['attempts']]
        if values and all(isinstance(value, (int, float))
                          and not isinstance(value, bool)
                          for value in values):
            report[target] = sum(values)

    return report


def run_native(peer, host, port, trust, mode, hostname, requested):
    try:
        # subprocess.run waits for termination; timeout kills and waits too.
        completed = subprocess.run([peer, 'client', host, str(port), str(trust), mode,
                                    requested, hostname], capture_output=True, text=True,
                                   timeout=12, check=False)
        return classify_attempt(completed, requested)
    except (subprocess.TimeoutExpired, OSError):
        return dict(result='FAIL', reason='transport_or_process_failure',
                    server_supported_ids=[], connection_id=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peer', default='/opt/mtc/retry-peer')
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, required=True)
    parser.add_argument('--hostname', required=True)
    parser.add_argument('--trust', type=Path, required=True)
    parser.add_argument('--mode', choices=['landmark', 'standalone'], default='landmark')
    parser.add_argument('--initial-id', required=True)
    parser.add_argument('--output', type=Path, help='create new JSON file; existing files rejected')
    args = parser.parse_args()
    encode_id(args.initial_id)
    if not 1 <= args.port <= 65535:
        parser.error('invalid port')
    # Reserve output before networking, and freeze trust bytes across attempts.
    with tempfile.TemporaryDirectory(prefix='mtc-retry-') as directory:
        trust = Path(directory) / 'trust.bin'
        data = args.trust.read_bytes()
        if not 0 < len(data) <= 65536:
            parser.error('invalid trust file size')
        trust.write_bytes(data)
        checked = subprocess.run([args.peer, 'inspect', str(trust), args.mode],
                                 capture_output=True, text=True, timeout=12, check=True)
        entries = events(checked.stdout, 'MTC_RETRY_TRUST ')
        if len(entries) != 1:
            raise ValueError('missing authenticated local trust identity')
        trusted_id = decode_id(bytes.fromhex(entries[0]['trusted_id_hex']))
        output = args.output.open('x') if args.output else None
        try:
            report = transaction(args.initial_id, trusted_id,
                                 lambda ident: run_native(args.peer, args.host, args.port,
                                                          trust, args.mode, args.hostname, ident))
            serialized = json.dumps(report, indent=2) + '\n'
            if output:
                output.write(serialized)
            print(serialized, end='')
        finally:
            if output:
                output.close()
    return 0 if report['final_result'] == 'PASS' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # No raw provider/process response, private key or trust bytes in errors.
        print(json.dumps(dict(final_result='FAIL', reason='configuration_or_inspection_failure',
                              error_type=type(error).__name__)))
        raise SystemExit(1)
