#!/usr/bin/env python3
"""One loopback capture per browser case; no repeated measurement campaign."""
import argparse
import base64
import csv
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

sys.dont_write_bytecode = True
import browser_validation as bv
sys.path.insert(0, str(bv.REPO/'campaigns/performance/handshake_performance'))
import pcap_handshake as ph

PREFIX = 'chromium-browser-pcap-'
FILTER = 'tcp port 4433'
METRICS = ('tcp_packets_client_to_server', 'tcp_packets_server_to_client', 'tcp_packets_total',
           'tcp_payload_bytes_client_to_server', 'tcp_payload_bytes_server_to_client', 'tcp_payload_bytes_total',
           'tcp_wire_bytes_client_to_server', 'tcp_wire_bytes_server_to_client', 'tcp_wire_bytes_total')
HANDSHAKE_FIELDS = ph.METRIC_FIELDS
BROWSER_TIMING_FIELDS = ('browser_process_wall_ms', 'browser_ssl_connect_ms',
                         'browser_navigation_to_clienthello_ms', 'browser_request_to_response_headers_ms')
COMPARISON_FIELDS = (*HANDSHAKE_FIELDS, *BROWSER_TIMING_FIELDS)
COMPARISON_DEFINITIONS = {
    'handshake': 'Per TCP stream, exactly campaigns/performance/handshake_performance/pcap_handshake.py fields and semantics: '
        'TCP SYN/SYN-ACK/ACK, TLS ClientHello through client Finished, and first HTTP request. '
        'Logical TLS bytes deduplicate retransmissions; wire bytes use frame.len. '
        'connection_handshake_wire_bytes counts the union of TCP and TLS frames once.',
    'availability': 'Handshake analysis is fail-closed, requires decrypted Finished/Certificate and HTTP, '
        'and reports analysis_status/error independently of functional browser PASS. '
        'Top-level handshake values require exactly one URL-linked connection; otherwise null. '
        'Per-connection values remain in connections and connection-metrics.csv. Latencies are never summed.',
    'tcp_wire_bytes': 'Whole captured stream frame.len including ACK-only frames, HTTP, closing frames '
        'and retransmissions, by direction and total. Not restricted to the handshake.',
    'browser_process_wall_ms': 'Monotonic time immediately before browser process creation through exit '
        '(including timeout termination): startup, navigation, rendering and shutdown; not handshake latency.',
    'browser_ssl_connect_ms': 'NetLog SSL_CONNECT BEGIN to successful END on the correlated ClientHello source; '
        'includes browser TLS processing/verification, not a substitute for the PCAP TLS interval.',
    'browser_navigation_to_clienthello_ms': 'NetLog target URL_REQUEST_START_JOB BEGIN to correlated ClientHello; '
        'available only for a unique job and a unique ClientHello in the URL dependency graph.',
    'browser_request_to_response_headers_ms': 'NetLog HTTP_TRANSACTION_SEND_REQUEST BEGIN to '
        'HTTP_TRANSACTION_READ_RESPONSE_HEADERS END on the same source in the unique URL connection graph; '
        'includes server/HTTP work, not TLS latency.',
    'timing': 'NetLog intervals use its millisecond clock only; never subtract PCAP epoch timestamps. '
        'Ambiguous, missing or invalid events are null (blank CSV), never zero.',
    'scope': 'Session totals cover only captured loopback TCP port 4433 traffic, not all browser networking. '
        'URL-linked versus auxiliary/aborted connections are reported separately. '
        'Compare identical TLS/authentication profiles and capture link layers; frame.len is capture-relative.'}
DECOMPOSITION = ('client_hello_tcp_payload_bytes', 'server_initial_flight_tcp_payload_bytes',
                 'client_post_server_flight_tls_payload_bytes', 'http_request_tcp_payload_bytes',
                 'http_response_tcp_payload_bytes', 'pre_http_tls_payload_bytes_total',
                 'client_hello_handshake_bytes')
DECOMPOSITION_DEFINITIONS = {
    'client_hello_tcp_payload_bytes': 'Observed bytes overlapping the single plaintext TLS record containing '
        'only ClientHello, including its 5-byte record header and retransmissions; excludes other coalesced bytes. '
        'Unavailable for fragmented TLS-record layouts.',
    'client_hello_handshake_bytes': 'Length of the correlated server.log ClientHello hex dump, including '
        'the 4-byte handshake header; excludes TLS record headers and retransmissions.',
    'unavailable_encrypted_components': 'Server-log semantic events are not mapped to PCAP TCP sequence ranges. '
        'Encrypted TLS 1.3 records do not distinguish Finished, HTTP, alerts or post-handshake messages. '
        'Packet direction/order alone cannot safely establish complete flight or HTTP boundaries.',
    'aggregation': 'Sum across successful URL-linked connections only when every URL-linked connection '
        'has an available value; otherwise null (blank in CSV). Missing values are never zero.'}


def connection_decomposition(segments, isn, handshake_bytes):
    """Optional measurement only; never changes correlation or PASS conditions."""
    values = dict.fromkeys(DECOMPOSITION)
    values['client_hello_handshake_bytes'] = handshake_bytes
    # Existing correlation has checked retransmission consistency and the ClientHello.
    # Bound this extra prefix read to one possible ClientHello record.
    limit = handshake_bytes+5
    prefix = bytearray()
    for seq, payload in sorted(segments, key=lambda item: (item[0]-isn) % (1 << 32)):
        offset = (seq-isn) % (1 << 32)
        if offset > len(prefix) or offset >= limit: break
        overlap = min(len(payload), len(prefix)-offset)
        prefix.extend(payload[overlap:overlap+max(0, limit-len(prefix))])
    if (len(prefix) == limit and prefix[0] == 22 and prefix[5] == 1
            and int.from_bytes(prefix[3:5], 'big') == handshake_bytes
            and int.from_bytes(prefix[6:9], 'big') == handshake_bytes-4):
        values['client_hello_tcp_payload_bytes'] = sum(
            max(0, min((seq-isn) % (1 << 32)+len(payload), limit)-(seq-isn) % (1 << 32))
            for seq, payload in segments)
    return values


def handshake_metrics(rows, client_random):
    """Use the s_client analyzer unchanged, then check browser correlation identity."""
    values = ph.analyze_safe(rows)
    if values['client_random'] != client_random:
        values = dict.fromkeys(HANDSHAKE_FIELDS)
        values.update(analysis_status='ERROR', analysis_error='PCAP/NetLog client_random mismatch')
    return values


def browser_metric_values(primary, browser_result, net):
    """Comparable connection fields and optional browser intervals, never summed latencies."""
    values = dict.fromkeys(COMPARISON_FIELDS)
    duration = browser_result.get('browser_process_wall_ms')
    if isinstance(duration, (int, float)) and not isinstance(duration, bool) and math.isfinite(duration) and duration >= 0:
        values['browser_process_wall_ms'] = duration
    if len(primary) != 1:
        values.update(analysis_status='ERROR', analysis_error='Expected exactly one URL-linked connection')
        return values
    entry = primary[0]
    values.update(entry['handshake_metrics'])
    types = {v: k for k, v in net.get('constants', {}).get('logEventTypes', {}).items()}
    phases = net.get('constants', {}).get('logEventPhase', {})
    begin, end = phases.get('PHASE_BEGIN', 1), phases.get('PHASE_END', 2)
    events = net.get('events', [])

    def name(event): return types.get(event.get('type'), event.get('type'))
    def source(event): return event.get('source', {}).get('id')
    def timestamp(event):
        try:
            value = float(event['time'])
            return value if math.isfinite(value) else None
        except (KeyError, TypeError, ValueError): return None
    def interval(starts, stops):
        if len(starts) != 1 or len(stops) != 1: return None
        first, last = timestamp(starts[0]), timestamp(stops[0])
        return last-first if first is not None and last is not None and last >= first else None

    hellos = []
    for event in events:
        params = event.get('params', {})
        if name(event) == 'SSL_HANDSHAKE_MESSAGE_SENT' and params.get('type') == 1:
            try:
                item = hello(base64.b64decode(params['bytes'], validate=True))
            except (ValueError, KeyError, IndexError): continue
            if item['client_random'] == entry['client_random']: hellos.append(event)
    if len(hellos) != 1 or source(hellos[0]) is None: return values
    ch = hellos[0]; own = [e for e in events if source(e) == source(ch) and name(e) == 'SSL_CONNECT']
    starts = [e for e in own if e.get('phase') == begin]
    stops = [e for e in own if e.get('phase') == end]
    ssl_ms = interval(starts, stops)
    if (ssl_ms is not None and timestamp(ch) is not None
            and stops[0].get('params', {}).get('net_error', 0) == 0
            and timestamp(starts[0]) <= timestamp(ch) <= timestamp(stops[0])):
        values['browser_ssl_connect_ms'] = ssl_ms
    url = browser_result.get('target_url')
    if not url: return values
    linked_ids = {sid for _, _, _, sid in bv.relevant_netlog(net, url) if sid is not None}
    linked = [e for e in events if source(e) in linked_ids]
    linked_hellos = [e for e in linked if name(e) == 'SSL_HANDSHAKE_MESSAGE_SENT'
                     and e.get('params', {}).get('type') == 1]
    if len(linked_hellos) != 1 or linked_hellos[0] is not ch: return values
    jobs = [e for e in linked if name(e) == 'URL_REQUEST_START_JOB' and e.get('phase') == begin
            and e.get('params', {}).get('url') == url]
    values['browser_navigation_to_clienthello_ms'] = interval(jobs, [ch])
    requests = [e for e in linked if name(e) == 'HTTP_TRANSACTION_SEND_REQUEST' and e.get('phase') == begin]
    headers = [e for e in linked if name(e) == 'HTTP_TRANSACTION_READ_RESPONSE_HEADERS' and e.get('phase') == end]
    if (len(requests) == len(headers) == 1 and source(requests[0]) == source(headers[0])
            and headers[0].get('params', {}).get('net_error', 0) == 0):
        values['browser_request_to_response_headers_ms'] = interval(requests, headers)
    return values


def save_comparison(output, result):
    """One row per correlated TCP stream; the shared schema keeps its column order."""
    fields = ('case', 'signature_profile', 'key_establishment', 'key_exchange_group',
              'classification', 'client_port',
              *HANDSHAKE_FIELDS, *METRICS)
    with (output/'connection-metrics.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for entry in result['wire_observed'].get('connections', []):
            writer.writerow(dict(case=result['name'], signature_profile=result.get('signature_profile'),
                key_establishment=result.get('key_establishment'),
                key_exchange_group=result.get('key_exchange_group'), classification=entry['classification'],
                client_port=entry['client_port'], **entry['handshake_metrics'],
                **{key: entry[key] for key in METRICS}))


def requirements():
    system = platform.system()
    return dict(platform=system, interface={'Darwin': 'lo0', 'Linux': 'lo'}.get(system),
                capture_filter=FILTER, dumpcap=shutil.which('dumpcap'), tcpdump=shutil.which('tcpdump'),
                tshark=shutil.which('tshark'), permissions='NOT CHECKED; capture readiness is checked only by run',
                instruction='Install capture tools manually if missing. Ask your administrator to grant '
                            'your user capture access to the loopback interface. No automatic sudo or permission changes.')


class Capture:
    def __init__(self, output, tools):
        self.output, self.tools = output, tools
        self.child = self.log = self.path = None
        self.clean = False
        self.keylog_path = output/'tls.keys'

    def start(self):
        # This file decrypts the captured session: create it privately before Chromium opens it.
        with self.keylog_path.open('xb') as keylog:
            os.fchmod(keylog.fileno(), 0o600)
        attempts = []
        try:
            for backend in ('dumpcap', 'tcpdump'):
                executable = self.tools[backend]
                if not executable:
                    continue
                self.path = self.output/('capture.pcapng' if backend == 'dumpcap' else 'capture.pcap')
                cmd = [executable, '-i', self.tools['interface']]
                cmd += (['-f', FILTER, '-s', '0', '-w', str(self.path)] if backend == 'dumpcap' else
                        ['-nn', '-s', '0', '-U', '-w', str(self.path), FILTER])
                log_path = self.output/(backend+'.stderr.log')
                attempt = dict(backend=backend, command=cmd, stderr=str(log_path), ready=False)
                attempts.append(attempt)
                self.log = log_path.open('xb')
                try:
                    self.child = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=self.log,
                                                  start_new_session=True, env={**os.environ, 'LC_ALL': 'C'})
                except OSError as error:
                    attempt['error'] = str(error)
                    self.log.close(); self.log = None
                    continue
                attempt['pid'] = self.child.pid
                deadline = time.monotonic()+10
                while time.monotonic() < deadline and self.child.poll() is None:
                    text = log_path.read_text(errors='replace')
                    ready = ('File:' in text if backend == 'dumpcap' else 'listening on ' in text)
                    if ready and self.path.exists():
                        attempt['ready'] = True
                        return
                    time.sleep(0.1)
                self.stop()
            raise ValueError('No capture backend became ready. '+self.tools['instruction']+
                             ' Inspect dumpcap/tcpdump stderr. Manual interface checks: dumpcap -D; tcpdump -D.')
        finally:
            bv.write(self.output/'capture-command.json', dict(interface=self.tools['interface'],
                     filter=FILTER, attempts=attempts, capture_file=str(self.path) if self.path else None))

    def stop(self):
        if self.child is None:
            return
        try:
            running = self.child.poll() is None
            if running:
                self.child.send_signal(signal.SIGINT)
            try:
                code = self.child.wait(timeout=10)
                self.clean = running and code == 0
            except subprocess.TimeoutExpired:
                self.child.kill(); self.child.wait(timeout=5)
                self.clean = False
        finally:
            self.child = None
            if self.log:
                self.log.close(); self.log = None


def hello(raw):
    kind, pos = bv.take_number(raw, 0, 1)
    length, pos = bv.take_number(raw, pos, 3)
    bv.require(kind == 1 and length == len(raw)-4, 'Malformed ClientHello')
    data = raw[pos:]; pos = 0
    _, pos = bv.take_number(data, pos, 2)
    random_end = pos + 32
    bv.require(random_end <= len(data), 'Malformed ClientHello')
    random = data[pos:random_end].hex(); pos = random_end
    _, pos = bv.take_vector(data, pos, 1)
    _, pos = bv.take_vector(data, pos)
    _, pos = bv.take_vector(data, pos, 1)
    exts, pos = bv.take_vector(data, pos)
    bv.require(pos == len(data), 'Trailing ClientHello data')
    ext_pos = 0; payload = None; hostname = None
    while ext_pos < len(exts):
        kind, ext_pos = bv.take_number(exts, ext_pos, 2)
        value, ext_pos = bv.take_vector(exts, ext_pos)
        if kind == 0xca34:
            bv.require(payload is None, 'Duplicate TAI extension')
            payload = value
        if kind == 0:
            entries, names_pos = bv.take_vector(value, 0)
            bv.require(names_pos == len(value), 'Trailing server-name extension data')
            entry_pos = 0
            while entry_pos < len(entries):
                name_type, entry_pos = bv.take_number(entries, entry_pos, 1)
                name, entry_pos = bv.take_vector(entries, entry_pos)
                if name_type == 0: hostname = name.decode('ascii')
            bv.require(entry_pos == len(entries), 'Trailing server-name list data')
    bv.require(ext_pos == len(exts), 'Trailing ClientHello extensions data')
    ids = []
    if payload is not None:
        entries, outer_pos = bv.take_vector(payload, 0)
        bv.require(outer_pos == len(payload), 'Trailing trust-anchor extension data')
        entry_pos = 0
        while entry_pos < len(entries):
            raw_id, entry_pos = bv.take_vector(entries, entry_pos, 1); arcs = []; n = 0
            bv.require(bool(raw_id) and not raw_id[-1] & 128, 'Malformed Trust Anchor ID')
            for byte in raw_id:
                n = (n << 7) | (byte & 127)
                if not byte & 128: arcs.append(n); n = 0
            ids.append(dict(hex=raw_id.hex(), decimal='.'.join(map(str, arcs))))
        bv.require(entry_pos == len(entries), 'Trailing Trust Anchor ID list data')
    return dict(client_random=random, hostname=hostname, client_hello_observed=True,
                trust_anchor_ids_extension_observed=payload is not None,
                trust_anchor_ids_extension_type='0xca34' if payload is not None else None,
                trust_anchor_ids_extension_payload_bytes=len(payload) if payload is not None else None,
                trust_anchor_ids_extension_payload_hex=payload.hex() if payload is not None else None,
                trust_anchor_ids=ids, requested_tai_observed=any(i['hex'] == bv.core.relid(bv.REQUESTED).hex() for i in ids))


def plaintext_hellos(segments, initial_sequence):
    """Reassemble a contiguous TCP prefix, then plaintext TLS handshake records only."""
    bv.require(initial_sequence is not None, 'Missing SYN: incomplete capture')
    data = bytearray()
    for seq, payload in sorted(segments, key=lambda item: (item[0]-initial_sequence) % (1 << 32)):
        offset = (seq-initial_sequence) % (1 << 32)
        if offset > len(data): break
        overlap = min(len(payload), len(data)-offset)
        bv.require(data[offset:offset+overlap] == payload[:overlap], 'Conflicting TCP retransmission')
        data.extend(payload[overlap:])
        bv.require(len(data) <= 8*1024*1024, 'TCP prefix exceeds bounded analysis size')
    pos = 0; handshake = bytearray(); found = []
    while pos+5 <= len(data):
        kind = data[pos]; size = int.from_bytes(data[pos+3:pos+5], 'big')
        if pos+5+size > len(data): break
        record = data[pos+5:pos+5+size]; pos += 5+size
        if kind != 22: continue  # Never interpret encrypted application_data as plaintext TLS.
        handshake.extend(record)
        while len(handshake) >= 4:
            size = 4+int.from_bytes(handshake[1:4], 'big')
            if len(handshake) < size: break
            raw = bytes(handshake[:size]); del handshake[:size]
            if raw[0] == 1: found.append(hello(raw))
    return found


def netlog_connections(net):
    """Index ClientHellos and conservative unused-TLS evidence by dependency component."""
    types = {v: k for k, v in net.get('constants', {}).get('logEventTypes', {}).items()}
    end_phase = net.get('constants', {}).get('logEventPhase', {}).get('PHASE_END', 2)
    begin_phase = net.get('constants', {}).get('logEventPhase', {}).get('PHASE_BEGIN', 1)
    graph = {}; grouped = {}

    def dependencies(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key == 'source_dependency' and isinstance(item, dict) and 'id' in item:
                    yield item['id']
                else:
                    yield from dependencies(item)
        elif isinstance(value, list):
            for item in value: yield from dependencies(item)

    def has_url(value):
        if isinstance(value, dict):
            return any((key == 'url' and bool(item)) or has_url(item) for key, item in value.items())
        return isinstance(value, list) and any(has_url(item) for item in value)

    for event in net.get('events', []):
        sid = event.get('source', {}).get('id')
        if sid is None: continue
        grouped.setdefault(sid, []).append(event)
        graph.setdefault(sid, set())
        for dep in dependencies(event.get('params', {})):
            graph[sid].add(dep); graph.setdefault(dep, set()).add(sid)
    indexed = {}; visited = set()
    for sid in graph:
        if sid in visited: continue
        component = {sid}; todo = [sid]
        while todo:
            for dep in graph[todo.pop()] - component:
                component.add(dep); todo.append(dep)
        visited.update(component)
        events = sorted((event for node in component for event in grouped.get(node, [])),
                        key=lambda event: float(event.get('time', 0)))
        hellos = {}; connected_at = None; closed_unused = False; used = False
        http_request = False; authentication = False; client_finished = False
        for event in events:
            name = types.get(event.get('type'), event.get('type'))
            params = event.get('params', {})
            used |= has_url(params) or 'SEND_REQUEST' in str(name) or name in (
                'HTTP2_SESSION_SEND_HEADERS', 'HTTP3_HEADERS_SENT')
            http_request |= 'SEND_REQUEST' in str(name) or name in (
                'HTTP2_SESSION_SEND_HEADERS', 'HTTP3_HEADERS_SENT')
            authentication |= (name in ('SSL_HANDSHAKE_MESSAGE_SENT', 'SSL_HANDSHAKE_MESSAGE_RECEIVED')
                               and params.get('type') in (11, 15, 20))
            client_finished |= name == 'SSL_HANDSHAKE_MESSAGE_SENT' and params.get('type') == 20
            if name == 'SSL_HANDSHAKE_MESSAGE_SENT' and params.get('type') == 1:
                item = hello(base64.b64decode(params['bytes'], validate=True))
                random = item['client_random']
                bv.require(random not in hellos or hellos[random] == item, 'Conflicting NetLog ClientHellos')
                hellos[random] = item
            if (name == 'SSL_CONNECT' and event.get('phase') == end_phase
                    and params.get('net_error', 0) == 0 and params.get('version') == 'TLS 1.3'):
                connected_at = float(event.get('time', 0))
            if (name == 'SOCKET_POOL_CLOSING_SOCKET' and params.get('reason') == 'Socket pool destroyed'
                    and connected_at is not None and float(event.get('time', 0)) >= connected_at):
                closed_unused = True
        # A shared component containing several handshakes cannot attribute its SSL_CONNECT
        # and pool-close events to an individual connection safely.
        auxiliary = len(hellos) == 1 and connected_at is not None and closed_unused and not used
        # Require lifecycle evidence on the ClientHello's own source. Component-wide
        # evidence can veto this classification but cannot supply a different socket's end.
        aborted = False
        if len(hellos) == 1 and not used and not client_finished and connected_at is None:
            forbidden = any(
                types.get(e.get('type'), e.get('type')) in (
                    'SOCKET_IN_USE', 'SSL_SOCKET_BYTES_SENT', 'SSL_SOCKET_BYTES_RECEIVED')
                or (types.get(e.get('type'), e.get('type')) == 'SSL_CONNECT'
                    and e.get('phase') == end_phase and e.get('params', {}).get('net_error', 0) == 0)
                for e in events)
            for node in component:
                started = sent_hello = sent_bytes = ended = False
                for e in sorted(grouped.get(node, []), key=lambda e: float(e.get('time', 0))):
                    name = types.get(e.get('type'), e.get('type'))
                    params = e.get('params', {})
                    if name == 'SSL_CONNECT' and e.get('phase') == begin_phase:
                        started = True
                    if started and name == 'SSL_HANDSHAKE_MESSAGE_SENT' and params.get('type') == 1:
                        sent_hello = True
                    if sent_hello and name == 'SOCKET_BYTES_SENT' and params.get('byte_count', 0) > 0:
                        sent_bytes = True
                    if sent_bytes and name == 'SOCKET_ALIVE' and e.get('phase') == end_phase:
                        ended = True
                aborted |= started and sent_hello and sent_bytes and ended and not forbidden
        for random, item in hellos.items():
            bv.require(random not in indexed, 'ClientHello random occurs in multiple NetLog components')
            indexed[random] = dict(hello=item, auxiliary_tls_only=auxiliary,
                                   aborted_unused_attempt=aborted,
                                   tls_completed=connected_at is not None,
                                   client_finished_observed=client_finished,
                                   authentication_observed=authentication, http_request_observed=http_request)
    return indexed


def analyze(output, capture, browser_result):
    result = dict(name=browser_result['name'], observed_outcome='INCONCLUSIVE', **{'pass': False},
                  key_establishment=browser_result.get('key_establishment'),
                  key_exchange_group=browser_result.get('tls_group'),
                  signature_profile=browser_result.get('signature_profile'),
                  wire_observed={k: None for k in METRICS},
                  pcap_tls_observed=dict(client_hello_observed=None, decryption_configured=False,
                                         encrypted_handshake_visibility='Not decoded; see semantic_evidence'),
                  semantic_evidence=dict(source='browser-validation classifier, NetLog and server.log',
                                         browser_result=browser_result), reasons=[])
    result['wire_observed'].update(browser_metric_values([], browser_result, {}))
    result['wire_observed']['comparison_definitions'] = COMPARISON_DEFINITIONS
    try:
        bv.require(capture.path is not None and capture.path.is_file(), 'Capture file missing')
        bv.require(capture.clean, 'Capture did not stop cleanly; packet completeness unconfirmed')
        capture_logs = '\n'.join(p.read_text(errors='replace') for p in output.glob('*.stderr.log')
                                 if p.name in ('dumpcap.stderr.log', 'tcpdump.stderr.log'))
        dropped = [int(n) for n in re.findall(r'(\d+) packets dropped by kernel', capture_logs)]
        dropped += [int(n) for n in re.findall(r'Packets dropped: (\d+)', capture_logs)]
        bv.require(not any(dropped), 'Capture tool reported dropped packets')
        tshark = capture.tools['tshark']
        bv.require(tshark, 'tshark unavailable: capture preserved; wire analysis/correlation unavailable')
        if capture.path.suffix == '.pcap':
            converted = output/'capture.pcapng'
            bv.command([tshark, '-n', '-r', capture.path, '-F', 'pcapng', '-w', converted])
            capture.path = converted
        fields = (*ph.FIELDS, 'tcp.seq_raw', 'tcp.flags.fin', 'tcp.flags.reset', 'frame.encap_type')
        cmd = [tshark, '-n', '-r', str(capture.path), '-Y', 'ip.src == 127.0.0.1 && ip.dst == 127.0.0.1 && tcp.port == 4433',
               '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=a', '-E', 'aggregator=,']
        keylog = getattr(capture, 'keylog_path', output/'tls.keys')
        if keylog.is_file() and keylog.stat().st_size:
            cmd += ['-o', 'tls.keylog_file:'+str(keylog)]
            result['pcap_tls_observed'].update(decryption_configured=True, keylog_file=str(keylog),
                keylog_sha256=bv.sha(keylog), encrypted_handshake_visibility='Decoded only where tshark supplies events')
        for field in fields: cmd += ['-e', field]
        bv.write(output/'analysis-command.json', dict(command=cmd))
        with (output/'tshark.tsv').open('x') as out, (output/'tshark.stderr').open('x') as err:
            analysis = subprocess.run(cmd, stdout=out, stderr=err, timeout=60)
        bv.require(analysis.returncode == 0, 'tshark failed; inspect tshark.stderr')
        streams = {}
        with (output/'tshark.tsv').open() as source:
            for row in csv.reader(source, delimiter='\t'):
                bv.require(len(row) == len(fields), 'Incomplete tshark fields')
                values = dict(zip(fields, row))
                frame, sport, dport, stream, seq, syn, ack, length, payload, fin, reset = (
                    values[key] for key in ('frame.number', 'tcp.srcport', 'tcp.dstport', 'tcp.stream',
                    'tcp.seq_raw', 'tcp.flags.syn', 'tcp.flags.ack', 'tcp.len', 'tcp.payload', 'tcp.flags.fin', 'tcp.flags.reset'))
                entry = streams.setdefault(stream, dict(stream=int(stream), client_port=None, segments=[], isn=None,
                                                         first_client_abort_frame=None, last_client_payload_frame=None,
                                                         first_server_payload_frame=None, pcap_rows=[],
                                                         **{k: 0 for k in METRICS}))
                entry['pcap_rows'].append(values)
                direction = 'client_to_server' if dport == '4433' else 'server_to_client'
                port = int(sport if dport == '4433' else dport)
                bv.require(entry['client_port'] in (None, port), 'Ambiguous TCP stream endpoints')
                entry['client_port'] = port
                entry['tcp_packets_'+direction] += 1; entry['tcp_packets_total'] += 1
                entry['tcp_payload_bytes_'+direction] += int(length); entry['tcp_payload_bytes_total'] += int(length)
                entry['tcp_wire_bytes_'+direction] += int(values['frame.len'])
                entry['tcp_wire_bytes_total'] += int(values['frame.len'])
                if dport != '4433' and int(length) and entry['first_server_payload_frame'] is None:
                    entry['first_server_payload_frame'] = int(frame)
                if dport == '4433':
                    if (fin.lower() in ('1', 'true') or reset.lower() in ('1', 'true')) and entry['first_client_abort_frame'] is None:
                        entry['first_client_abort_frame'] = int(frame)
                    if syn.lower() in ('1', 'true') and ack.lower() in ('0', 'false'):
                        entry['isn'] = (int(seq)+1) % (1 << 32)
                    if int(length):
                        entry['last_client_payload_frame'] = int(frame)
                        raw = bytes.fromhex(payload.replace(':', ''))
                        bv.require(len(raw) == int(length), 'Truncated TCP payload')
                        entry['segments'].append((int(seq), raw))
        server = (output/'server.log').read_text(errors='replace')
        server_hellos = {}; early_rejections = set(); post_auth_rejections = set()
        server_hello_lengths = {}; completed = set()
        hello_matches = list(re.finditer(r'^<<< TLS[^\n]*, ClientHello\n((?:    [0-9a-f ]+\n)+)', server, re.M))
        for index, match in enumerate(hello_matches):
            item = hello(bytes.fromhex(match[1])); server_hellos[item['client_random']] = item
            # s_server handles connections sequentially; bound evidence to this ClientHello.
            transcript = server[match.end():hello_matches[index+1].start() if index+1 < len(hello_matches) else len(server)]
            server_hello_lengths[item['client_random']] = len(bytes.fromhex(match[1]))
            if all(re.search(r'^'+direction+r' TLS[^\n]*, Handshake[^\n]*, Finished\s*$', transcript, re.M)
                   for direction in ('>>>', '<<<')):
                completed.add(item['client_random'])
            if (re.search(r'^>>> TLS[^\n]*, Alert[^\n]*, fatal handshake_failure\s*$', transcript, re.M)
                    and not re.search(r'^(?:>>>|<<<) TLS[^\n]*, Handshake[^\n]*, (?:ServerHello|Certificate|CertificateVerify|Finished)\s*$', transcript, re.M)
                    and not re.search(r'ApplicationData|Application Data|^(?:GET|POST|HEAD) ', transcript, re.M)):
                early_rejections.add(item['client_random'])
            if result['name'] in ('mtc-bad-merkle', 'mtc-bad-serial'):
                flight = [re.search(r'^>>> TLS[^\n]*, Handshake[^\n]*, '+name+r'\n((?:    [0-9a-f ]+\n)+)',
                                    transcript, re.M)
                          for name in ('EncryptedExtensions', 'Certificate', 'CertificateVerify', 'Finished')]
                alert = re.search(r'^<<< TLS[^\n]*, Alert[^\n]*, fatal certificate[_ ]unknown\n((?:    [0-9a-f ]+\n)+)',
                                  transcript, re.M)
                if (all(flight) and alert and bytes.fromhex(alert[1]) == b'\x02\x2e'
                        and all(a.end() <= b.start() for a, b in zip(flight, flight[1:]+[alert]))
                        and item['requested_tai_observed']
                        and not re.search(r'^<<< TLS[^\n]*, Handshake[^\n]*, Finished\s*$|ApplicationData|Application Data|^(?:GET|POST|HEAD) ',
                                          transcript, re.M)):
                    # Decrypted semantic evidence comes from s_server, never the encrypted PCAP.
                    ee = base64.b64encode(bytes.fromhex(flight[0][1])).decode('ascii')
                    if bv.encrypted_extensions_selected([
                            ('SSL_HANDSHAKE_MESSAGE_RECEIVED', dict(type=8, bytes=ee), None, None)]):
                        post_auth_rejections.add(item['client_random'])
        url = bv.read(output/'chromium-command.json')['command'][-1]
        net = bv.read(output/'netlog.json')
        events = bv.relevant_netlog(net, url)
        net_connections = netlog_connections(net)
        net_hellos = {}
        for name, params, _, _ in events:
            if name == 'SSL_HANDSHAKE_MESSAGE_SENT' and params.get('type') == 1:
                item = hello(base64.b64decode(params['bytes'], validate=True)); net_hellos[item['client_random']] = item
        matched = []; observations = []; seen = set(); unmatched = []
        for entry in streams.values():
            segments = entry.pop('segments'); isn = entry.pop('isn')
            pcap_rows = entry.pop('pcap_rows')
            entry['capture_encapsulation_types'] = sorted({r['frame.encap_type'] for r in pcap_rows})
            if not segments:
                unmatched.append(entry); continue
            items = plaintext_hellos(segments, isn)
            bv.require(bool(items), 'TCP payload without a complete ClientHello')
            classifications = []; randoms = []; rejected = []; rejected_after = []
            for item in items:
                random = item['client_random']
                bv.require(item['hostname'] == bv.HOST and server_hellos.get(random) == item,
                           'PCAP/server ClientHello mismatch or uncorrelated traffic')
                connection = net_connections.get(random)
                if connection is not None:
                    bv.require(connection['hello'] == item, 'PCAP/NetLog ClientHello contents mismatch')
                early = (result['name'] == 'mtc-no-trust' and random in early_rejections
                         and entry['tcp_payload_bytes_server_to_client'] == 7
                         and connection is not None and not connection['tls_completed']
                         and not connection['authentication_observed'] and not connection['http_request_observed'])
                rejected.append(early)
                after = (result['name'] in ('mtc-bad-merkle', 'mtc-bad-serial')
                         and random in post_auth_rejections and connection is not None
                         and not connection['tls_completed'] and not connection['client_finished_observed']
                         and not connection['http_request_observed'])
                rejected_after.append(after)
                if random in net_hellos:
                    bv.require(net_hellos[random] == item, 'URL-linked ClientHello contents mismatch')
                    classification = 'url_linked'
                elif early:
                    classification = 'rejected_before_server_auth'
                elif after:
                    classification = 'rejected_after_server_auth'
                elif connection is not None and connection['auxiliary_tls_only']:
                    classification = 'auxiliary_tls_only'
                else:
                    classification = 'other_correlated'
                bv.require(random not in seen, 'ClientHello random maps to more than one captured handshake')
                classifications.append(classification); randoms.append(random)
                seen.add(random); observations.append(dict(stream=entry['stream'], **item))
            entry.update(client_random=randoms[0], client_randoms=randoms,
                         rejected_before_server_auth=all(rejected),
                         rejected_after_server_auth=all(rejected_after),
                         requested_tai_observed=all(item['requested_tai_observed'] for item in items),
                         classification=classifications[0] if len(set(classifications)) == 1 else 'other_correlated')
            entry['handshake_metrics'] = handshake_metrics(pcap_rows, entry['client_random'])
            if (entry['classification'] == 'url_linked' and len(items) == 1
                    and randoms[0] in completed and browser_result['pass']
                    and result['name'] in ('mtc-positive', 'x509-positive')):
                entry.update(connection_decomposition(segments, isn, server_hello_lengths[randoms[0]]))
            matched.append(entry)
        bv.require(bool(seen) and seen == set(server_hellos), 'Incomplete PCAP/server connection correlation')
        bv.require(bool(net_hellos) and set(net_hellos) <= seen, 'Missing URL-linked target connection correlation')
        primary = [entry for entry in matched if entry['classification'] == 'url_linked']
        successful_navigation = any(
            len(e['client_randoms']) == 1 and e['client_random'] in completed
            and net_connections.get(e['client_random'], {}).get('tls_completed')
            for e in primary)
        for entry in matched:
            connection = net_connections.get(entry['client_random'], {})
            abort_frame = entry['first_client_abort_frame']
            last_client_payload = entry['last_client_payload_frame']
            first_server_payload = entry['first_server_payload_frame']
            # Strict capture ordering: all client payload (including the complete,
            # correlated ClientHello) precedes abort; every server payload follows.
            # Even retransmitted client payload after abort makes this unavailable.
            abort_before_flight = (abort_frame is not None and last_client_payload is not None
                                   and first_server_payload is not None
                                   and last_client_payload < abort_frame < first_server_payload)
            aborted = (result['name'] in ('mtc-positive', 'x509-positive')
                       and browser_result['pass'] is True and successful_navigation
                       and entry['classification'] == 'other_correlated'
                       and len(entry['client_randoms']) == 1
                       and connection.get('aborted_unused_attempt', False)
                       and entry['client_random'] not in completed
                       and (entry['tcp_payload_bytes_server_to_client'] == 0 or abort_before_flight))
            entry['aborted_before_tls_completion'] = aborted
            entry['abort_before_server_flight'] = aborted and abort_before_flight
            if aborted:
                entry['classification'] = 'aborted_before_tls_completion'
        result['wire_observed'] = dict(**{k: sum(e[k] for e in matched) for k in METRICS},
            **{'url_linked_'+k: sum(e[k] for e in primary) for k in METRICS},
            url_linked_connection_count=len(primary), url_linked_streams=[e['stream'] for e in primary],
            auxiliary_tls_only_connection_count=sum(e['classification'] == 'auxiliary_tls_only' for e in matched),
            aborted_before_tls_completion_connection_count=sum(e['aborted_before_tls_completion'] for e in matched),
            rejected_before_server_auth_connection_count=sum(e['rejected_before_server_auth'] for e in matched),
            rejected_after_server_auth_connection_count=sum(e['rejected_after_server_auth'] for e in matched),
            connection_count=len(matched), captured_connection_count=len(streams), connections=matched,
            connections_without_client_payload=unmatched,
            byte_definition='Observed TCP payload bytes, including retransmissions; excludes all link/IP/TCP headers',
            primary_scope='TCP payload for connections linked by NetLog to the requested navigation',
            browser_session_scope='All target TLS connections correlated between PCAP and server.log')
        result['wire_observed'].update({
            'url_linked_'+key: sum(e[key] for e in primary)
            if primary and all(e.get(key) is not None for e in primary) else None
            for key in DECOMPOSITION})
        result['wire_observed']['decomposition_definitions'] = DECOMPOSITION_DEFINITIONS
        result['wire_observed'].update(browser_metric_values(primary, browser_result, net))
        result['wire_observed']['comparison_definitions'] = COMPARISON_DEFINITIONS
        result['pcap_tls_observed'].update(client_hello_observed=True, client_hellos=observations,
            requested_tai_observed=all(o['requested_tai_observed'] for o in observations))
        case = result['name']
        expected_group = case in ('mtc-positive', 'mtc-bad-merkle', 'mtc-bad-serial')
        if case.startswith('mtc-'):
            bv.require(all(o['requested_tai_observed'] == expected_group for o in observations), 'Unexpected requested TAI in capture')
        if expected_group:
            bv.require(browser_result.get('requested_tai_observed') is True, 'Requested TAI differs from browser classifier')
        bv.require(bool(primary), 'No URL-linked PCAP stream')
        if case == 'mtc-no-trust':
            bv.require(all(e['rejected_before_server_auth'] and e['classification'] in
                           ('url_linked', 'rejected_before_server_auth') for e in matched)
                       and not any(e['tcp_payload_bytes_total'] for e in unmatched),
                       'No-trust attempt lacks correlated early fatal rejection or has unexpected payload')
            bv.require(all(browser_result.get(key) is False for key in (
                'application_data_observed', 'client_finished_observed', 'server_authentication_flight_observed',
                'server_finished_observed', 'requested_tai_observed', 'selected_tai_observed')),
                'No-trust semantic evidence contradicts rejection before server authentication')
        elif case in ('mtc-bad-merkle', 'mtc-bad-serial'):
            bv.require(all(e['rejected_after_server_auth'] and e['classification'] in
                           ('url_linked', 'rejected_after_server_auth') for e in matched)
                       and not any(e['tcp_payload_bytes_total'] for e in unmatched),
                       'Attempt lacks correlated post-server-auth certificate_unknown rejection or has unexpected payload')
            bv.require(all(browser_result.get(key) is True for key in (
                'requested_tai_observed', 'selected_tai_observed', 'server_authentication_flight_observed',
                'server_finished_observed')) and all(browser_result.get(key) is False for key in (
                'client_finished_observed', 'application_data_observed')),
                'Browser semantic evidence contradicts rejection after server authentication')
        else:
            bv.require(not any(e['classification'] == 'other_correlated' for e in matched),
                       'Additional correlated connection lacks sufficient unused TLS-only evidence')
        result.update(observed_outcome=browser_result['observed_outcome'], **{'pass': browser_result['pass']})
    except (ValueError, OSError, KeyError, IndexError, subprocess.SubprocessError) as error:
        result['reasons'].append(str(error))
    save_comparison(output, result)
    result['evidence'] = {p.name: str(p) for p in output.iterdir() if p.is_file()}
    if capture.path is not None and capture.path.is_file():
        result['capture_file'] = str(capture.path)
        result['capture_sha256'] = bv.sha(capture.path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'requirements', 'status', 'run'))
    parser.add_argument('case', nargs='?', choices=(*bv.CASES, 'all'))
    parser.add_argument('--key-establishment', choices=tuple(bv.KEY_ESTABLISHMENTS), default='x25519',
                        help='Group restricted at the server and verified in NetLog (default: x25519)')
    parser.add_argument('--chromium', type=Path)
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--image', default='mt-tls-mtc:local')
    args = parser.parse_args()
    bv.require((args.action == 'run') == bool(args.case), 'run requires CASE; other actions take no case')
    bv.require(5 <= args.timeout <= 300, 'Timeout must be between 5 and 300 seconds')
    tools = requirements()
    if args.action == 'requirements':
        print(json.dumps(tools, indent=2)); return 0
    if args.action == 'plan':
        selected_group = bv.key_establishment_config(args.key_establishment)
        print('PRINT ONLY: reuse browser-validation credentials, server, headless browser and classifier.')
        print('Key establishment: '+selected_group['key_establishment_label']+' ('+selected_group['group']+'); '
              'server restriction and NetLog verify the selected group; Chromium retains its compiled group offer.')
        print('Cases: '+', '.join(bv.CASES))
        print('One capture per case; individual negative runs also capture mtc-positive as their required control.')
        print('Order: validate credentials/hostname -> server -> loopback capture ready -> headless browser -> stop capture -> stop server -> correlate.')
        print('Darwin lo0 / Linux lo; filter: '+FILTER+'; dumpcap preferred, tcpdump fallback; no automatic sudo/install.')
        print('tshark optional: without it, preserve capture and report INCONCLUSIVE. TCP payload totals include retransmissions.')
        print('Capture-only TLS key logging (private tls.keys) permits the shared s_client handshake analyzer.')
        print('connection-metrics.csv: per-stream shared handshake fields plus whole-stream TCP payload/wire totals.')
        print('Browser/NetLog timings are separate; missing/ambiguous metrics stay null, independently of functional PASS.')
        return 0
    if args.action == 'status':
        roots = sorted((bv.REPO/'artifacts/results').glob(PREFIX+'*/summary.json'))
        print(json.dumps(bv.read(roots[-1]), indent=2) if roots else 'NO BROWSER PCAP RESULTS'); return 0
    bv.require(tools['interface'], 'Only Darwin and Linux loopback capture are supported')
    bv.require(tools['dumpcap'] or tools['tcpdump'], tools['instruction'])
    # Share the functional runner lock: both workflows use the same TLS port.
    lock = bv.REPO/'.mt-state/chromium-browser-validation.lock'
    lock.parent.mkdir(exist_ok=True)
    try: lock.mkdir()
    except FileExistsError: raise ValueError('Browser validation locked; inspect active run before retrying')
    selected_group = bv.key_establishment_config(args.key_establishment)
    root = None; summary = dict(overall_pass=False, cases=[], capture_backend=tools,
                                key_establishment=args.key_establishment, tls=selected_group)
    try:
        root = bv.REPO/'artifacts/results'/(PREFIX+bv.stamp()); root.mkdir(parents=True)
        bv.write(root/'owner.json', dict(workflow='mtc.browser-pcap', root=str(root)))
        print('Result directory: '+str(root), flush=True)
        credentials = bv.prepare_credentials(bv.REPO, root, args.image)
        bv.require(credentials['x509']['root_trust']['status'] == 'TRUSTED',
                   'X509 root is not trusted; use browser-validation trust-x509 explicitly')
        bv.check_hostname()
        browser = bv.browser_executable(args.chromium)
        with socket.socket() as sock:
            try: sock.bind(('127.0.0.1', 4433))
            except OSError: raise ValueError('Port 4433 occupied; stop its owner explicitly')
        summary.update(chromium=browser, credentials=credentials, hostname=bv.HOST)
        cases = bv.CASES if args.case == 'all' else (('mtc-positive', args.case) if args.case in bv.CASES[1:4] else (args.case,))
        control = False
        for case in cases:
            output = root/case; capture = Capture(output, tools)
            try:
                for selected, keys in [(credentials['mtc'], [('cert','cert_sha256'), ('key','key_sha256'), ('trust','trust_sha256'), ('anchor','anchor_sha256')]),
                                       (credentials['x509'], [('cert','certificate_sha256'), ('key','key_sha256'), ('root','root_sha256')])]:
                    for pathkey, hashkey in keys:
                        bv.require(bv.sha(selected[pathkey]) == selected[hashkey], 'Credential changed: '+pathkey)
                browser_result = bv.run_case(case, credentials, browser, output, root, args.timeout, control,
                    capture=capture, key_establishment=args.key_establishment)
                bv.write(output/'browser-result.json', browser_result)
                result = analyze(output, capture, browser_result)
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                output.mkdir(exist_ok=True)
                result = dict(name=case, observed_outcome='INCONCLUSIVE', **{'pass': False}, reasons=[str(error)])
            finally:
                capture.stop()
            bv.write(output/'result.json', result); bv.write(output/'summary.json', result)
            summary['cases'].append(result)
            if case == 'mtc-positive': control = result['pass']
            print(case+': '+result['observed_outcome'], flush=True)
        summary['overall_pass'] = all(r['pass'] for r in summary['cases'])
        return 0 if summary['overall_pass'] else 1
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        summary['reason'] = str(error); raise
    finally:
        try:
            if root is not None: bv.write(root/'summary.json', summary)
        finally:
            lock.rmdir()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print('ERROR: '+str(error), file=sys.stderr); sys.exit(1)
