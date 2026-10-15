#!/usr/bin/env python3
"""Synthetic comparison-schema tests; no capture or browser is launched."""
import base64
import copy
import csv
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / 'campaigns/performance/handshake_performance'))
import browser_pcap as pcap
import browser_measurements as measurements
import test_pcap_handshake as shared


def connection(rows=None, random=shared.RANDOM, stream=0):
    rows = shared.fixture() if rows is None else rows
    return dict(stream=stream, client_port=50000 + stream, client_random=random,
                client_randoms=[random], classification='url_linked',
                handshake_metrics=pcap.handshake_metrics(rows, random),
                **{field: 0 for field in pcap.METRICS})


def synthetic_certificate(proof=b'proof', sct=None):
    validity = shared.p.core.seq(
        shared.p.core.der(24, b'20200101000000Z'),
        shared.p.core.der(24, b'20990101000000Z'))
    fields = [shared.p.core.der(0xa0, shared.p.core.integer(2)),
              shared.p.core.integer(1 << 48), shared.p.core.ALG,
              shared.p.core.name('32473.101'), validity,
              shared.p.core.seq(), shared.p.core.seq()]
    if sct is not None:
        extension = shared.p.core.seq(
            shared.p.core.oid('1.3.6.1.4.1.11129.2.4.2'),
            shared.p.core.der(4, sct))
        fields.append(shared.p.core.der(0xa3, shared.p.core.seq(extension)))
    return shared.p.core.certificate(shared.p.core.seq(*fields), proof)


def client_hello(random=shared.RANDOM, requested_tai=None):
    hostname = pcap.bv.HOST.encode('ascii')
    name = b'\0' + len(hostname).to_bytes(2, 'big') + hostname
    sni = len(name).to_bytes(2, 'big') + name
    extensions = b'\0\0' + len(sni).to_bytes(2, 'big') + sni
    if requested_tai is not None:
        raw_id = pcap.bv.core.relid(requested_tai)
        entries = bytes([len(raw_id)]) + raw_id
        payload = len(entries).to_bytes(2, 'big') + entries
        extensions += b'\xca\x34' + len(payload).to_bytes(2, 'big') + payload
    body = (b'\x03\x03' + bytes.fromhex(random) + b'\0\0\x02\x13\x02\x01\0'
            + len(extensions).to_bytes(2, 'big') + extensions)
    return base64.b64encode(b'\x01' + len(body).to_bytes(3, 'big') + body).decode('ascii')


def timing_netlog(target):
    def event(name, source, time, phase=0, **params):
        return dict(type=name, source=dict(id=source), time=str(time), phase=phase, params=params)
    return dict(constants=dict(logEventTypes={}, logEventPhase=dict(PHASE_BEGIN=1, PHASE_END=2)),
                events=[
                    event('URL_REQUEST_START_JOB', 20, 80, 1, url=target,
                          source_dependency=dict(id=10)),
                    event('SSL_CONNECT', 10, 90, 1),
                    event('SSL_HANDSHAKE_MESSAGE_SENT', 10, 100, type=1, bytes=client_hello()),
                    event('SSL_CONNECT', 10, 110, 2, net_error=0, version='TLS 1.3'),
                    event('HTTP_TRANSACTION_SEND_REQUEST', 20, 111, 1),
                    event('HTTP_TRANSACTION_READ_RESPONSE_HEADERS', 20, 125, 2, net_error=0),
                    # An unrelated socket must not supply a start or completion event.
                    event('SSL_CONNECT', 99, 0, 1),
                    event('SSL_CONNECT', 99, 999, 2, net_error=0, version='TLS 1.3'),
                ])


def add_timing_event(net, name, source=10, **params):
    net['events'].append(dict(type=name, source=dict(id=source), time='105',
                              phase=0, params=params))


def auxiliary_netlog(reason, *, used=None, close_time=30, multiple_hellos=False):
    events = [
        dict(type='SSL_HANDSHAKE_MESSAGE_SENT', source=dict(id=1), time='10', phase=0,
             params=dict(type=1, bytes=client_hello())),
        dict(type='SSL_CONNECT', source=dict(id=1), time='20', phase=2,
             params=dict(net_error=0, version='TLS 1.3')),
    ]
    if multiple_hellos:
        events.append(dict(type='SSL_HANDSHAKE_MESSAGE_SENT', source=dict(id=1),
                           time='11', phase=0,
                           params=dict(type=1, bytes=client_hello('cd' * 32))))
    if used == 'url':
        events.append(dict(type='URL_METADATA', source=dict(id=1), time='25', phase=0,
                           params=dict(url='https://server.mtc.example.com:4433/')))
    elif used == 'request':
        events.append(dict(type='HTTP_TRANSACTION_SEND_REQUEST', source=dict(id=1),
                           time='25', phase=1, params={}))
    events.append(dict(type='SOCKET_POOL_CLOSING_SOCKET', source=dict(id=1),
                       time=str(close_time), phase=0, params=dict(reason=reason)))
    return dict(constants=dict(logEventTypes={},
                               logEventPhase=dict(PHASE_BEGIN=1, PHASE_END=2)),
                events=events)


class BrowserComparisonMetricsTests(unittest.TestCase):
    def test_crypto_timings_follow_the_clienthello_dependency_component(self):
        target = 'https://' + pcap.bv.HOST + ':4433/'
        net = timing_netlog(target)
        add_timing_event(net, 'CREDENTIAL_VALIDATION_TIMING',
                         credential_validation_total_ns='9000', credential_type='mtc')
        add_timing_event(net, 'MTC_VERIFICATION_TIMING', mtc_total_ns='7000',
                         merkle_leaf_hash_ns='100', merkle_path_ns='200',
                         merkle_total_ns='350', merkle_proof_ns='200',
                         standalone_signatures_ns='6000',
                         standalone_signature_count='2',
                         standalone_signature_cache_ns='50',
                         standalone_signature_cache_hits='1',
                         standalone_signature_cache_misses='1',
                         verification_mode='standalone', success=True)
        add_timing_event(net, 'SSL_CERTIFICATE_VERIFY_TIMING',
                         certificate_verify_crypto_ns='3000', elapsed_ns='3000',
                         signature_algorithm=1027, success=True)
        # Same event name on a disconnected browser connection must not be mixed in.
        add_timing_event(net, 'SSL_CERTIFICATE_VERIFY_TIMING', source=99,
                         elapsed_ns='999999', signature_algorithm=2052, success=False)
        timings = pcap.netlog_connections(net)[shared.RANDOM]['netlog_timings']
        self.assertEqual(timings['netlog_timing_status'], 'OK')
        self.assertEqual(timings['credential_validation_total_ns'], 9000)
        self.assertEqual(timings['credential_type'], 'mtc')
        self.assertIsNone(timings['x509_signatures_ns'])
        self.assertEqual(timings['mtc_total_ns'], 7000)
        self.assertEqual(timings['merkle_leaf_hash_ns'], 100)
        self.assertEqual(timings['merkle_path_ns'], 200)
        self.assertEqual(timings['merkle_total_ns'], 350)
        self.assertEqual(timings['merkle_proof_ns'], 200)
        self.assertEqual(timings['standalone_signatures_ns'], 6000)
        self.assertEqual(timings['standalone_signature_count'], 2)
        self.assertEqual(timings['standalone_signature_cache_ns'], 50)
        self.assertEqual(timings['mtc_verification_mode'], 'standalone')
        self.assertTrue(timings['mtc_success'])
        self.assertEqual(timings['certificate_verify_crypto_ns'], 3000)
        self.assertEqual(timings['certificate_verify_elapsed_ns'], 3000)
        self.assertEqual(timings['certificate_verify_algorithm'], 1027)
        self.assertTrue(timings['certificate_verify_success'])

    def test_old_netlog_has_null_crypto_timings(self):
        target = 'https://' + pcap.bv.HOST + ':4433/'
        timings = pcap.netlog_connections(
            timing_netlog(target))[shared.RANDOM]['netlog_timings']
        self.assertEqual(timings['netlog_timing_status'], 'UNAVAILABLE')
        self.assertIsNone(timings['netlog_timing_error'])
        for field in pcap.NETLOG_CRYPTO_TIMING_FIELDS:
            self.assertIsNone(timings[field])

    def test_duplicate_timing_kind_is_not_assigned(self):
        target = 'https://' + pcap.bv.HOST + ':4433/'
        net = timing_netlog(target)
        for elapsed in ('1', '2'):
            add_timing_event(net, 'SSL_CERTIFICATE_VERIFY_TIMING', elapsed_ns=elapsed,
                             signature_algorithm=1027, success=True)
        timings = pcap.netlog_connections(net)[shared.RANDOM]['netlog_timings']
        self.assertEqual(timings['netlog_timing_status'], 'ERROR')
        self.assertIn('expected at most one event', timings['netlog_timing_error'])
        self.assertIsNone(timings['certificate_verify_elapsed_ns'])

    def test_zero_duration_is_distinct_from_unexecuted_optional_region(self):
        target = 'https://' + pcap.bv.HOST + ':4433/'
        net = timing_netlog(target)
        add_timing_event(net, 'CREDENTIAL_VALIDATION_TIMING',
                         credential_validation_total_ns='0', credential_type='x509',
                         x509_signatures_ns='0')
        timings = pcap.netlog_connections(net)[shared.RANDOM]['netlog_timings']
        self.assertEqual(timings['credential_validation_total_ns'], 0)
        self.assertEqual(timings['x509_signatures_ns'], 0)
        self.assertIsNone(timings['mtc_total_ns'])

    def test_unique_primary_exports_component_timings_to_comparison_row(self):
        target = 'https://' + pcap.bv.HOST + ':4433/'
        net = timing_netlog(target)
        add_timing_event(net, 'SSL_CERTIFICATE_VERIFY_TIMING', elapsed_ns='3000',
                         signature_algorithm=1027, success=True)
        entry = connection()
        entry['netlog_timings'] = pcap.netlog_connections(
            net)[shared.RANDOM]['netlog_timings']
        values = pcap.browser_metric_values([entry], dict(target_url=target), net)
        self.assertEqual(values['certificate_verify_elapsed_ns'], 3000)
        self.assertEqual(values['certificate_verify_algorithm'], 1027)
        self.assertTrue(values['certificate_verify_success'])
        self.assertEqual(values['netlog_timing_status'], 'OK')

    def test_unused_tls_accepts_only_supported_post_connect_close_reasons(self):
        for reason in ('Socket pool destroyed', 'Network changed'):
            with self.subTest(reason=reason):
                indexed = pcap.netlog_connections(auxiliary_netlog(reason))
                self.assertTrue(indexed[shared.RANDOM]['auxiliary_tls_only'])

    def test_network_change_with_url_or_http_use_is_not_auxiliary(self):
        for used in ('url', 'request'):
            with self.subTest(used=used):
                indexed = pcap.netlog_connections(
                    auxiliary_netlog('Network changed', used=used))
                self.assertFalse(indexed[shared.RANDOM]['auxiliary_tls_only'])
                self.assertEqual(indexed[shared.RANDOM]['http_request_observed'],
                                 used == 'request')

    def test_close_before_tls_completion_is_not_auxiliary(self):
        indexed = pcap.netlog_connections(
            auxiliary_netlog('Network changed', close_time=15))
        self.assertFalse(indexed[shared.RANDOM]['auxiliary_tls_only'])

    def test_component_with_multiple_clienthellos_is_not_auxiliary(self):
        indexed = pcap.netlog_connections(
            auxiliary_netlog('Network changed', multiple_hellos=True))
        self.assertFalse(indexed[shared.RANDOM]['auxiliary_tls_only'])
        self.assertFalse(indexed['cd' * 32]['auxiliary_tls_only'])

    def test_unknown_close_reason_is_not_auxiliary(self):
        indexed = pcap.netlog_connections(auxiliary_netlog('Idle timeout'))
        self.assertFalse(indexed[shared.RANDOM]['auxiliary_tls_only'])

    def test_correlation_failure_diagnostic_identifies_run_and_missing_evidence(self):
        random = 'ab' * 32
        entry = dict(stream=7, client_port=50123, client_randoms=[random],
                     classification='other_correlated',
                     tcp_payload_bytes_client_to_server=123,
                     tcp_payload_bytes_server_to_client=456,
                     first_client_abort_frame=None, first_server_payload_frame=12,
                     last_client_payload_frame=11,
                     aborted_before_tls_completion=False)
        net = {random: dict(tls_completed=True, client_finished_observed=True,
                            authentication_observed=True, http_request_observed=False,
                            auxiliary_tls_only=False, aborted_unused_attempt=False)}
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            pcap.bv.write(output/'measurement-metadata.json', dict(
                phase='warmup', profile='ecdsa-p256', case='mtc-standalone',
                pair_index=1, execution_order=3))
            diagnostic = pcap.correlation_diagnostics(
                output, [entry], [], net, {random})
        self.assertEqual(diagnostic['execution']['case'], 'mtc-standalone')
        self.assertEqual(diagnostic['primary_tcp_streams'], [])
        observed = diagnostic['connections'][0]
        self.assertEqual(observed['tcp_stream'], 7)
        self.assertTrue(observed['evidence'][0]['netlog_tls_completed'])
        self.assertFalse(observed['evidence'][0]['netlog_auxiliary_tls_only'])
        self.assertFalse(observed['evidence'][0]['netlog_aborted_unused_attempt'])

    def test_capture_creates_a_private_session_key_file_without_running_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            capture = pcap.Capture(Path(tmp), dict(dumpcap=None, tcpdump=None, interface='lo0', instruction='manual'))
            with self.assertRaisesRegex(ValueError, 'No capture backend'):
                capture.start()
            self.assertEqual(capture.keylog_path.stat().st_mode & 0o777, 0o600)

    def test_process_duration_is_monotonic_without_launching_a_browser(self):
        child = Mock(pid=123)
        child.wait.return_value = 0
        with tempfile.TemporaryDirectory() as tmp, patch.object(pcap.bv, 'check_hostname'), \
                patch.object(pcap.bv.subprocess, 'Popen', return_value=child), \
                patch.object(pcap.bv.time, 'monotonic', side_effect=[10, 10.125]):
            output = Path(tmp)
            self.assertEqual(pcap.bv.run_browser(['mock-browser'], output, 5), 0)
            self.assertEqual(pcap.bv.read(output/'browser-timing.json')['browser_process_wall_ms'], 125)

    def test_capture_only_command_hands_private_keylog_to_owned_browser(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); output = root/'case'
            capture = SimpleNamespace(keylog_path=output/'tls.keys', prepare_keylog=Mock(),
                                      start=Mock(), stop=Mock())
            def browser(cmd, target, timeout, **kwargs):
                self.assertIn('--ssl-key-log-file='+str(capture.keylog_path.resolve()), cmd)
                self.assertEqual(cmd[-1], 'about:blank')
                self.assertTrue(kwargs['target_url'].startswith('https://'+pcap.bv.HOST+':4433/'))
                kwargs['before_navigation']()
                pcap.bv.write(target/'browser-timing.json', dict(
                    browser_process_wall_ms=125, stabilization_ms=25))
                return 0
            with patch.object(pcap.bv, 'Server'), patch.object(pcap.bv, 'check_hostname'), \
                    patch.object(pcap.bv, 'run_browser', side_effect=browser), \
                    patch.object(pcap.bv, 'classify', return_value={}):
                result = pcap.bv.run_case('x509-positive', dict(mtc=dict(
                    requested_tai='a', selected_tai='b', profile='ecdsa-p256',
                    mode='landmark')),
                    dict(executable='/mock/chromium'), output, root, 5, False, capture=capture)
            self.assertEqual(result['browser_process_wall_ms'], 125)
            self.assertEqual(result['stabilization_ms'], 25)
            capture.prepare_keylog.assert_called_once()
            capture.start.assert_called_once()

    def test_single_extraction_exports_shared_handshake_and_full_stream_wire_cost(self):
        raw = base64.b64decode(client_hello())
        record = b'\x16\x03\x03'+len(raw).to_bytes(2, 'big')+raw
        rows = shared.fixture()
        ch = rows[3]
        ch.update({'tcp.payload': record.hex(), 'tcp.len': str(len(record)),
                   'tls.handshake.length': str(len(raw)-4), 'frame.len': str(len(record)+66)})
        finished = next(r for r in rows if r['frame.number'] == '8')
        finished['tcp.seq'] = str(1+len(record))
        request = next(r for r in rows if r['frame.number'] == '9')
        request.update({'tcp.seq': str(1+len(record)+41), 'tcp.payload': shared.record(35, 32)})
        for row in rows:
            row.update({'ip.src': '127.0.0.1', 'ip.dst': '127.0.0.1', 'tcp.flags.fin': '0',
                        'tcp.flags.reset': '0', 'frame.encap_type': '0'})
            row['tcp.seq_raw'] = str(int(row['tcp.seq'])+(1000 if row['tcp.dstport'] == '4433' else 2000))
        expected = shared.p.analyze_safe(rows, credential_kind='x509')
        self.assertEqual(expected['analysis_status'], 'OK')
        def extraction(cmd, stdout, stderr, timeout):
            fields = [cmd[i+1] for i, value in enumerate(cmd) if value == '-e']
            csv.writer(stdout, delimiter='\t', lineterminator='\n').writerows(
                [[row.get(field, '') for field in fields] for row in rows])
            return SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as tmp, patch.object(pcap.subprocess, 'run', side_effect=extraction) as extract:
            output = Path(tmp); capture = SimpleNamespace(path=output/'capture.pcapng', clean=True,
                tools=dict(tshark='mock-tshark'), keylog_path=output/'tls.keys')
            capture.path.touch(); capture.keylog_path.write_text('synthetic keylog')
            pcap.bv.write(output/'chromium-command.json', dict(
                command=['mock', 'about:blank'], target_url='https://'+pcap.bv.HOST+':4433/'))
            net = timing_netlog('https://'+pcap.bv.HOST+':4433/')
            pcap.bv.write(output/'netlog.json', net)
            (output/'server.log').write_text('<<< TLS 1.3, Handshake, ClientHello\n    '+raw.hex(' ')+'\n'
                '>>> TLS 1.3, Handshake, Finished\n<<< TLS 1.3, Handshake, Finished\n')
            result = pcap.analyze(output, capture, dict(name='x509-positive', observed_outcome='PASS', **{'pass': True}))
            self.assertTrue(result['pass'], result['reasons'])
            extract.assert_called_once()
            self.assertIn('tls.keylog_file:'+str(capture.keylog_path), extract.call_args.args[0])
            wire = result['wire_observed']
            for key in shared.p.METRIC_FIELDS: self.assertEqual(wire[key], expected[key])
            self.assertEqual(wire['tcp_wire_bytes_total'], sum(int(row['frame.len']) for row in rows))
            self.assertGreater(wire['tcp_wire_bytes_total'], wire['connection_handshake_wire_bytes'])
            self.assertTrue((output/'connection-metrics.csv').is_file())

    def test_common_metrics_equal_the_reference_analyzer(self):
        rows = shared.fixture(fragment=True, retransmission=True)
        result = pcap.handshake_metrics(rows, shared.RANDOM)
        self.assertEqual(result, shared.p.analyze_safe(rows))
        self.assertEqual(tuple(result), shared.p.METRIC_FIELDS)

    def test_browser_scenarios_select_the_exact_shared_credential_kind(self):
        cases = (
            (dict(name='x509-positive'), 'x509'),
            (dict(name='mtc-positive', mtc_trust_mode='landmark'), 'mtc-landmark'),
            (dict(name='mtc-positive', mtc_trust_mode='standalone'), 'mtc-standalone'),
            (dict(name='mtc-positive', mtc_trust_mode='landmark',
                  measurement_scenario='mtc-standalone'), 'mtc-standalone'),
        )
        for browser_result, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(pcap.credential_kind(browser_result), expected)
                with patch.object(pcap.ph, 'analyze_safe', return_value={
                        field: (shared.RANDOM if field == 'client_random' else None)
                        for field in pcap.HANDSHAKE_FIELDS}) as analyze:
                    pcap.handshake_metrics([], shared.RANDOM, expected)
                analyze.assert_called_once_with(
                    [], expect_client_certificate=False,
                    credential_kind=expected)

    def test_mtc_modes_extract_proof_and_merkle_path_through_browser_adapter(self):
        for mode, signatures in (
                ('landmark', ()),
                ('standalone', (('32473.101', b'signature'),))):
            with self.subTest(mode=mode):
                proof = shared.p.core.proof(
                    0, 16, (b'a' * 32, b'b' * 32), signatures)
                der = synthetic_certificate(proof)
                rows = shared.fixture()
                rows[4]['tls.handshake.certificate'] = der.hex()
                result = pcap.handshake_metrics(
                    rows, shared.RANDOM, 'mtc-' + mode)
                self.assertEqual(result['analysis_status'], 'OK')
                self.assertEqual(result['tls_server_mtc_proof_bytes'], len(proof))
                self.assertEqual(result['tls_server_mtc_merkle_path_bytes'], 64)
                self.assertEqual(result['tls_server_mtc_merkle_path_hashes'], 2)
                self.assertEqual(result['authentication_components_status'], 'OK')

    def test_x509_sct_present_absent_and_certificate_verify_are_extracted(self):
        for sct, expected in ((None, 0), (b'\x00\x03abc', 5)):
            with self.subTest(sct=sct):
                rows = shared.fixture()
                rows[4]['tls.handshake.certificate'] = synthetic_certificate(
                    sct=sct).hex()
                result = pcap.handshake_metrics(rows, shared.RANDOM, 'x509')
                self.assertEqual(result['tls_server_sct_bytes'], expected)
                self.assertEqual(result['tls_server_certificate_verify_bytes'], 64)
                self.assertEqual(
                    result['tls_server_certificate_verify_signature_bytes'], 56)
                self.assertEqual(result['tls_server_authentication_bytes'], 368)

    def test_missing_structured_der_marks_only_components_unavailable(self):
        result = pcap.handshake_metrics(
            shared.fixture(), shared.RANDOM, 'mtc-landmark')
        self.assertEqual(result['analysis_status'], 'OK')
        self.assertEqual(result['authentication_components_status'], 'UNAVAILABLE')
        self.assertIsNone(result['tls_server_mtc_proof_bytes'])
        self.assertTrue(result['authentication_components_error'])

    def test_ack_with_clienthello_has_no_double_counted_wire_frame(self):
        rows = [row for row in shared.fixture() if row['frame.number'] != '3']
        result = pcap.handshake_metrics(rows, shared.RANDOM)
        self.assertEqual(result['tcp_handshake_wire_bytes'], 546)
        self.assertEqual(result['tls_handshake_wire_bytes'], 1453)
        self.assertEqual(result['connection_handshake_wire_bytes'], 1585)
        self.assertLess(result['connection_handshake_wire_bytes'],
                        result['tcp_handshake_wire_bytes'] + result['tls_handshake_wire_bytes'])

    def test_missing_decrypted_finished_leaves_common_metrics_unavailable(self):
        rows = shared.fixture()
        for row in rows:
            if row['tls.handshake.type'] == '20':
                row['tls.handshake.type'] = ''
                row['tls.handshake.length'] = ''
        result = pcap.handshake_metrics(rows, shared.RANDOM)
        self.assertEqual(result['analysis_status'], 'ERROR')
        self.assertIn('Finished', result['analysis_error'])
        self.assertIsNone(result['tls_clienthello_to_client_finished_ms'])
        self.assertIsNone(result['tls_handshake_wire_bytes'])
        self.assertEqual(result['client_random'], shared.RANDOM)

    def test_mismatched_client_random_rejects_comparison_values(self):
        result = pcap.handshake_metrics(shared.fixture(), 'cd' * 32)
        self.assertEqual(result['analysis_status'], 'ERROR')
        self.assertTrue(result['analysis_error'])
        self.assertIsNone(result['tls_handshake_wire_bytes'])
        self.assertIsNone(result['tcp_handshake_ms'])

    def test_single_primary_preserves_reference_values(self):
        entry = connection()
        result = pcap.browser_metric_values([entry], {'browser_process_wall_ms': 123.5}, {})
        for field in shared.p.METRIC_FIELDS:
            self.assertEqual(result[field], entry['handshake_metrics'][field])
        self.assertEqual(result['browser_process_wall_ms'], 123.5)

    def test_multiple_primary_connections_do_not_sum_common_latencies(self):
        first = connection()
        second_rows = shared.fixture()
        second_random = 'cd' * 32
        for row in second_rows:
            row['tcp.stream'] = '1'
            if row['tls.handshake.random']:
                row['tls.handshake.random'] = second_random
        second = connection(second_rows, second_random, 1)
        result = pcap.browser_metric_values([first, second], {}, {})
        self.assertEqual(result['analysis_status'], 'ERROR')
        self.assertTrue(result['analysis_error'])
        for field in ('tcp_handshake_ms', 'tls_clienthello_to_client_finished_ms',
                      'tls_handshake_wire_bytes', 'tcp_stream', 'client_random'):
            self.assertIsNone(result[field])
        self.assertEqual(first['handshake_metrics']['analysis_status'], 'OK')
        self.assertEqual(second['handshake_metrics']['analysis_status'], 'OK')
        self.assertEqual(second['handshake_metrics']['tcp_stream'], 1)

    def test_browser_netlog_durations_use_correlated_source_events(self):
        target = 'https://' + pcap.bv.HOST + ':4433/'
        result = pcap.browser_metric_values([connection()], dict(target_url=target), timing_netlog(target))
        self.assertEqual(result['browser_ssl_connect_ms'], 20)
        self.assertEqual(result['browser_navigation_to_clienthello_ms'], 20)
        self.assertEqual(result['browser_request_to_response_headers_ms'], 14)
        # The common PCAP duration is from a different clock and remains unchanged.
        self.assertAlmostEqual(result['tcp_handshake_ms'], .045)

    def test_response_headers_phase_none_is_a_valid_completion(self):
        target = 'https://' + pcap.bv.HOST + ':4433/'
        net = timing_netlog(target)
        net['constants']['logEventPhase']['PHASE_NONE'] = 0
        net['events'][5]['phase'] = 0
        result = pcap.browser_metric_values([connection()], dict(target_url=target), net)
        self.assertEqual(result['browser_request_to_response_headers_ms'], 14)

    def test_response_headers_phase_none_rejects_negative_interval(self):
        target = 'https://' + pcap.bv.HOST + ':4433/'
        net = timing_netlog(target)
        net['constants']['logEventPhase']['PHASE_NONE'] = 0
        net['events'][5].update(phase=0, time='100')
        result = pcap.browser_metric_values([connection()], dict(target_url=target), net)
        self.assertIsNone(result['browser_request_to_response_headers_ms'])

    def test_ambiguous_or_failed_netlog_completion_is_not_a_duration(self):
        target = 'https://' + pcap.bv.HOST + ':4433/'
        net = timing_netlog(target)
        net['events'].append(copy.deepcopy(net['events'][4]))
        result = pcap.browser_metric_values([connection()], dict(target_url=target), net)
        self.assertIsNone(result['browser_request_to_response_headers_ms'])
        net = timing_netlog(target)
        net['events'][3]['params']['net_error'] = -1
        result = pcap.browser_metric_values([connection()], dict(target_url=target), net)
        self.assertIsNone(result['browser_ssl_connect_ms'])

    def test_navigation_timing_is_unavailable_for_multiple_clienthellos(self):
        target = 'https://' + pcap.bv.HOST + ':4433/'
        net = timing_netlog(target)
        extra = copy.deepcopy(net['events'][2])
        extra['time'] = '101'
        extra['params']['bytes'] = client_hello('cd' * 32)
        net['events'].append(extra)
        result = pcap.browser_metric_values([connection()], dict(target_url=target), net)
        self.assertIsNone(result['browser_navigation_to_clienthello_ms'])
        self.assertIsNone(result['browser_request_to_response_headers_ms'])

    def test_duplicate_failed_end_does_not_hide_completion_ambiguity(self):
        target = 'https://' + pcap.bv.HOST + ':4433/'
        net = timing_netlog(target)
        duplicate_ssl = copy.deepcopy(net['events'][3])
        duplicate_ssl['params']['net_error'] = -1
        duplicate_headers = copy.deepcopy(net['events'][5])
        duplicate_headers['params']['net_error'] = -1
        net['events'].extend([duplicate_ssl, duplicate_headers])
        result = pcap.browser_metric_values([connection()], dict(target_url=target), net)
        self.assertIsNone(result['browser_ssl_connect_ms'])
        self.assertIsNone(result['browser_request_to_response_headers_ms'])

    def test_csv_preserves_reference_column_order_and_blank_missing_values(self):
        entry = connection()
        entry['handshake_metrics']['tls_handshake_wire_bytes'] = None
        result = dict(name='mtc-positive', wire_observed=dict(connections=[entry]))
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            pcap.save_comparison(output, result)
            with (output / 'connection-metrics.csv').open(newline='') as source:
                reader = csv.DictReader(source)
                self.assertEqual(reader.fieldnames,
                                 ['case', 'signature_profile', 'key_establishment', 'key_exchange_group',
                                  'classification', 'client_port',
                                  *shared.p.METRIC_FIELDS, *pcap.NETLOG_CRYPTO_TIMING_FIELDS,
                                  *pcap.NETLOG_TIMING_DIAGNOSTIC_FIELDS, *pcap.METRICS])
                rows = list(reader)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['case'], 'mtc-positive')
        self.assertEqual(rows[0]['classification'], 'url_linked')
        self.assertEqual(rows[0]['client_random'], shared.RANDOM)
        self.assertEqual(rows[0]['tls_handshake_wire_bytes'], '')
        self.assertEqual(rows[0]['tls_client_handshake_bytes'], '150')
        self.assertEqual(rows[0]['credential_validation_total_ns'], '')

    def test_pilot_csv_retains_nullable_comparisons_and_available_sample_counts(self):
        rows = []
        for pair, durations in ((1, (2.5, 1.5, 1.75)),
                                (2, (3.5, None, 2.75))):
            for case, duration in zip(measurements.CASES, durations):
                row = dict.fromkeys(measurements.META, '')
                row.update({field: 2 for field in measurements.METRICS})
                row.update(dict.fromkeys((*measurements.DECOMPOSITION, *measurements.COMPARISON)))
                row.update(pair=pair, pair_index=pair, case=case, signature_profile='ecdsa-p256',
                           status='PASS', pair_complete=True,
                           tcp_handshake_ms=duration, analysis_status='OK' if duration is not None else 'ERROR')
                rows.append(row)
        # A measured-looking value on an incomplete pair must not enter descriptions.
        rejected = copy.deepcopy(rows[0])
        rejected.update(pair_index=3, status='INCONCLUSIVE', pair_complete=False, tcp_handshake_ms=999)
        rows.append(rejected)
        pairs = []
        for pair, values in ((1, (1.5, 2.5, -1.0)),
                             (2, (None, 3.5, None))):
            paired = dict.fromkeys(measurements.PAIR_FIELDS)
            paired.update(pair=pair, pair_index=pair, signature_profile='ecdsa-p256',
                          execution_order='mtc-positive -> x509-positive')
            for metric in measurements.PRIMARY:
                paired.update(measurements.paired_values({
                    'x509': {metric: 2},
                    'mtc-landmark': {metric: 2},
                    'mtc-standalone': {metric: 2},
                }, metric))
            for suffix, value in zip(('mtc', 'x509', 'delta'), values):
                paired['tcp_handshake_ms_'+suffix] = value
            pairs.append(paired)
        summary = dict(status='PASS', requested_pairs=2, profiles=['ecdsa-p256'],
                       tls=dict(version='TLS 1.3', group='X25519',
                                cipher='TLS_AES_256_GCM_SHA384'),
                       key_establishment='x25519', depth=2)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            measurements.save_outputs(root, summary, rows, pairs)
            with (root/'measurements.csv').open(newline='') as source:
                reader = csv.DictReader(source)
                self.assertEqual(reader.fieldnames,
                                 [*measurements.META, *measurements.METRICS,
                                  *measurements.CSV_DECOMPOSITION, *measurements.CSV_COMPARISON])
                saved_rows = list(reader)
            with (root/'pairs.csv').open(newline='') as source:
                reader = csv.DictReader(source)
                self.assertEqual(reader.fieldnames, list(measurements.PAIR_FIELDS))
                saved_pairs = list(reader)
            with (root/'warmups.csv').open(newline='') as source:
                warmup_fields = csv.DictReader(source).fieldnames
            saved_summary = pcap.bv.read(root/'summary.json')
            report = (root/'README.md').read_text()
            html_report = (root/'report.html').read_text()
        measurement_fields = [*measurements.META, *measurements.METRICS,
                              *measurements.CSV_DECOMPOSITION, *measurements.CSV_COMPARISON]
        for omitted in measurements.CSV_OMITTED:
            self.assertNotIn(omitted, measurement_fields)
            self.assertNotIn(omitted, warmup_fields)
            for suffix in ('mtc', 'x509', 'delta'):
                self.assertNotIn(f'{omitted}_{suffix}', measurements.PAIR_FIELDS)
        retained = [field for field in (*measurements.DECOMPOSITION, *measurements.COMPARISON)
                    if field not in measurements.CSV_OMITTED]
        self.assertEqual([field for field in measurement_fields if field in retained], retained)
        self.assertEqual(saved_rows[4]['tcp_handshake_ms'], '')
        self.assertEqual(saved_pairs[1]['tcp_handshake_ms_mtc'], '')
        self.assertEqual(saved_pairs[1]['tcp_handshake_ms_delta'], '')
        self.assertEqual(saved_pairs[1]['tcp_handshake_ms_x509'], '3.5')
        stats = saved_summary['comparison_statistics']
        stats = stats['ecdsa-p256']
        self.assertEqual(stats['mtc-landmark']['tcp_handshake_ms']['n'], 1)
        self.assertEqual(stats['mtc-landmark']['tcp_handshake_ms']['mean'], 1.5)
        self.assertEqual(stats['x509']['tcp_handshake_ms']['n'], 2)
        self.assertEqual(stats['x509']['tcp_handshake_ms']['mean'], 3)
        self.assertEqual(stats['mtc-standalone']['tcp_handshake_ms']['n'], 2)
        self.assertNotIn('tls_handshake_wire_bytes', stats['mtc-landmark'])
        self.assertIn('## Data dictionary', report)
        self.assertIn('### measurements.csv', report)
        self.assertIn('### warmups.csv', report)
        self.assertIn('### pairs.csv', report)
        self.assertIn('### summary.json', report)
        for field in measurement_fields:
            self.assertIn(f'`{field}`', report)
        for field in measurements.PAIR_FIELDS:
            self.assertIn(f'`{field}`', report)
        for field in saved_summary:
            self.assertIn(f'`{field}`', report)
        self.assertIn('they never mean zero', report)
        self.assertIn('not CertificateVerify', report)
        self.assertIn('left scenario minus right scenario', report)
        self.assertIn('Chromium paired browser measurements', html_report)
        self.assertIn('Performance statistics', html_report)

    def test_three_scenario_order_is_deterministic_and_balanced(self):
        self.assertEqual(measurements.order(1),
                         ('x509', 'mtc-landmark', 'mtc-standalone'))
        self.assertEqual(measurements.order(2),
                         ('mtc-landmark', 'mtc-standalone', 'x509'))
        self.assertEqual(measurements.order(3),
                         ('mtc-standalone', 'x509', 'mtc-landmark'))
        self.assertEqual(measurements.order(4), measurements.order(1))

    def test_warmup_rounds_precede_measured_rounds(self):
        self.assertEqual(measurements.campaign_phases(5, 30),
                         (('warmup', 5), ('measured', 30)))

    def test_all_profile_warmup_and_measurement_totals(self):
        profiles = measurements.CAMPAIGN_PROFILES
        for pairs, warmups, measured, warmup_runs in (
                (1, 1, 18, 18), (3, 1, 54, 18), (30, 5, 540, 90)):
            totals = measurements.campaign_totals(
                profiles, pairs, warmups)
            self.assertEqual(totals['total_measurements'], measured)
            self.assertEqual(totals['total_warmup_runs'], warmup_runs)

    def test_standalone_requested_tai_is_matched_exactly_in_clienthello(self):
        raw = base64.b64decode(client_hello(
            requested_tai='32473.101.2.1.0'))
        with patch.object(pcap.bv, 'REQUESTED', '32473.101.2.1.0'):
            standalone = pcap.hello(raw)
        self.assertTrue(standalone['requested_tai_observed'])
        self.assertEqual(standalone['trust_anchor_ids'][0]['decimal'],
                         '32473.101.2.1.0')
        with patch.object(pcap.bv, 'REQUESTED', '32473.101'):
            wrong_prefix = pcap.hello(raw)
        self.assertFalse(wrong_prefix['requested_tai_observed'])

    def test_landmark_requested_tai_remains_unchanged(self):
        raw = base64.b64decode(client_hello(
            requested_tai='32473.101.2.1.1'))
        with patch.object(pcap.bv, 'REQUESTED', '32473.101.2.1.1'):
            landmark = pcap.hello(raw)
        self.assertTrue(landmark['requested_tai_observed'])

    def test_pair_contains_all_three_comparisons_and_legacy_aliases(self):
        values = {
            'x509': {'metric': 10},
            'mtc-landmark': {'metric': 13},
            'mtc-standalone': {'metric': 15},
        }
        paired = measurements.paired_values(values, 'metric')
        self.assertEqual(paired['metric_delta'], 3)
        self.assertEqual(paired['metric_mtc_landmark_vs_x509_delta'], 3)
        self.assertEqual(paired['metric_mtc_standalone_vs_x509_delta'], 5)
        self.assertEqual(
            paired['metric_mtc_landmark_vs_mtc_standalone_delta'], -2)

    def test_authentication_status_fields_are_never_numeric_or_paired(self):
        for field in ('authentication_components_status',
                      'authentication_components_error'):
            self.assertIn(field, measurements.COMPARISON)
            self.assertNotIn(field, measurements.COMPARISON_NUMERIC)
            self.assertNotIn(field, measurements.CSV_COMPARISON_NUMERIC)
            self.assertFalse(any(name.startswith(field + '_')
                                 for name in measurements.PAIR_FIELDS))

    def test_authentication_data_dictionary_is_complete(self):
        fields = [field for field in shared.p.METRIC_FIELDS
                  if ('certificate_verify' in field or 'mtc_' in field
                      or 'sct_' in field or 'authentication_' in field)]
        for field in fields:
            with self.subTest(field=field):
                value_type, unit, definition = measurements.metric_definition(field)
                self.assertTrue(value_type)
                self.assertTrue(unit)
                self.assertTrue(definition)
        self.assertIn('eight bytes', measurements.metric_definition(
            'tls_server_certificate_verify_bytes')[2])
        self.assertIn('already inside Certificate', measurements.metric_definition(
            'tls_server_authentication_bytes')[2])

    def test_scenario_credentials_never_fall_back_between_modes(self):
        credentials = {
            'x509': {'cert': 'x509'},
            'mtc_landmark': {'cert': 'landmark', 'mode': 'landmark'},
            'mtc_standalone': {'cert': 'standalone', 'mode': 'standalone'},
        }
        for case, expected in (('x509', 'x509'),
                               ('mtc-landmark', 'landmark'),
                               ('mtc-standalone', 'standalone')):
            selected_credentials, validation_case, selected = (
                measurements.scenario_credentials(credentials, case))
            self.assertEqual(selected['cert'], expected)
            self.assertEqual(validation_case, ('x509-positive' if case == 'x509'
                                                else 'mtc-positive'))
            if case != 'x509':
                self.assertIs(selected_credentials['mtc'], selected)
            else:
                self.assertIs(selected_credentials['mtc'],
                              credentials['mtc_landmark'])


if __name__ == '__main__':
    unittest.main()
