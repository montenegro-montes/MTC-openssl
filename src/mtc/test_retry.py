"""Deterministic controller/parser tests; no TLS, sockets or fixture writes."""
import json
import subprocess
import unittest
from unittest.mock import patch
import retry

A, B, C = '32473.9.1.1.1', '32473.101.1.1.1', '32473.102.1.1.1'


def completed(requested, supported=B, reason='trust_anchor_mismatch', ok=False, number=1, raw=None):
    ident = retry.encode_id(supported)
    wire = (len(ident)+1).to_bytes(2, 'big') + bytes([len(ident)]) + ident
    native = dict(result='PASS' if ok else 'FAIL', connection_id=f'{number:064x}',
                  session_reused=False, tls_version='TLSv1.3', cipher='TLS_AES_256_GCM_SHA384', negotiated_group=1034)
    stdout = 'MTC_RETRY_RESULT ' + json.dumps(native) + '\n'
    timing = dict(
        connection_id=f'{number:064x}',
        retry_tcp_connect_wall_ms_native=0.1,
        retry_tls_attempt_wall_ms=0.9,
        retry_attempt_wall_ms_native=1.1,
    )
    stdout += 'MTC_RETRY_TIMING ' + json.dumps(timing) + '\n'
    stderr = 'MTC_RETRY_CH ' + json.dumps(dict(requested_id_hex=retry.encode_id(requested).hex())) + '\n'
    stderr += 'MTC_RETRY_EE ' + json.dumps(dict(available_list_hex=raw or wire.hex(), reason=reason)) + '\n'
    if ok:
        stderr += 'MTC verification: OK\n'
    return subprocess.CompletedProcess([], 0 if ok else 1, stdout, stderr)


class RetryTests(unittest.TestCase):
    def execute(self, initial, responses):
        requests = []

        def attempt(requested):
            requests.append(requested)
            return retry.classify_attempt(responses[len(requests)-1], requested)

        report = retry.transaction(initial, B, attempt)
        self.assertEqual(report['attempt_count'], len(requests))
        return report, requests

    def test_A_direct(self):
        r, requests = self.execute(B, [completed(B, reason='compatible', ok=True)])
        self.assertEqual((r['final_result'], r['retry_count'], requests), ('PASS', 0, [B]))

    def test_compatible_group(self):
        group = '32473.101.2.1.1'
        r, requests = self.execute(group, [completed(group, reason='compatible', ok=True)])
        self.assertEqual((r['final_result'], r['retry_count'], requests), ('PASS', 0, [group]))

    def test_individual_classification(self):
        for ident in ('32473.101.1.1.1', '32473.101.1.7.129'):
            self.assertTrue(retry.is_individual_landmark_id(ident))
        for ident in ('32473.101', '32473.101.2.1.1', '32473.101.2.7.129',
                      '32473.101.1.0.1', '32473.101.1.1.0'):
            self.assertFalse(retry.is_individual_landmark_id(ident))

    def test_noninitial_individual_retry_is_not_rewritten_as_group(self):
        target = '32473.101.1.7.129'
        seen = []
        def attempt(ident):
            seen.append(ident)
            return retry.classify_attempt(completed(ident, supported=target,
                reason='compatible' if ident == target else 'trust_anchor_mismatch',
                ok=ident == target, number=len(seen)), ident)
        report = retry.transaction(A, target, attempt)
        self.assertEqual(seen, [A, target])
        self.assertEqual(report['selected_landmark'], target)
        self.assertEqual(report['retry_selected_id'], target)
        self.assertEqual(report['final_result'], 'PASS')

    def test_B_retry_success(self):
        r, requests = self.execute(A, [completed(A), completed(B, reason='compatible', ok=True, number=2)])
        self.assertEqual((r['final_result'], r['retry_count'], requests), ('PASS', 1, [A, B]))
        self.assertEqual(r['retry_selected_id'], B)
        self.assertNotEqual(r['attempt_1_connection_id'], r['attempt_2_connection_id'])
        self.assertAlmostEqual(r['retry_total_tcp_connect_wall_ms_native'], 0.2)
        self.assertAlmostEqual(r['retry_total_tls_attempt_wall_ms'], 1.8)
        self.assertAlmostEqual(r['retry_total_attempt_wall_ms_native'], 2.2)

    def test_C_no_local_common(self):
        r, requests = self.execute(A, [completed(A, supported=C)])
        self.assertEqual((r['final_result'], r['retry_count'], requests), ('FAIL', 0, [A]))
        self.assertEqual(r['failure_reason'], 'no_common_locally_trusted_anchor')

    def test_D_malformed_alternatives(self):
        for wire in ('0000', '000180', '0003028001', '00020181', '00020101ff', 'zz', '00'*84):
            with self.subTest(wire=wire):
                r, requests = self.execute(A, [completed(A, raw=wire)])
                self.assertEqual((r['final_result'], r['retry_count'], requests), ('FAIL', 0, [A]))

    def test_duplicate_alternatives(self):
        ident = retry.encode_id(B)
        body = bytes([len(ident)]) + ident
        wire = (2*len(body)).to_bytes(2, 'big') + body*2
        with self.assertRaises(ValueError):
            retry.available_ids(wire.hex())

    def test_E_second_incompatible(self):
        r, requests = self.execute(A, [completed(A), completed(B, supported=C, number=2)])
        self.assertEqual((r['final_result'], r['retry_count'], requests), ('FAIL', 1, [A, B]))

    def test_generic_alert_cannot_trigger_retry(self):
        response = subprocess.CompletedProcess([], 1, '', 'handshake_failure\n')
        r, requests = self.execute(A, [response])
        self.assertEqual((r['retry_count'], requests), (0, [A]))

    def test_authentication_failure_cannot_trigger_retry(self):
        r, requests = self.execute(B, [completed(B, reason='compatible')])
        self.assertEqual((r['retry_count'], requests), (0, [B]))

    def test_success_needs_authentication_marker(self):
        response = completed(B, reason='compatible', ok=True)
        response.stderr = response.stderr.replace('MTC verification: OK', '')
        r, _ = self.execute(B, [response])
        self.assertEqual(r['final_result'], 'FAIL')

    def test_session_reuse_rejected(self):
        response = completed(B, reason='compatible', ok=True)
        response.stdout = response.stdout.replace('"session_reused": false', '"session_reused": true')
        r, _ = self.execute(B, [response])
        self.assertEqual(r['final_result'], 'FAIL')

    def test_stale_connection_rejected(self):
        r, _ = self.execute(A, [completed(A), completed(B, reason='compatible', ok=True)])
        self.assertEqual(r['final_result'], 'FAIL')

    def test_wrong_clienthello_rejected(self):
        r, requests = self.execute(A, [completed(B)])
        self.assertEqual((r['final_result'], r['retry_count'], requests), ('FAIL', 0, [A]))

    def test_process_timeout_is_nonretryable(self):
        with patch('retry.subprocess.run', side_effect=subprocess.TimeoutExpired([], 12)):
            r = retry.run_native('peer', 'localhost', 4433, 'trust', 'landmark', 'retry.lab', A)
        self.assertEqual(r['reason'], 'transport_or_process_failure')

    def test_id_bounds(self):
        for ident in ('', '01', '1.', '-1', '4294967296', '１'):
            with self.assertRaises(ValueError):
                retry.encode_id(ident)
        for raw in (b'\x81', b'\x80\x01', b'\xff'*10+b'\x7f', b'\0'*81):
            with self.assertRaises(ValueError):
                retry.decode_id(raw)


if __name__ == '__main__':
    unittest.main()
