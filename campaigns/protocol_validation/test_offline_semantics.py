"""Small pure-Python tests; no Docker, TLS, OpenSSL, PCAP or fixture generation."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from semantics import decode_id, encode_id, decode_list, encode_list, trust_mapping, timestamp_checks
from negative_cases import classify_validator
from report import layers
from verify_tls_transcript import (exact_messages, signed_input, hkdf_expand_label,
                                   finished, keylog_secrets, certificate_verify, core)


class SemanticsTests(unittest.TestCase):
    def test_id_binary_example_from_draft_section_3(self):
        self.assertEqual(encode_id((32473, 1)), bytes.fromhex('81fd5901'))
        self.assertEqual(decode_id(bytes.fromhex('81fd5901')), (32473, 1))

    def test_noncanonical_and_truncated_ids(self):
        for data in (b'', b'\x80\x01', b'\x81', b'\0'*256):
            with self.subTest(data=data), self.assertRaises(ValueError):
                decode_id(data)

    def test_list_round_trip_keeps_preference_order(self):
        ids = [(32473, 9), (32473, 1)]
        self.assertEqual(decode_list(encode_list(ids), available=True), ids)

    def test_empty_requested_allowed_available_forbidden(self):
        self.assertEqual(decode_list(b'\0\0'), [])
        with self.assertRaises(ValueError):
            decode_list(b'\0\0', available=True)

    def test_bad_vector_lengths(self):
        for value in (b'', b'\0\1', b'\0\1\0', b'\0\2\x02\1'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_list(value)

    def mapping(self, marker=None, mode='landmark'):
        anchor = (32473, 2, 1, 8, 42) if mode == 'landmark' else (32473, 2)
        wire = encode_list([anchor])
        return trust_mapping(wire, wire, [marker if marker is not None else dict(length=0, data=b'')],
                             '32473.2', mode, 8, 42)

    def test_private_individual_not_group(self):
        result = self.mapping()
        self.assertEqual(result['status'], 'PASS_EXPERIMENTAL_CODEPOINT')
        self.assertEqual(result['draft_extension_type'], 'TBD')
        self.assertEqual(result['individual_landmark_id'], '32473.2.1.8.42')
        self.assertEqual(result['landmark_group_id'], '32473.2.2.8.42')
        self.assertFalse(result['landmark_group_advertised'])
        self.assertEqual(result['landmark_group_recommendation']['status'], 'UNRESOLVED')

    def test_wrong_certificate_extension(self):
        for marker in (dict(length=1,data=b'\0'), dict(length=0,data=b'\0'), dict(length=1,data=b'')):
            self.assertEqual(self.mapping(marker)['status'], 'FAIL')

    def test_wrong_anchor(self):
        a = encode_list([(32473, 2, 1, 1, 1)])
        b = encode_list([(32473, 2, 1, 1, 2)])
        self.assertEqual(trust_mapping(a,b,[dict(length=0,data=b'')],'32473.2','landmark',1,1)['status'], 'FAIL')

    def test_standalone_ca_anchor(self):
        self.assertEqual(self.mapping(mode='standalone')['status'], 'PASS_EXPERIMENTAL_CODEPOINT')

    def test_timestamps_not_clock_requirement(self):
        result = timestamp_checks('standalone', (123, b'root', []))
        self.assertEqual(result['mtcproof']['signed_timestamp'], 0)
        self.assertEqual(result['local_policy']['status'], 'LOCAL_POLICY')
        self.assertEqual(result['checkpoint']['signer_assertions']['status'], 'UNRESOLVED')
        self.assertEqual(timestamp_checks('landmark', None)['mtcproof']['status'], 'NOT_APPLICABLE')
        with self.assertRaises(ValueError):
            timestamp_checks('standalone', (1 << 64, b'', []))

    def test_negative_expected_rejection(self):
        observed, validator, _ = classify_validator(1, dict(overall='FAIL',failure_kind='INVALID_OBJECT'))
        self.assertEqual((observed,validator), ('REJECT','FAIL'))
        self.assertEqual('PASS' if observed == 'REJECT' else 'FAIL', 'PASS')

    def test_operational_failure_is_not_expected_rejection(self):
        self.assertEqual(classify_validator(1,dict(overall='FAIL',failure_kind='VALIDATOR_ERROR'))[0], 'ERROR')
        self.assertEqual(classify_validator(0,dict(overall='FAIL',failure_kind='INVALID_OBJECT'))[0], 'ERROR')
        self.assertEqual(classify_validator(0,dict(overall='PASS'))[0], 'ACCEPT')

    def test_historical_reports_remain_readable(self):
        result = layers(dict(overall='PASS',endpoint_authentication=True), dict(overall='PASS'))
        self.assertEqual(result['endpoint_authentication']['status'], 'PASS')
        self.assertEqual(result['trust_anchors_semantic_mapping']['status'], 'NOT_EXECUTED')
        self.assertEqual(result['certificate_verify_independent_verification']['status'], 'NOT_EXECUTED')
        self.assertEqual(result['server_finished_independent_verification']['status'], 'NOT_EXECUTED')


class TranscriptTests(unittest.TestCase):
    @staticmethod
    def raw_capture(empty=False):
        # Multiple repeated handshake keys in one packet emulate jsonraw exactly.
        def packet(types, src, dst, sport, dport):
            values = [('ip.src_raw',src),('ip.dst_raw',dst),('tcp.srcport_raw',sport),('tcp.dstport_raw',dport)]
            entries = [json.dumps(k)+':'+json.dumps([v,0,len(bytes.fromhex(v)),0,0]) for k,v in values]
            for typ in types:
                raw = b'' if empty else bytes([typ,0,0,1,0])
                entries.append('"tls.handshake_raw":'+json.dumps([raw.hex(),0,len(raw),0,0]))
            return '{'+','.join(entries)+'}'
        return '['+','.join([packet([1],'01010101','02020202','a001','1151'),
                             packet([2,8,11,15,20],'02020202','01010101','1151','a001'),
                             packet([20],'01010101','02020202','a001','1151')])+']'

    def test_duplicate_json_keys_preserved(self):
        messages = exact_messages(self.raw_capture())
        self.assertEqual([m['raw'][0] for m in messages], [1,2,8,11,15,20,20])

    def test_missing_exact_bytes_not_reconstructed(self):
        with self.assertRaises(ValueError):
            exact_messages(self.raw_capture(empty=True))

    def test_missing_or_extra_messages_rejected(self):
        for value in (self.raw_capture().replace('0800000100','0d00000100'), '[]'):
            with self.assertRaises(ValueError):
                exact_messages(value)

    def test_cv_signed_input(self):
        transcript = b'handcrafted handshake bytes'
        self.assertEqual(signed_input(transcript), b'\x20'*64+b'TLS 1.3, server CertificateVerify'+b'\0'+hashlib.sha384(transcript).digest())
        self.assertNotEqual(signed_input(transcript), signed_input(transcript+b'\0'))

    def test_sha384_finished_vectors(self):
        # Fixed regression values, cross-computed with explicit HKDF info bytes
        # 00300e746c7331332066696e697368656400 and a one-block HMAC reference.
        key = hkdf_expand_label(bytes(range(48)),b'finished',b'',48)
        self.assertEqual(key.hex(),'fcbe325d88fe0a23ac276c591cdbfe90895612d7c0cbcdb21e3d1ffc20d96ed8148a1610d115f29b6771bccdf7a29fe2')
        result = finished(bytes(range(48)),b'handcrafted handshake bytes')
        self.assertEqual(result.hex(),'f3986b8da949234eaeb12c3fe0acff38f529c07a6be63242b4ca07b25c2a177f1019334787da7cb8c099ba3396fb956a')
        self.assertNotEqual(result,finished(bytes(range(48)),b'handcrafted handshake byteS'))

    def test_secret_selection_by_client_random(self):
        random = b'\x01'*32
        text = 'SERVER_HANDSHAKE_TRAFFIC_SECRET '+random.hex()+' '+('02'*48)
        self.assertEqual(list(keylog_secrets(text,random)), ['SERVER_HANDSHAKE_TRAFFIC_SECRET'])
        self.assertEqual(keylog_secrets(text,b'\0'*32), {})
        with self.assertRaises(ValueError):
            keylog_secrets(text+'\n'+text[:-2]+'03',random)

    def test_signature_verifier_does_not_use_endpoint(self):
        spki = core.seq(core.seq(core.oid('2.16.840.1.101.3.4.3.18')),core.der(3,b'\0test'))
        with patch('verify_tls_transcript.subprocess.run',return_value=SimpleNamespace(returncode=0,stdout=b'',stderr=b'')) as run:
            result = certificate_verify('unused-test-executable',0x0905,spki,b'exact input',b'signature')
            self.assertEqual(result['status'], 'PASS')
            self.assertIn('-rawin',run.call_args.args[0])
        with self.assertRaises(ValueError):
            certificate_verify('unused-test-executable',0x0904,spki,b'input',b'signature')
        self.assertEqual(certificate_verify(None,0x0905,spki,b'input',b'sig')['status'],'NOT_EXECUTED')


if __name__ == '__main__':
    unittest.main()
