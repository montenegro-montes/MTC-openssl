"""Focused typed-config tests; no browser, Docker, network, or fixture writes."""

import unittest

import core
from config_formats import (MCA2Authority, MCP2Checkpoint, MTB2Bundle,
                            encode_mtb2)
from export_chromium_anchor import parse_landmark


def bundle(*, log=2, landmark=(1 << 32), signatures=None):
    first = log << 48
    authority = MCA2Authority(
        '32473.101',
        (('32473.101', b'opaque-ca-spki'),
         ('32473.201', b'opaque-cosigner-spki')),
        log, first, first + 15)
    left, right = b'\x11' * 32, b'\x22' * 32
    checkpoint = MCP2Checkpoint(
        16, 1, core.H(b'\x01' + left + right),
        signatures or (('32473.101', b'a'), ('32473.201', b'b')),
        ((0, 8, left), (8, 16, right)))
    return encode_mtb2(MTB2Bundle(authority, checkpoint, landmark))


class TypedChromiumAnchorTests(unittest.TestCase):
    def test_explicit_mtb2_signaling_identity(self):
        anchor = parse_landmark(bundle())
        self.assertEqual(anchor['source_format'], 'MTB2')
        self.assertEqual(anchor['log_number'], 2)
        self.assertEqual(anchor['landmark']['number'], 1 << 32)
        self.assertEqual(anchor['landmark']['requested_trust_anchor_id'],
                         '32473.101.2.2.4294967296')
        self.assertEqual(anchor['landmark']['selected_trust_anchor_id'],
                         '32473.101.1.2.4294967296')

    def test_missing_signaling_landmark_rejected(self):
        with self.assertRaisesRegex(ValueError, 'no signaling landmark'):
            parse_landmark(bundle(landmark=None))

    def test_malformed_mtb2_rejected(self):
        raw = bundle()
        for malformed in (raw[:-1], raw + b'\0', b'MCF1' + raw[4:]):
            with self.subTest(length=len(malformed)), self.assertRaises(ValueError):
                parse_landmark(malformed)

    def test_signature_bytes_are_exported_but_not_trusted_by_exporter(self):
        anchor = parse_landmark(bundle(signatures=(
            ('32473.101', b'not-valid'), ('32473.201', b'not-valid'))))
        self.assertGreater(anchor['landmark']['checkpoint_signatures_bytes'], 0)


if __name__ == '__main__':
    unittest.main()
