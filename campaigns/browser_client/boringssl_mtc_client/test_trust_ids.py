"""Small ID-reader tests; synthetic config prefixes, no TLS or fixture writes."""
import unittest
from trust_ids import configured_ids
from config_formats import (MCA2Authority, MCP2Checkpoint, MTB2Bundle,
                            encode_mca2, encode_mtb2)
import core


def config(log=1, landmark=1):
    first = log << 48
    authority = MCA2Authority('32473.101',
        (('32473.101', b'key-a'), ('32473.201', b'key-b')),
        log, first, first + 15)
    if landmark is None:
        return encode_mca2(authority)
    left, right = b'\x11' * 32, b'\x22' * 32
    checkpoint = MCP2Checkpoint(16, 1, core.H(b'\x01' + left + right),
        (('32473.101', b'a'), ('32473.201', b'b')),
        ((0, 8, left), (8, 16, right)))
    return encode_mtb2(MTB2Bundle(authority, checkpoint, landmark))


class TrustIDs(unittest.TestCase):
    def test_standalone(self):
        ids = configured_ids(config(landmark=None), 'standalone')
        self.assertEqual(ids['selected_id'], '32473.101')
        self.assertEqual(ids['requested_id'], '32473.101')

    def test_individual_and_group(self):
        ids = configured_ids(config(), 'landmark')
        self.assertEqual(ids['selected_id'], '32473.101.1.1.1')
        self.assertEqual(ids['requested_id'], '32473.101.2.1.1')

    def test_coordinates_are_not_hardcoded(self):
        ids = configured_ids(config(7, 129), 'landmark')
        self.assertEqual(ids['selected_id'], '32473.101.1.7.129')
        self.assertEqual(ids['requested_id'], '32473.101.2.7.129')

    def test_no_signaling_landmark_uses_ca(self):
        raw = config(landmark=1)
        bundle = __import__('config_formats').decode_mtb2(raw)
        raw = encode_mtb2(MTB2Bundle(bundle.authority, bundle.checkpoint, None))
        ids = configured_ids(raw, 'landmark')
        self.assertIsNone(ids['landmark_number'])
        self.assertEqual(ids['selected_id'], '32473.101')

    def test_invalid_or_truncated(self):
        for raw in (b'', config()[:10], config()[:-7] + b'\x02'):
            with self.assertRaises(ValueError):
                configured_ids(raw, 'landmark')


if __name__ == '__main__':
    unittest.main()
