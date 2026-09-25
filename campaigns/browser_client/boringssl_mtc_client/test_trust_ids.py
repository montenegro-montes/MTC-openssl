"""Small ID-reader tests; synthetic config prefixes, no TLS or fixture writes."""
import unittest
from trust_ids import configured_ids


def config(log=1, landmark=1):
    def vec(raw, width=1):
        return len(raw).to_bytes(width, 'big') + raw
    # Only the metadata reader is tested; these are not cryptographic fixtures.
    return (b'MCF1' + vec(b'32473.101') + b'\x02' +
            2 * (vec(b'32473.101') + vec(b'key', 2)) +
            log.to_bytes(2, 'big') + bytes(16) + landmark.to_bytes(4, 'big'))


class TrustIDs(unittest.TestCase):
    def test_standalone(self):
        ids = configured_ids(config(), 'standalone')
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

    def test_invalid_or_truncated(self):
        for raw in (b'', config()[:10], config(0, 1), config(1, 0)):
            with self.assertRaises(ValueError):
                configured_ids(raw, 'landmark')


if __name__ == '__main__':
    unittest.main()
