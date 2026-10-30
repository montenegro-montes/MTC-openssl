"""Offline s_server command contract; no subprocesses or TLS connections."""
from pathlib import Path
import unittest

from capture import client_command, fixture_hostname, server_command


class ServerPairCommandTests(unittest.TestCase):
    def test_pair_reuses_one_key_and_registers_both_credentials(self):
        fixture = Path('/fixture')
        manifest = dict(ca_id='32473.101', log_number=1, latest_landmark=1)
        pair = server_command(fixture, 'landmark', 0, manifest, True)
        self.assertEqual(pair[pair.index('-cert')+1], '/fixture/standalone-0000.pem')
        self.assertEqual(pair[pair.index('-mtc_id')+1], '32473.101')
        self.assertEqual(pair[pair.index('-mtc_landmark_id')+1], '32473.101.1.1.1')
        self.assertEqual(pair[pair.index('-mtc_landmark_cert')+1],
                         '/fixture/landmark-0000.pem')
        self.assertEqual(pair[pair.index('-key')+1],
                         pair[pair.index('-mtc_landmark_key')+1])
        self.assertIn('-mtc_standalone_trust', pair)
        self.assertIn('-mtc_landmark_trust', pair)
        self.assertNotIn('-mtc_landmark', pair)
        legacy = server_command(fixture, 'landmark', 0, manifest)
        self.assertEqual(legacy[legacy.index('-cert')+1],
                         '/fixture/landmark-0000.pem')
        self.assertNotIn('-mtc_standalone_trust', legacy)

    def test_landmark_pair_requires_retained_rp_state(self):
        fixture = Path('/fixture')
        pair = client_command(fixture, 'landmark', 'server.mtc.example.com', True)
        self.assertIn('-mtc_landmark', pair)
        self.assertEqual(pair[pair.index('-mtc_trusted_subtrees')+1],
                         '/capture/rp-state/generations/validated/trusted-subtrees.mts1')
        self.assertEqual(pair[pair.index('-mtc_trust')+1], '/fixture/trust.bin')
        legacy = client_command(fixture, 'landmark', 'server.mtc.example.com')
        self.assertNotIn('-mtc_trusted_subtrees', legacy)
        standalone = client_command(fixture, 'standalone',
                                    'server.mtc.example.com', True)
        self.assertNotIn('-mtc_trusted_subtrees', standalone)

    def test_pair_leaf_zero_uses_manifest_hostname(self):
        manifest={'server_hostname':'server.mtc.example.com'}
        self.assertEqual(fixture_hostname(manifest,0,True),
                         'server.mtc.example.com')
        self.assertEqual(fixture_hostname(manifest,1,True),'member-1.lab')
        self.assertEqual(fixture_hostname(manifest,0,False),'server')
        with self.assertRaises(ValueError):
            fixture_hostname({},0,True)


if __name__ == '__main__':
    unittest.main()
