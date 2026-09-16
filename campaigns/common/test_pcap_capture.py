"""Shared-core regression checks; no Docker, capture or TLS execution."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import pcap_capture


class SharedCaptureTests(unittest.TestCase):
    def test_canonical_metrics_and_disabled_or_warmup_noop(self):
        self.assertEqual(len(pcap_capture.METRICS), 8)
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            with patch.dict(os.environ, MEASUREMENT_PCAP='0'):
                with pcap_capture.observation(root, 'pq', 0, 0, False, 4433) as key:
                    self.assertIsNone(key)
            with pcap_capture.observation(root, 'pq', 0, 0, True, 4433) as key:
                self.assertIsNone(key)
            self.assertEqual(list(root.iterdir()), [])

    def test_hash_is_content_based(self):
        with tempfile.TemporaryDirectory() as value:
            path = Path(value) / 'handshakes.pcap'
            path.write_bytes(b'pcap')
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            path.write_bytes(b'changed')
            self.assertNotEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_failure_metrics_are_null_in_derived_schema(self):
        with tempfile.TemporaryDirectory() as value:
            root = Path(value)
            (root / 'pcap').mkdir()
            directory = root / 'pcap' / 'sample-0000-pq'
            directory.mkdir()
            pcap_capture.save(directory / 'observation.json', {
                'campaign_id': 'latency-rtt10-c1', 'round_id': 1,
                'scenario': 'pq', 'is_warmup': 0,
            })
            pcap_capture.save(directory / 'capture-status.json', {
                'status': 'CAPTURE_FAILURE', 'error': 'not ready',
            })
            pcap_capture.analyze(root)
            result = json.loads((directory / 'derived.json').read_text())
            self.assertIsNone(result['metrics'])
            self.assertEqual(result['capture_status'], 'CAPTURE_FAILURE')


if __name__ == '__main__':
    unittest.main()
