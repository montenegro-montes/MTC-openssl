#!/usr/bin/env python3
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name('chromium.py')


class ChromiumRendererTest(unittest.TestCase):
    def render(self, summary):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source = root/'summary.json'
        output = root/'report.html'
        source.write_text(json.dumps(summary))
        subprocess.run([sys.executable, str(SCRIPT), str(source), '--output', str(output)], check=True, capture_output=True, text=True)
        return output.read_text()

    def test_renders_validation_and_measurement_schemas(self):
        validation = self.render({'overall_pass': True, 'hostname': 'server.mtc.example.com', 'cases': [{
            'name': 'mtc-positive', 'signature_profile': 'ecdsa-p256', 'mtc_trust_mode': 'standalone',
            'expected_outcome': 'accept', 'observed_outcome': 'PASS', 'pass': True,
            'negotiated_canonical_tls': True, 'server_authentication_flight_observed': True,
            'server_finished_observed': True, 'client_finished_observed': True,
            'application_data_observed': True, 'requested_tai_observed': True, 'selected_tai_observed': True,
        }]})
        self.assertIn('Functional validation', validation)
        self.assertIn('TLS authentication evidence', validation)

        stats = {'n': 3, 'mean': 12.5, 'sample_stdev': 1.0, 'median': 12, 'minimum': 11, 'maximum': 14}
        measurement = self.render({'status': 'PASS', 'profiles': ['ecdsa-p256'], 'scenarios': ['x509'],
            'comparison_statistics': {'ecdsa-p256': {'x509': {'tls_server_certificate_bytes': stats}}},
            'descriptive_statistics': {}, 'paired_delta_statistics': {}})
        self.assertIn('Performance statistics', measurement)
        self.assertIn('tls_server_certificate_bytes', measurement)
        self.assertIn('<svg', measurement)
        self.assertIn('Experimental evidence', measurement)


if __name__ == '__main__':
    unittest.main()
