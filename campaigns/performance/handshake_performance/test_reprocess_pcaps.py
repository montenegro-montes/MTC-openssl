#!/usr/bin/env python3
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import json
import sys

import reprocess_pcaps as reprocess
import pcap_handshake as pcap


class ReprocessPcapsTests(unittest.TestCase):
    def test_capture_discovery_and_structured_tshark_fields(self):
        with tempfile.TemporaryDirectory() as temporary:
            source=Path(temporary);capture=source/'pcap'/'ecdsa-p256-x509-simple-measured-1'
            capture.mkdir(parents=True);(capture/'handshake.pcap').write_bytes(b'pcap');(capture/'keylog.txt').write_text('secret')
            row={'profile':'ecdsa-p256','case':'x509-simple','phase':'measured','repetition':'1'}
            self.assertEqual(reprocess.capture_directory(source,row),capture)
            completed=subprocess.CompletedProcess([],0,stdout=b'row\n',stderr=b'')
            output=source/'derived.tsv'
            with mock.patch.object(reprocess.subprocess,'run',return_value=completed) as run:
                reprocess.tshark(capture,output,'capture-image')
            command=run.call_args.args[0]
            for field in pcap.STRUCTURED_FIELDS:
                self.assertIn(field,command)
            self.assertEqual(output.read_bytes(),b'row\n')
            self.assertIn('tcp.port==4433,tls',command)
            for preference in reprocess.TSHARK_PREFERENCES:
                self.assertIn(preference+':TRUE',command)

    def test_missing_capture_fails_without_creating_a_substitute(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError,'missing or ambiguous'):
                reprocess.capture_directory(Path(temporary),{
                    'profile':'ecdsa-p256','case':'mtc-simple-landmark',
                    'phase':'measured','repetition':'1'})

    def test_tshark_preferences_are_checked(self):
        completed=subprocess.CompletedProcess([],0,stdout='\n'.join(reprocess.TSHARK_PREFERENCES),stderr='')
        with mock.patch.object(reprocess.subprocess,'run',return_value=completed):
            reprocess.check_tshark('capture-image')
        incomplete=subprocess.CompletedProcess([],0,stdout='',stderr='')
        with mock.patch.object(reprocess.subprocess,'run',return_value=incomplete), self.assertRaisesRegex(ValueError,'lacks required preferences'):
            reprocess.check_tshark('capture-image')

    def test_html_renderer_accepts_absent_http_statistic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);summary=root/'summary.json';report=root/'report.html'
            summary.write_text(json.dumps({'key_establishment':{'id':'x25519','label':'X25519','openssl_group':'X25519'},
                'pcap':{'ecdsa-p256':{'x509-simple':{'key_establishment':{'label':'X25519','openssl_group':'X25519'},
                    'tcp_syn_to_first_application_request_ms':None,
                    'tls_server_certificate_bytes':{'n':1,'mean':440,'sample_stdev':None,'median':440,
                                                     'mean_95_ci_low':None,'mean_95_ci_high':None}}}}}))
            renderer=reprocess.REPO/'bin/renders/handshake-performance.py'
            subprocess.run([sys.executable,str(renderer),str(summary),'--output',str(report),'--mode','run-pcap',
                            '--started-epoch','1','--ended-epoch','2','--kem-id','x25519','--kem-label','X25519',
                            '--kem-group','X25519'],check=True)
            self.assertIn('Server Certificate message',report.read_text())


if __name__=='__main__':
    unittest.main()
