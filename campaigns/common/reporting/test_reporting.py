import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch
from .adapters import load, digest
from .render import render, fmt

class ReportingTest(unittest.TestCase):
    def make(self, directory, **records):
        for name,value in records.items(): (Path(directory)/name).write_text(json.dumps(value))
        return load(directory)

    def test_native_smoke(self):
        with tempfile.TemporaryDirectory() as d:
            model=self.make(d,**{'result.json':{'status':'PASS','integration_smoke_only':True,'scientific_measurement':False,'pcap_enabled':False,'values':{'tcp_connect_wall_ms_native':.19775,'handshake_wall_ms':.811625,'connection_establishment_wall_ms_native':1.040667}}})
            page=render(model)
            for value in ('0.197750','0.811625','1.040667'): self.assertIn(value,page)
            self.assertIn('INTEGRATION SMOKE — NOT SCIENTIFIC PERFORMANCE DATA',page)
            self.assertFalse(model['pcap_present'])

    def test_pcap(self):
        with tempfile.TemporaryDirectory() as d:
            model=self.make(d,**{'summary.json':{'scenarios':[{'scenario':'one','tcp_connect_wall_ms':10,'tls_from_pcap_wall_ms':20,'connection_handshake_wall_ms':32,'connection_handshake_packets':8}]}})
            self.assertTrue(model['pcap_present']);self.assertIn('PCAP timing',render(model))
            self.assertNotIn('Native boundaries',render(model))

    def test_null_and_legacy(self):
        with tempfile.TemporaryDirectory() as d:
            model=self.make(d,**{'metadata.json':{'scenario':'old','handshake_wall_ms':None}})
            page=render(model)
            self.assertIn('unavailable',page);self.assertNotIn('PCAP timing',page)
            self.assertIsNone(model['flags']['scientific_measurement'])

    def test_failures(self):
        with tempfile.TemporaryDirectory() as d:
            model=self.make(d,**{'result.json':{'status':'FAIL'},'validation.json':{'passed':False}})
            self.assertTrue(model['warnings']);self.assertIn('FAILURE',render(model))
            (Path(d)/'failures.csv').write_text('scenario,is_warmup,error\none,0,rejected\n')
            self.assertIn('rejected',render(load(d)))

    def test_escaping(self):
        with tempfile.TemporaryDirectory() as d:
            page=render(self.make(d,**{'metadata.json':{'scenario':'<script>alert(1)</script>','error':'<img src=x onerror=evil()>'}}))
            self.assertNotIn('<script>',page);self.assertNotIn('<img src=x',page)
            self.assertIn('&lt;script&gt;',page)

    def test_formatting(self):
        self.assertEqual(fmt(.19775,'tcp_connect_wall_ms_native'),'0.197750')
        self.assertEqual(fmt(None),'unavailable');self.assertEqual(fmt(0,'handshake_wall_ms'),'0.000000')

    def test_offline_and_preservation(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'result.json';p.write_text('{"status":"PASS"}');before=digest(p)
            with patch.object(socket,'socket',side_effect=AssertionError('Network forbidden')):
                page=render(load(d))
            self.assertEqual(before,digest(p))
            self.assertNotIn('http://',page);self.assertNotIn('https://',page)
            self.assertNotIn('<script',page);self.assertIn('canonical scientific records',page)

    def test_integrity_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'handshakes.pcap').write_bytes(b'example')
            model=self.make(d,**{'capture-status.json':{'status':'SUCCESS','pcap_sha256':'wrong'}})
            self.assertFalse(model['integrity'][0]['hash_match'])
            self.assertIn('INTEGRITY FAILURE',render(model))

    def test_jsonl_adapter(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'pcap-metrics.jsonl').write_text(json.dumps({'client_random':'abc','capture_status':'SUCCESS','metrics':{'tcp_connect_wall_ms':2}})+'\n')
            model=load(d);self.assertEqual(model['metrics'][0][1]['client_random'],'abc')

    def test_capture_status_not_global_success(self):
        with tempfile.TemporaryDirectory() as d:
            model=self.make(d,**{'capture-status.json':{'status':'SUCCESS'}})
            self.assertIn('PARTIAL',model['status'])

    def test_cli_rejects_source_output_and_existing_output(self):
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); source=root/'source';source.mkdir()
            (source/'result.json').write_text('{"status":"PASS"}')
            invalid=subprocess.run([sys.executable,'-m','campaigns.common.reporting',str(source),'--output',str(source/'report.html')],capture_output=True,text=True)
            self.assertNotEqual(invalid.returncode,0);self.assertFalse((source/'report.html').exists())
            target=root/'report.html';target.write_text('preserve')
            existing=subprocess.run([sys.executable,'-m','campaigns.common.reporting',str(source),'--output',str(target)],capture_output=True,text=True)
            self.assertNotEqual(existing.returncode,0);self.assertEqual(target.read_text(),'preserve')

if __name__=='__main__': unittest.main()
