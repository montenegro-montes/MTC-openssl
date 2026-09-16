"""Deterministic ClientHello association checks: no Docker, network, TLS or tshark."""
import csv
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

REPO=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(REPO/'campaigns/original_campaigns/handshake_capture'))
from analyze import client_random_stream
import analyze
from test_analyze import fixture
sys.path.insert(0,str(REPO/'campaigns/common'))
import pcap_capture

RANDOM='ab'*32


class StreamTests(unittest.TestCase):
    def query(self, output, value=RANDOM):
        with patch.object(analyze.subprocess,'run',return_value=Mock(stdout=output)) as call:
            result=client_random_stream(Path('capture.pcap'),value,4434)
        cmd=call.call_args.args[0];expr=cmd[cmd.index('-Y')+1]
        self.assertIn('tls.handshake.type == 1',expr)
        self.assertIn('tcp.dstport == 4434',expr)
        self.assertIn(':'.join(['ab']*32),expr)
        return result

    def test_unique_match(self):self.assertEqual(self.query('7\n'),7)

    def test_retransmitted_hello_same_stream(self):self.assertEqual(self.query('7\n7\n'),7)

    def test_no_match(self):
        with self.assertRaisesRegex(ValueError,'no ClientHello'):self.query('')

    def test_duplicate_streams(self):
        with self.assertRaisesRegex(ValueError,'multiple streams'):self.query('7\n8\n')

    def test_missing_malformed_random(self):
        for value in [None,'','ab','g'*64,'ab '*32]:
            with patch.object(analyze.subprocess,'run') as call:
                with self.assertRaisesRegex(ValueError,'malformed'):client_random_stream(Path('unused'),value,4434)
                call.assert_not_called()

    def test_invalid_stream_output(self):
        with self.assertRaisesRegex(ValueError,'ambiguous'):self.query('7,8\n')

    def extract(self, configured=None):
        rows=fixture()
        for row in rows:row['tcp.stream']='7'
        ack=dict(rows[-1]);ack.update({'frame.number':'99','tcp.stream':'0','tls.handshake.type':''});rows.append(ack)
        buf=io.StringIO();w=csv.DictWriter(buf,fieldnames=analyze.FIELDS);w.writeheader();w.writerows(rows)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'handshakes.pcap').write_bytes(b'offline mocked capture');(root/'tls.keys').write_text('')
            item={'scenario':'pq','server_port':4433}
            if configured is not None:item['tcp_stream']=configured
            (root/'connections.json').write_text(json.dumps([item]))
            with patch.object(sys,'argv',['analyze.py',str(root),'--client-random',RANDOM]), patch.object(analyze.subprocess,'run',side_effect=[Mock(stdout=buf.getvalue(),stderr=''),Mock(stdout='7\n')]):
                analyze.main()
            return json.loads((root/'summary.json').read_text())['scenarios'][0]

    def test_unrelated_ack_and_matching_stream(self):
        result=self.extract()
        self.assertEqual(result['tcp_stream'],7);self.assertEqual(result['client_random'],RANDOM)
        self.assertEqual(result['packets'],6)  # unrelated stream is excluded by exact identity

    def test_configured_stream_conflict(self):
        with self.assertRaisesRegex(ValueError,'conflicts'):self.extract(configured=0)

    def test_shared_core_rejects_wrong_extractor_random(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);d=root/'pcap/sample-0000-pq';d.mkdir(parents=True)
            identity=dict(campaign_id='one',round_id=1,round=0,scenario='pq',order_in_round=1,is_warmup=0)
            (d/'observation.json').write_text(json.dumps(identity));pcap=d/'handshakes.pcap';pcap.write_bytes(b'mock');digest=hashlib.sha256(pcap.read_bytes()).hexdigest()
            (d/'capture-status.json').write_text(json.dumps({'status':'SUCCESS','pcap_sha256':digest}))
            (d/'tls.keys').write_text('CLIENT_RANDOM '+RANDOM+' '+'cd'*48+'\n')
            with (root/'samples.csv').open('w') as f:
                row=dict(identity,client_random=RANDOM);w=csv.DictWriter(f,fieldnames=list(row));w.writeheader();w.writerow(row)
            metrics=dict(scenario='pq',tcp_stream=7,client_random='ef'*32)
            (d/'summary.json').write_text(json.dumps({'pcap_sha256':digest,'scenarios':[metrics]}))
            with patch.dict(pcap_capture.os.environ,MEASUREMENT_PCAP_CLIENT_RANDOM_STREAM='1'),patch.object(pcap_capture.subprocess,'run',return_value=Mock(returncode=0,stdout='',stderr='')) as call:
                pcap_capture.analyze(root)
            self.assertIn('--client-random',call.call_args.args[0])
            result=json.loads((d/'derived.json').read_text());self.assertEqual(result['analysis_status'],'ANALYSIS_FAILURE');self.assertIn('association mismatch',result['error'])

if __name__=='__main__':unittest.main()
