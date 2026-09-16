"""Offline bandwidth adapter checks; no measurements or Docker execution."""
import ast
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pcap_adapter import capture_session
from run import enrich

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'campaigns/common'))
import pcap_capture

class BandwidthAdapterTests(unittest.TestCase):
    def test_disabled_path_has_no_capture_operations(self):
        with tempfile.TemporaryDirectory() as d, patch('pcap_adapter.subprocess.run') as process:
            with capture_session(['compose'],Path(d),{},False,1): pass
            process.assert_not_called();self.assertEqual(list(Path(d).iterdir()),[])

    def test_enabled_order_and_driver_failure_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            events=[]
            def command(args,**kwargs): events.append(args);return subprocess.CompletedProcess(args,0)
            env={'MEASUREMENT_RUN_ROOT':'/work/example','MEASUREMENT_CAMPAIGN_ID':'one'}
            with patch('pcap_adapter.subprocess.run',side_effect=command):
                with self.assertRaisesRegex(RuntimeError,'TLS failed'):
                    with capture_session(['compose'],Path(d),env,True,1):
                        events.append(['TLS']);raise RuntimeError('TLS failed')
            self.assertIn('up',events[0]);self.assertEqual(events[1],['TLS'])
            self.assertIn('/opt/pcap-core/pcap_capture.py',events[2]);self.assertIn('analyze',events[2]);self.assertIn('stop',events[3])

    def test_analysis_failure_is_explicit_null(self):
        with tempfile.TemporaryDirectory() as d:
            def command(args,**kw):
                if 'analyze' in args: raise subprocess.CalledProcessError(1,args)
            with patch('pcap_adapter.subprocess.run',side_effect=command):
                with capture_session(['compose'],Path(d),{'MEASUREMENT_RUN_ROOT':'/work','MEASUREMENT_CAMPAIGN_ID':'one'},True,1):pass
            result=json.loads((Path(d)/'pcap-analysis-status.json').read_text())
            self.assertEqual(result['status'],'ANALYSIS_FAILURE');self.assertIsNone(result['metrics'])

    def test_warmups_disabled_and_measured_observation_shared(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ,MEASUREMENT_PCAP='1',MEASUREMENT_CAMPAIGN_ID='one'):
            root=Path(d)
            with pcap_capture.observation(root,'pq',0,0,True,4433) as key:self.assertIsNone(key)
            self.assertEqual(list(root.iterdir()),[])
            directory=root/'pcap/sample-0000-pq'
            def ready(*args):
                if not (directory/'ready.json').exists():pcap_capture.save(directory/'ready.json',{'status':'LISTENING'})
                else:pcap_capture.save(directory/'capture-status.json',{'status':'SUCCESS'})
            with patch.object(pcap_capture,'wait_for',side_effect=ready):
                with pcap_capture.observation(root,'pq',0,0,False,4433) as key:self.assertEqual(key,directory/'tls.keys')
            self.assertEqual(json.loads((directory/'observation.json').read_text())['is_warmup'],0)
            self.assertTrue((directory/'stop').exists())

    def test_native_columns_and_original_columns_survive_enrichment(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'samples.csv'
            path.write_text('transport_total_bytes,handshake_wall_ms,tcp_connect_wall_ms_native,connection_establishment_wall_ms_native\n100,2.5,1.0,4.0\n')
            rows=enrich(path,{'bandwidth_measured_mbps':5},'bandwidth-limited')
            self.assertEqual(rows[0]['handshake_wall_ms'],'2.5');self.assertEqual(rows[0]['tcp_connect_wall_ms_native'],'1.0');self.assertEqual(rows[0]['connection_establishment_wall_ms_native'],'4.0')
            self.assertEqual(rows[0]['transport_total_bytes'],'100')

    def test_stage1_failure_preserves_tls_success_and_null_pcap(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);folder=root/'pcap/sample-0000-pq';folder.mkdir(parents=True)
            random='a'*64
            (root/'samples.csv').write_text('campaign_id,round_id,scenario,is_warmup,client_random\none,1,pq,0,'+random+'\n')
            pcap_capture.save(folder/'observation.json',{'campaign_id':'one','round_id':1,'scenario':'pq','is_warmup':0})
            (folder/'handshakes.pcap').write_bytes(b'synthetic-pcap')
            pcap_capture.save(folder/'capture-status.json',{'status':'SUCCESS','pcap_sha256':hashlib.sha256(b'synthetic-pcap').hexdigest()})
            (folder/'tls.keys').write_text('CLIENT_HANDSHAKE_TRAFFIC_SECRET '+random+' fake\n')
            with patch.object(pcap_capture.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','extractor error')):pcap_capture.analyze(root)
            result=json.loads((folder/'derived.json').read_text())
            self.assertEqual(result['tls_status'],'SUCCESS');self.assertEqual(result['analysis_status'],'ANALYSIS_FAILURE');self.assertIsNone(result['metrics'])

    def test_runner_validation_before_capture_and_inspection_after(self):
        text=(Path(__file__).parent/'run.py').read_text()
        self.assertLess(text.index('probe=parse_probe'),text.index('with capture_session'))
        self.assertLess(text.index('with capture_session'),text.index("directory/'server-qdisc-after.txt'"))
        self.assertIn("env['MEASUREMENT_PCAP']='1' if a.pcap else '0'",text)
        compose=(ROOT/'docker/original_campaigns/compose.network-bandwidth.yaml').read_text()
        self.assertIn('profiles: [pcap]',compose);self.assertIn('network_mode: "service:server"',compose)
        self.assertIn('mt-tls-capture:local',compose)

    def test_frozen_bandwidth_parameters_and_validator(self):
        from run import RTTS,RATES,SCENARIOS,burst,GOODPUT_MIN_RATIO,GOODPUT_MAX_RATIO
        self.assertEqual(RTTS,[10,50,100]);self.assertEqual(RATES,[100,20,10,5,1]);self.assertEqual(len(SCENARIOS),6)
        self.assertEqual(burst(5),6250);self.assertEqual((GOODPUT_MIN_RATIO,GOODPUT_MAX_RATIO),(.8,1.05))
        client=(Path(__file__).parent/'client.sh').read_text()
        self.assertIn('root handle 1: tbf',client);self.assertIn('parent 1:1 handle 10: netem',client)
        self.assertIn('iperf3 -c server -t 4 -O 4 -R -J',client)

if __name__=='__main__': unittest.main()
