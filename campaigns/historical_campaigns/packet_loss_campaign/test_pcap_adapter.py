"""Failure-aware offline tests: no Docker, packets or TLS attempts."""
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

REPO=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(REPO/'campaigns/common'))
sys.path.insert(0,str(REPO/'campaigns/historical_campaigns/handshake_capture'))
import pcap_capture as core
from analyze import handshake_metrics
from test_analyze import fixture
sys.path.remove(str(REPO/'campaigns/historical_campaigns/handshake_capture'))
from pcap_adapter import capture_session
from network import validate_qdisc

# Load only the real wrapper's functions, without executing its benchmark.
tree=ast.parse((Path(__file__).parent/'measure.py').read_text())
namespace=dict(csv=csv,json=json,os=os,subprocess=subprocess,sys=sys,Path=Path,failures=[])
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef)],type_ignores=[]),'loss-functions','exec'),namespace)

class LossPCAPTests(unittest.TestCase):
    def test_off_is_noop(self):
        with tempfile.TemporaryDirectory() as d,patch.object(core.subprocess,'run') as run:
            with capture_session([],Path(d),{},False,1): pass
            run.assert_not_called();self.assertEqual(list(Path(d).iterdir()),[])

    def test_on_uses_shared_failure_mode_and_finalizes_exception(self):
        events=[]
        with tempfile.TemporaryDirectory() as d,patch.object(core.subprocess,'run',side_effect=lambda args,**kw:events.append(args)):
            with self.assertRaises(TimeoutError):
                with capture_session([],Path(d),{'MEASUREMENT_RUN_ROOT':'/work','MEASUREMENT_CAMPAIGN_ID':'one'},True,1):
                    raise TimeoutError('TLS timeout')
        self.assertIn('up',events[0]);self.assertIn('--allow-failed',events[1]);self.assertIn('stop',events[2])

    def test_observation_failure_and_timeout_stop_even_on_exception(self):
        for error in (RuntimeError('TLS failure'),subprocess.TimeoutExpired([],30)):
            with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,MEASUREMENT_PCAP='1',MEASUREMENT_CAMPAIGN_ID='one'):
                root=Path(d);folder=root/'pcap/sample-0000-pq'
                def ready(*args):
                    core.save(folder/('capture-status.json' if (folder/'ready.json').exists() else 'ready.json'),{'status':'SUCCESS'})
                with patch.object(core,'wait_for',side_effect=ready),self.assertRaises(type(error)):
                    with core.observation(root,'pq',0,0,False,4433):raise error
                self.assertTrue((folder/'stop').exists())
                self.assertEqual(json.loads((folder/'tls-status.json').read_text())['status'],'TLS_MEASUREMENT_FAILURE')

    def test_normal_return_preserves_recorded_failure(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,MEASUREMENT_PCAP='1',MEASUREMENT_CAMPAIGN_ID='one'):
            root=Path(d);folder=root/'pcap/sample-0000-pq'
            with patch.object(core,'wait_for'):
                with core.observation(root,'pq',0,0,False,4433):core.save(folder/'tls-status.json',{'status':'TLS_MEASUREMENT_FAILURE'})
            self.assertEqual(json.loads((folder/'tls-status.json').read_text())['status'],'TLS_MEASUREMENT_FAILURE')
            self.assertTrue((folder/'stop').exists())

    def test_warmup_is_not_captured(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,MEASUREMENT_PCAP='1'):
            with core.observation(Path(d),'pq',0,0,True,4433) as key:self.assertIsNone(key)
            self.assertEqual(list(Path(d).iterdir()),[])

    def test_success_definitions_unchanged(self):
        self.assertEqual(handshake_metrics(fixture(),4433),handshake_metrics(fixture(),4433,allow_incomplete=True))

    def test_tcp_established_without_finished(self):
        m=handshake_metrics(fixture()[:4],4433,allow_incomplete=True)
        self.assertEqual(m['tcp_connect_wall_ms'],2)
        self.assertEqual(m['pcap_analysis_status'],'PARTIAL');self.assertTrue(m['tcp_established_observed'])
        self.assertTrue(m['client_hello_observed']);self.assertFalse(m['client_finished_observed'])
        for key in core.METRICS[1:]:self.assertIsNone(m[key])

    def test_no_establishment_has_no_duration(self):
        for rows in (fixture()[:1],fixture()[:2],fixture()[2:4]):
            m=handshake_metrics(rows,4433,allow_incomplete=True)
            for key in core.METRICS:self.assertIsNone(m[key])
            self.assertFalse(m['tcp_established_observed'])

    def test_partial_retransmissions_use_entire_capture_separate_field(self):
        rows=fixture()[:4]
        rows[-1]['tcp.analysis.retransmission']='1';rows[-1]['tcp.analysis.fast_retransmission']='1'
        m=handshake_metrics(rows,4433,allow_incomplete=True)
        self.assertEqual(m['capture_retransmission_frames'],1);self.assertEqual(m['capture_packet_count'],4)
        self.assertIsNone(m['connection_handshake_retransmission_frames'])

    def test_partial_rejects_malformed_or_ambiguous_evidence(self):
        for key,value in (('ip.len','99999'),('frame.time_epoch','NaN'),('ipv6.src','::1')):
            rows=fixture()[:4];rows[-1][key]=value
            with self.assertRaises(ValueError):handshake_metrics(rows,4433,allow_incomplete=True)
        rows=fixture()[:4];rows[-1]['tcp.stream']='1'
        with self.assertRaises(ValueError):handshake_metrics(rows,4433,allow_incomplete=True)

    def analyze_failed(self,root,duplicate=False,hash_bad=False,summary_bad=False,capture_bad=False,success=False):
        folder=root/'pcap/sample-0000-pq';folder.mkdir(parents=True)
        core.save(folder/'observation.json',dict(campaign_id='one',round_id=1,scenario='pq',is_warmup=0,order_in_round=1))
        (root/'failures.csv').write_text('campaign_id,round_id,scenario,is_warmup,order_in_round\none,1,pq,0,1\n'+('one,1,pq,0,1\n' if duplicate else ''))
        if success:
            (root/'failures.csv').unlink();(root/'samples.csv').write_text('campaign_id,round_id,scenario,is_warmup,client_random\none,1,pq,0,'+'a'*64+'\n')
            (folder/'tls.keys').write_text('CLIENT_HANDSHAKE_TRAFFIC_SECRET '+'a'*64+' fake\n')
        pcap=b'fixture-pcap';(folder/'handshakes.pcap').write_bytes(pcap);sha=hashlib.sha256(pcap).hexdigest()
        core.save(folder/'capture-status.json',dict(status='CAPTURE_FAILURE' if capture_bad else 'SUCCESS',pcap_sha256='bad' if hash_bad else sha))
        def extractor(args,**kw):
            self.assertEqual('--allow-incomplete' in args,not success)
            m=handshake_metrics(fixture() if success else fixture()[:4],4433,allow_incomplete=not success)
            core.save(folder/'summary.json',dict(pcap_sha256='bad' if summary_bad else sha,scenarios=[dict(scenario='pq',**m)]))
            return subprocess.CompletedProcess(args,0,'','')
        with patch.object(core.subprocess,'run',side_effect=extractor):core.analyze(root,allow_failed=True)
        return json.loads((folder/'derived.json').read_text())

    def test_missing_random_unique_failure_partial(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.analyze_failed(Path(d));self.assertEqual((r['tls_status'],r['capture_status'],r['analysis_status']),('TLS_MEASUREMENT_FAILURE','SUCCESS','PARTIAL'))
            self.assertEqual(r['association_confidence'],'observation_tuple_only');self.assertIsNone(r['client_random'])

    def test_duplicate_failure_never_attached(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.analyze_failed(Path(d),duplicate=True);self.assertEqual(r['analysis_status'],'ANALYSIS_FAILURE');self.assertIsNone(r['metrics'])

    def test_hash_chain_fail_closed(self):
        for option in ('hash_bad','summary_bad'):
            with tempfile.TemporaryDirectory() as d:
                r=self.analyze_failed(Path(d),**{option:True});self.assertIsNone(r['metrics']);self.assertIn('hash',r['error'])

    def test_capture_failure_is_not_partial(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.analyze_failed(Path(d),capture_bad=True);self.assertEqual(r['capture_status'],'CAPTURE_FAILURE');self.assertEqual(r['analysis_status'],'NOT_EXECUTED')

    def test_success_shared_analysis(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.analyze_failed(Path(d),success=True);self.assertEqual((r['tls_status'],r['capture_status'],r['analysis_status']),('SUCCESS','SUCCESS','SUCCESS'))

    def test_timeout_bytes_keeps_original_124_accounting(self):
        with patch.object(subprocess,'run',side_effect=subprocess.TimeoutExpired([],30,output=b'out',stderr=b'err')):
            result=namespace['loss_run']([], '')
        self.assertEqual(result.returncode,124);self.assertEqual(result.stdout,'out');self.assertIn('LOSS_TIMEOUT',result.stderr)

    def test_failure_csv_compatible_native_unavailable_and_numeric(self):
        for tcp in (None,1.25):
            with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,MEASUREMENT_RUN_ROOT=d,MEASUREMENT_CAMPAIGN_ID='one',MEASUREMENT_SEED='1',LOSS_TARGET_PERCENT='1',MEASUREMENT_PCAP='1'):
                root=Path(d)/'one';folder=root/'pcap/sample-0000-pq';folder.mkdir(parents=True);namespace['failures']=[]
                stderr='NATIVE_CONNECTION_METRICS '+json.dumps({'tcp_connect_wall_ms_native':tcp,'connection_establishment_wall_ms_native':None})
                namespace['write_failure']('pq',0,0,False,subprocess.CompletedProcess([],1,'',stderr))
                with (root/'failures.csv').open() as f:row=next(csv.DictReader(f))
                self.assertEqual(len(row),13);self.assertNotIn('handshake_wall_ms',row)
                m=json.loads((folder/'native-timing.json').read_text());self.assertEqual(m['tcp_connect_wall_ms_native'],tcp);self.assertIsNone(m['handshake_wall_ms']);self.assertIsNone(m['connection_establishment_wall_ms_native'])

    def test_wrong_tuple_without_random_is_not_attached(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.analyze_failed(root)
            (root/'failures.csv').write_text('campaign_id,round_id,scenario,is_warmup,order_in_round\none,1,other-scenario,0,1\n')
            with patch.object(core.subprocess,'run') as run:
                core.analyze(root,allow_failed=True);run.assert_not_called()
            r=json.loads((root/'pcap/sample-0000-pq/derived.json').read_text())
            self.assertEqual(r['capture_status'],'SUCCESS');self.assertIsNone(r['metrics'])
            self.assertEqual(r['analysis_status'],'ANALYSIS_FAILURE')

    def test_real_timeout_wrapper_normal_return_still_stops_capture(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,MEASUREMENT_RUN_ROOT=d,MEASUREMENT_CAMPAIGN_ID='one',MEASUREMENT_SEED='1',LOSS_TARGET_PERCENT='1',MEASUREMENT_PCAP='1'):
            root=Path(d)/'one';root.mkdir();folder=root/'pcap/sample-0000-pq';namespace['failures']=[]
            def ready(*args):
                core.save(folder/('capture-status.json' if (folder/'ready.json').exists() else 'ready.json'),{'status':'SUCCESS'})
            with patch.object(core,'wait_for',side_effect=ready):
                with core.observation(root,'pq',0,0,False,4433):
                    with patch.object(subprocess,'run',side_effect=subprocess.TimeoutExpired([],30,stderr=b'partial')):
                        result=namespace['loss_run']([], '')
                    namespace['write_failure']('pq',0,0,False,result)
            self.assertTrue((folder/'stop').exists())
            status=json.loads((folder/'tls-status.json').read_text())
            self.assertEqual(status['status'],'TLS_MEASUREMENT_FAILURE');self.assertEqual(status['failure_reason'],'timeout')

    def test_forced_exit_without_complete_native_record_preserves_failure(self):
        for stderr in ('','NATIVE_CONNECTION_METRICS {'):
            with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,MEASUREMENT_RUN_ROOT=d,MEASUREMENT_CAMPAIGN_ID='one',MEASUREMENT_SEED='1',LOSS_TARGET_PERCENT='1',MEASUREMENT_PCAP='1'):
                folder=Path(d)/'one/pcap/sample-0000-pq';folder.mkdir(parents=True);namespace['failures']=[]
                namespace['write_failure']('pq',0,0,False,subprocess.CompletedProcess([],137,'',stderr))
                m=json.loads((folder/'native-timing.json').read_text())
                self.assertIsNone(m['tcp_connect_wall_ms_native']);self.assertIsNone(m['handshake_wall_ms'])
                with (Path(d)/'one/failures.csv').open() as f:self.assertEqual(next(csv.DictReader(f))['returncode'],'137')

    def test_tcpdump_gets_sigint_and_zero_captured_is_failure(self):
        import signal
        for count in (0,2):
            with tempfile.TemporaryDirectory() as d:
                folder=Path(d);core.save(folder/'request.json',{'server_port':4433})
                class Process:
                    returncode=None
                    def poll(self):return self.returncode
                    def send_signal(self,sig):
                        self_signal=sig
                        if self_signal!=signal.SIGINT:raise AssertionError('tcpdump must receive SIGINT')
                        with (folder/'tcpdump.log').open('a') as f:f.write(str(count)+' packets captured\n2 packets received by filter\n')
                    def wait(self,timeout=None):self.returncode=0;return 0
                    def kill(self):self.returncode=-9
                def launch(args,**kw):
                    kw['stderr'].write('listening on eth0\n');kw['stderr'].flush()
                    (folder/'handshakes.pcap').write_bytes(b'p'*50)
                    return Process()
                def wait(predicate,*args):
                    if (folder/'ready.json').exists():(folder/'stop').touch()
                    self.assertTrue(predicate())
                with patch.object(core.subprocess,'Popen',side_effect=launch),patch.object(core,'wait_for',side_effect=wait),patch.object(core.time,'sleep'),patch.object(core.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'packet','')):
                    core.capture_one(folder)
                status=json.loads((folder/'capture-status.json').read_text())
                self.assertEqual(status['status'],'SUCCESS' if count else 'CAPTURE_FAILURE')

    def test_loss_model_and_runner_order_unchanged(self):
        from config import LOSSES,HANDSHAKE_TIMEOUT_SECONDS,SCENARIOS
        self.assertEqual(LOSSES,['0','0.1','0.5','1','2','5']);self.assertEqual(HANDSHAKE_TIMEOUT_SECONDS,30);self.assertEqual(len(SCENARIOS),6)
        validate_qdisc('qdisc netem 8001: root refcnt 2 limit 1000 delay 25ms loss 1%', '1')
        text=(Path(__file__).parent/'run.py').read_text()
        self.assertLess(text.index('probe=parse_ping'),text.index('with capture_session'))
        self.assertLess(text.index('with capture_session'),text.index("directory/'server-qdisc-after.txt'"))
        client=(Path(__file__).parent/'client.sh').read_text();self.assertIn('tc qdisc replace dev eth0 root netem delay 25ms loss',client)

if __name__=='__main__':unittest.main()
