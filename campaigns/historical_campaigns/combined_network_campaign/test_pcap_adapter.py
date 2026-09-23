"""Combined composition tests only; no Docker, TLS or scientific analysis."""
import ast,csv,hashlib,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from config import PROFILES,TIMEOUT_SECONDS,burst_bytes
from network import commands,parse_ping,validate_qdisc,validate_throughput
from run import add_fields,design,ensure_failures
from pcap_adapter import capture_session

REPO=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(REPO));sys.path.insert(0,str(REPO/'campaigns/common'))
import pcap_capture as core
from campaigns.common.reporting.adapters import load
from campaigns.common.reporting.render import render
spec=importlib.util.spec_from_file_location('stage1',REPO/'campaigns/historical_campaigns/handshake_capture/analyze.py')
extractor=importlib.util.module_from_spec(spec);spec.loader.exec_module(extractor)
tree=ast.parse((REPO/'campaigns/historical_campaigns/handshake_capture/test_analyze.py').read_text())
fixtures={'FIELDS':extractor.FIELDS};exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='fixture'],type_ignores=[]),'existing-stage1-fixture','exec'),fixtures)
fixture=fixtures['fixture']
tree=ast.parse((REPO/'campaigns/historical_campaigns/packet_loss_campaign/measure.py').read_text())
wrapper=dict(csv=csv,json=json,os=os,subprocess=subprocess,sys=sys,Path=Path,failures=[])
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef)],type_ignores=[]),'existing-loss-wrapper','exec'),wrapper)

class CombinedPCAPTests(unittest.TestCase):
    def test_off_preserves_noop_path(self):
        with tempfile.TemporaryDirectory() as d,patch.object(core.subprocess,'run') as run:
            with capture_session([],Path(d),{},False,1):pass
            run.assert_not_called();self.assertEqual(list(Path(d).iterdir()),[])
        self.assertEqual((design('full')['measured_attempts'],design('full')['warmup_attempts']),(3600,600))

    def test_on_uses_shared_failure_aware_session(self):
        with patch('pcap_adapter.shared_session') as session:
            capture_session([],Path('/unused'),{},True,1)
            session.assert_called_once_with([],Path('/unused'),{},True,1,allow_failed=True)

    def test_warmup_not_captured(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,MEASUREMENT_PCAP='1'):
            with core.observation(Path(d),'pq',0,0,True,4433) as key:self.assertIsNone(key)
            self.assertEqual(list(Path(d).iterdir()),[])

    def observation(self,failed=False,timeout=False):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,MEASUREMENT_PCAP='1',MEASUREMENT_CAMPAIGN_ID='one',MEASUREMENT_RUN_ROOT=d,MEASUREMENT_SEED='402001',LOSS_TARGET_PERCENT='1'):
            root=Path(d)/'one';root.mkdir();folder=root/'pcap/sample-0000-pq';wrapper['failures']=[]
            def ready(*args):core.save(folder/('capture-status.json' if (folder/'ready.json').exists() else 'ready.json'),{'status':'SUCCESS'})
            with patch.object(core,'wait_for',side_effect=ready):
                with core.observation(root,'pq',0,0,False,4433) as key:
                    self.assertEqual(key,folder/'tls.keys')
                    if failed:
                        if timeout:
                            with patch.object(subprocess,'run',side_effect=subprocess.TimeoutExpired([],30,stderr=b'partial')):result=wrapper['loss_run']([], '')
                        else:result=subprocess.CompletedProcess([],1,'','NATIVE_CONNECTION_METRICS {"tcp_connect_wall_ms_native":3,"connection_establishment_wall_ms_native":null}')
                        wrapper['write_failure']('pq',0,0,False,result)
            self.assertTrue((folder/'stop').exists())
            return json.loads((folder/'tls-status.json').read_text())

    def test_measured_success_captured(self):self.assertEqual(self.observation()['status'],'SUCCESS')
    def test_measured_failure_captured(self):self.assertEqual(self.observation(failed=True)['status'],'TLS_MEASUREMENT_FAILURE')
    def test_timeout_finalizes_without_changing_policy(self):
        self.assertEqual(TIMEOUT_SECONDS,30);self.assertEqual(self.observation(failed=True,timeout=True)['failure_reason'],'timeout')

    def test_exception_finalizes_session_before_teardown(self):
        events=[]
        with tempfile.TemporaryDirectory() as d,patch.object(core.subprocess,'run',side_effect=lambda args,**kw:events.append(args)):
            with self.assertRaises(RuntimeError):
                with capture_session([],Path(d),{'MEASUREMENT_RUN_ROOT':'/work','MEASUREMENT_CAMPAIGN_ID':'one'},True,1):raise RuntimeError('driver failed')
        self.assertIn('up',events[0]);self.assertIn('--allow-failed',events[1]);self.assertIn('stop',events[2])

    def test_partial_semantics_reused(self):
        m=extractor.handshake_metrics(fixture()[:4],4433,allow_incomplete=True)
        self.assertEqual(m['tcp_connect_wall_ms'],2);self.assertEqual(m['pcap_analysis_status'],'PARTIAL')
        self.assertIsNone(m['tls_from_pcap_wall_ms']);self.assertIsNone(m['connection_handshake_wall_ms'])
        self.assertIsNone(m['connection_handshake_retransmission_frames']);self.assertEqual(m['capture_retransmission_frames'],0)
        m=extractor.handshake_metrics(fixture()[:1],4433,allow_incomplete=True)
        self.assertIsNone(m['tcp_connect_wall_ms'])

    def test_profiles_unchanged(self):
        self.assertEqual([(n,p['rtt_ms'],p['rate_mbit'],p['loss_percent']) for n,p in PROFILES.items()],
                         [('baseline',10,None,'0'),('wan',50,20,'0.5'),('constrained',100,5,'1'),('adverse',100,1,'2')])

    def test_qdisc_hierarchy_unchanged(self):
        q=commands(PROFILES['constrained'])
        self.assertEqual(q[0],['tc','qdisc','replace','dev','eth0','root','handle','1:','tbf','rate','5mbit','burst','1600','latency','1000ms'])
        self.assertEqual(q[1],['tc','qdisc','replace','dev','eth0','parent','1:1','handle','10:','netem','delay','50ms','loss','1%'])
        self.assertEqual(commands(PROFILES['baseline']),[['tc','qdisc','replace','dev','eth0','root','handle','10:','netem','delay','5ms','loss','0%']])

    def test_impairment_order_and_symmetry_unchanged(self):
        compose=(REPO/'docker/historical_campaigns/compose.network-combined.yaml').read_text()
        client=(Path(__file__).parent/'client.sh').read_text()
        self.assertIn('python3 /opt/network-combined/apply_network.py',compose);self.assertIn('python3 /opt/network-combined/apply_network.py',client)
        self.assertEqual(commands(PROFILES['adverse'])[0][8],'tbf');self.assertEqual(commands(PROFILES['adverse'])[1][9],'netem')

    def test_rtt_validation_preserved(self):
        ping=parse_ping('2 packets transmitted, 2 received, 0% packet loss\n64 bytes time=99.0 ms\n64 bytes time=101.0 ms',2)
        self.assertEqual(ping['measured_rtt_median_ms'],100)
        self.assertIn(">10:raise RuntimeError('RTT",(Path(__file__).parent/'run.py').read_text())

    def test_bandwidth_validation_preserved(self):
        validate_throughput(.5,5);validate_throughput(5.75,5)
        with self.assertRaises(ValueError):validate_throughput(5.76,5)
        with self.assertRaises(ValueError):validate_throughput(0,5)

    def test_loss_validation_preserved(self):
        q='qdisc tbf 1: root rate 5Mbit\nqdisc netem 10: parent 1:1 delay 50ms loss 1%'
        validate_qdisc(q,PROFILES['constrained'])
        with self.assertRaises(ValueError):validate_qdisc(q.replace('loss 1%','loss 2%'),PROFILES['constrained'])

    def test_native_columns_propagate_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'samples.csv';path.write_text('handshake_wall_ms,tcp_connect_wall_ms_native,connection_establishment_wall_ms_native,transport_total_bytes\n4,2,6.5,100\n')
            row=add_fields(path,{'network_profile':'constrained'})[0]
            self.assertEqual((row['handshake_wall_ms'],row['tcp_connect_wall_ms_native'],row['connection_establishment_wall_ms_native'],row['transport_total_bytes']),('4','2','6.5','100'))

    def analyzed(self,root,failed=False,bad_hash=False,wrong_identity=False):
        folder=root/'pcap/sample-0000-pq';folder.mkdir(parents=True)
        core.save(folder/'observation.json',dict(campaign_id='one',round_id=1,scenario='pq',is_warmup=0,order_in_round=1))
        random='a'*64
        if failed:(root/'failures.csv').write_text('campaign_id,round_id,scenario,is_warmup,order_in_round\none,1,'+('other' if wrong_identity else 'pq')+',0,1\n')
        else:
            (root/'samples.csv').write_text('campaign_id,round_id,scenario,is_warmup,client_random\none,1,pq,0,'+random+'\n')
            (folder/'tls.keys').write_text('CLIENT_HANDSHAKE_TRAFFIC_SECRET '+random+' fake\n')
        pcap=b'existing-core-fixture';(folder/'handshakes.pcap').write_bytes(pcap);sha=hashlib.sha256(pcap).hexdigest()
        core.save(folder/'capture-status.json',dict(status='SUCCESS',pcap_sha256='bad' if bad_hash else sha))
        def run(args,**kw):
            self.assertEqual('--allow-incomplete' in args,failed)
            metrics=extractor.handshake_metrics(fixture()[:4] if failed else fixture(),4433,allow_incomplete=failed)
            core.save(folder/'summary.json',dict(pcap_sha256=sha,scenarios=[dict(scenario='pq',**metrics)]))
            return subprocess.CompletedProcess(args,0,'','')
        with patch.object(core.subprocess,'run',side_effect=run):core.analyze(root,allow_failed=True)
        return json.loads((folder/'derived.json').read_text())

    def test_success_pcap_metrics_propagate(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.analyzed(Path(d));self.assertEqual(r['analysis_status'],'SUCCESS')
            self.assertEqual([r['metrics'][k] for k in core.METRICS[:3]],[2,2,4])

    def test_failure_partial_metrics_propagate(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.analyzed(Path(d),failed=True)
            self.assertEqual((r['tls_status'],r['capture_status'],r['analysis_status']),('TLS_MEASUREMENT_FAILURE','SUCCESS','PARTIAL'))
            self.assertEqual(r['association_confidence'],'observation_tuple_only')

    def test_wrong_association_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.analyzed(Path(d),failed=True,wrong_identity=True)
            self.assertEqual(r['analysis_status'],'ANALYSIS_FAILURE');self.assertIsNone(r['metrics'])

    def test_hash_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            r=self.analyzed(Path(d),failed=True,bad_hash=True);self.assertIsNone(r['metrics']);self.assertIn('hash',r['error'])

    def test_output_schema_and_compose_core_mount(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'failures.csv';ensure_failures(path)
            with path.open() as f:self.assertEqual(len(next(csv.reader(f))),14)
        compose=(REPO/'docker/historical_campaigns/compose.network-combined.yaml').read_text()
        self.assertIn('profiles: [pcap]',compose);self.assertIn('network_mode: "service:server"',compose)
        self.assertIn('/opt/measurement/pcap_capture.py:ro',compose)
        text=(Path(__file__).parent/'run.py').read_text()
        self.assertLess(text.index('validate_throughput(throughput'),text.index('with capture_session'))
        self.assertLess(text.index('with capture_session'),text.index("directory/'server-qdisc-after.txt'"))

    def test_reporting_combined_fields_and_signed_delta(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'validation.json').write_text(json.dumps({'profile':'constrained','rtt_ms':100,'rate_mbit':5,'loss_percent':'1','measured_rtt_ms':101,'measured_bandwidth_mbit':4.5,'loss_measured_percent':.5}))
            (Path(d)/'result.json').write_text(json.dumps({'metrics':{'tcp_connect_wall_ms_native':2,'tcp_connect_wall_ms':1,'handshake_wall_ms':4,'tls_from_pcap_wall_ms':5,'connection_establishment_wall_ms_native':6.5,'connection_handshake_wall_ms':6}}))
            page=render(load(d));configured=page.split('<h2>Configured network condition</h2>')[1].split('</section>')[0]
            measured=page.split('<h2>Measured / validated network condition</h2>')[1].split('</section>')[0]
            self.assertIn('constrained',configured);self.assertIn('rate_mbit',configured);self.assertNotIn('measured_bandwidth_mbit',configured)
            self.assertIn('measured_bandwidth_mbit',measured);self.assertIn('measured_rtt_ms',measured)
            self.assertIn('native minus PCAP ms',page);self.assertIn('-1.0',page)

if __name__=='__main__':unittest.main()
