"""Small offline integration tests. No Docker or live TLS traffic."""
import ast
import csv
import json
import os
import shutil
import struct
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
import capture


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.env=patch.dict(os.environ,MEASUREMENT_PCAP='1',MEASUREMENT_CAMPAIGN_ID='campaign-01')
        self.env.start(); self.addCleanup(self.env.stop)

    def observation_fixture(self):
        directory=self.root/'pcap'/'sample-0000-pq'; directory.mkdir(parents=True)
        capture.save(directory/'observation.json',dict(campaign_id='campaign-01',round_id=1,scenario='pq',is_warmup=0))
        (directory/'handshakes.pcap').write_bytes(b'synthetic-pcap')
        pcap_hash=capture.hashlib.sha256((directory/'handshakes.pcap').read_bytes()).hexdigest()
        capture.save(directory/'capture-status.json',dict(status='SUCCESS',pcap_sha256=pcap_hash))
        (directory/'tls.keys').write_text('CLIENT_HANDSHAKE_TRAFFIC_SECRET abc secret\n')
        with (self.root/'samples.csv').open('w') as f:
            writer=csv.DictWriter(f,fieldnames=['campaign_id','round_id','scenario','is_warmup','client_random'])
            writer.writeheader();writer.writerow(dict(campaign_id='campaign-01',round_id=1,scenario='pq',is_warmup=0,client_random='abc'))
        return directory

    def test_disabled_and_warmup_do_nothing(self):
        with patch.dict(os.environ,MEASUREMENT_PCAP='0'):
            with capture.observation(self.root,'pq',0,0,False,4433) as key: self.assertIsNone(key)
        with capture.observation(self.root,'pq',0,0,True,4433) as key: self.assertIsNone(key)
        self.assertEqual(list(self.root.iterdir()),[])

    def test_lifecycle_association_and_tls_failure(self):
        def reply(predicate,seconds=8):
            d=next((self.root/'pcap').iterdir())
            if (d/'stop').exists(): capture.save(d/'capture-status.json',dict(status='SUCCESS'))
            else: capture.save(d/'ready.json',dict(status='LISTENING'))
            self.assertTrue(predicate())
        with patch.object(capture,'wait_for',side_effect=reply):
            with self.assertRaisesRegex(RuntimeError,'TLS failed'):
                with capture.observation(self.root,'pq',2,4,False,4433) as key:
                    self.assertEqual(key.name,'tls.keys'); raise RuntimeError('TLS failed')
        d=next((self.root/'pcap').iterdir())
        identity=json.loads((d/'observation.json').read_text())
        self.assertEqual((identity['campaign_id'],identity['round_id'],identity['order_in_round']),('campaign-01',3,5))
        self.assertTrue((d/'stop').exists())
        self.assertEqual(json.loads((d/'tls-status.json').read_text())['status'],'TLS_MEASUREMENT_FAILURE')

    def test_capture_timeout_preserves_tls(self):
        with patch.object(capture,'wait_for',side_effect=TimeoutError('not ready')):
            with capture.observation(self.root,'pq',0,0,False,4433) as key: self.assertIsNone(key)
        d=next((self.root/'pcap').iterdir())
        self.assertEqual(json.loads((d/'tls-status.json').read_text())['status'],'SUCCESS')
        self.assertTrue((d/'client-capture-error.json').exists())

    def test_analysis_reuses_extractor_and_joins(self):
        d=self.observation_fixture()
        metrics=dict.fromkeys(capture.METRICS,1);metrics.update(scenario='pq',tcp_stream=0)
        capture.save(d/'summary.json',dict(pcap_sha256=capture.hashlib.sha256((d/'handshakes.pcap').read_bytes()).hexdigest(), scenarios=[metrics]))
        with patch.object(capture.subprocess,'run',return_value=Mock(returncode=0,stdout='',stderr='')) as run:
            capture.analyze(self.root)
        self.assertEqual(run.call_args.args[0][1],str(capture.EXTRACTOR))
        result=json.loads((self.root/'pcap-metrics.jsonl').read_text())
        self.assertEqual(result['client_random'],'abc');self.assertEqual(result['metrics'],metrics)
        self.assertEqual(result['analysis_status'],'SUCCESS')

    def test_capture_analysis_and_keylog_failures_are_null(self):
        d=self.observation_fixture()
        for kind in ('extractor','keylog','capture'):
            if kind=='keylog': (d/'tls.keys').write_text('CLIENT_HANDSHAKE_TRAFFIC_SECRET wrong secret\n')
            if kind=='capture': capture.save(d/'capture-status.json',dict(status='CAPTURE_FAILURE',error='empty PCAP'))
            with patch.object(capture.subprocess,'run',return_value=Mock(returncode=1,stdout='',stderr='failure')):
                capture.analyze(self.root)
            result=json.loads((d/'derived.json').read_text())
            self.assertIsNone(result['metrics']);self.assertEqual(result['tls_status'],'SUCCESS')
            self.assertEqual(result['capture_status'],'CAPTURE_FAILURE' if kind == 'capture' else 'SUCCESS')

    def test_changed_pcap_hash_is_rejected(self):
        d=self.observation_fixture()
        capture.save(d/'capture-status.json',dict(status='SUCCESS',pcap_sha256='capture-hash'))
        (d/'handshakes.pcap').write_bytes(b'changed')
        capture.analyze(self.root)
        result=json.loads((d/'derived.json').read_text())
        self.assertIsNone(result['metrics'])
        self.assertEqual(result['capture_status'],'CAPTURE_FAILURE')
        self.assertEqual(result['analysis_status'],'NOT_EXECUTED')
        self.assertIn('PCAP hash does not match capture status',result['error'])

    def test_shutdown_drain_sigint_wait_and_readability(self):
        d=self.root;capture.save(d/'request.json',dict(server_port=4433))
        events=[]; proc=Mock();proc.poll.return_value=None;proc.wait.return_value=0
        def popen(*args,**kwargs):
            kwargs['stderr'].write('listening on eth0\n');kwargs['stderr'].flush()
            (d/'handshakes.pcap').write_bytes(b'x'*80)
            return proc
        def wait(predicate,seconds=8):
            if (d/'ready.json').exists(): (d/'stop').touch()
            self.assertTrue(predicate())
        def signal(sig):
            events.append(('signal',sig))
            with (d/'tcpdump.log').open('a') as log:log.write('2 packets captured\n')
        proc.send_signal.side_effect=signal
        proc.wait.side_effect=lambda **kwargs: events.append(('wait',)) or 0
        with patch.object(capture.subprocess,'Popen',side_effect=popen), patch.object(capture,'wait_for',side_effect=wait), patch.object(capture.time,'sleep',side_effect=lambda t:events.append(('drain',t))), patch.object(capture.subprocess,'run',return_value=Mock(returncode=0,stdout='packet')) as read:
            capture.capture_one(d)
        self.assertEqual(events[:3],[('drain',1.2),('signal',capture.signal.SIGINT),('wait',)])
        self.assertIn('-r',read.call_args.args[0])
        self.assertEqual(json.loads((d/'capture-status.json').read_text())['status'],'SUCCESS')

    @unittest.skipUnless(shutil.which('tcpdump'), 'local tcpdump unavailable')
    def test_offline_pcap_readability(self):
        # Synthetic Ethernet/IPv4/TCP SYN, no network activity or scientific data.
        ethernet=bytes.fromhex('00112233445566778899aabb0800')
        ipv4=struct.pack('!BBHHHBBH4s4s',0x45,0,40,1,0,64,6,0,
                         bytes([10,0,0,1]),bytes([10,0,0,2]))
        tcp=struct.pack('!HHIIBBHHH',50000,4433,100,0,0x50,2,65535,0,0)
        frame=ethernet+ipv4+tcp
        pcap=self.root/'synthetic.pcap'
        pcap.write_bytes(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+
                         struct.pack('<IIII',1,0,len(frame),len(frame))+frame)
        result=subprocess.run(['tcpdump','-n','-r',str(pcap),'-c','1'],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0);self.assertTrue(result.stdout.strip())

    def test_legacy_and_current_benchmark_summary_hooks(self):
        base=Path(__file__).resolve().parent
        driver=(base/'measure.py').read_text()
        saved=(base.parents[2]/'src/mtc/benchmark.py').read_text()
        transforms=driver[driver.index('def once('):driver.index("exec(compile(source,")]
        old=saved.replace("values=[r[metric] for r in group if r.get(metric) is not None]\n        if not values: continue",
                          "values=[r[metric] for r in group]")
        with patch.dict(os.environ,MEASUREMENT_PCAP='0'):
            for version in (old,saved):
                namespace=dict(source=version,os=os)
                exec(compile(transforms,'summary-compatibility','exec'),namespace)
                ast.parse(namespace['source'])
                self.assertIn('if not values:',namespace['source'])
            unknown=saved.replace('if not values: continue','if not values: pass')
            with self.assertRaisesRegex(ValueError,'summary source drift'):
                exec(compile(transforms,'summary-drift','exec'),dict(source=unknown,os=os))

    def test_measurement_context_includes_shared_module(self):
        repo=Path(__file__).resolve().parents[3]
        rules=(repo/"docker/original_campaigns/Dockerfile.measurement.dockerignore").read_text().splitlines()
        self.assertIn("!campaigns/common/",rules)
        self.assertIn("!campaigns/common/pcap_capture.py",rules)

    def test_runtime_mount_and_runner_finalize_pending_requests(self):
        repo=Path(__file__).resolve().parents[3]
        compose=(repo/'docker/original_campaigns/compose.measurement.yaml').read_text()
        runner=(Path(__file__).parent/'run.py').read_text()
        self.assertIn('campaigns/common:/opt/pcap-core:ro',compose)
        self.assertIn('/opt/pcap-core/pcap_capture.py',compose)
        self.assertIn('PYTHONPATH=/opt/pcap-core',runner)
        self.assertIn('with capture_session(base,directory,env,a.pcap',runner)
        self.assertLess(runner.index('with capture_session'),runner.index("base+['down']"))

    def test_session_stops_pending_capture_before_extraction(self):
        d=self.root;request=d/'pcap/sample-0000-pq/request.json';request.parent.mkdir(parents=True);request.write_text('{}')
        events=[]
        def run(args,**kwargs):
            if 'analyze' in args:
                self.assertTrue((request.parent/'stop').exists())
                self.assertTrue((request.parent/'capture-status.json').exists())
            events.append(args)
            return Mock(returncode=0)
        def monotonic():
            if (request.parent/'stop').exists():capture.save(request.parent/'capture-status.json',{'status':'SUCCESS'})
            return 0
        with patch.object(capture.subprocess,'run',side_effect=run),patch.object(capture.time,'monotonic',side_effect=monotonic):
            with self.assertRaisesRegex(RuntimeError,'driver exited'):
                with capture.capture_session([],d,{'MEASUREMENT_RUN_ROOT':'/work','MEASUREMENT_CAMPAIGN_ID':'one'},True,1):raise RuntimeError('driver exited')
        self.assertIn('analyze',events[1]);self.assertIn('stop',events[2])

    def test_empty_pcap_rejected(self):
        d=self.root;capture.save(d/'request.json',dict(server_port=4433))
        proc=Mock();proc.poll.return_value=None;proc.wait.return_value=0
        def wait(predicate,seconds=8): pass
        with patch.object(capture.subprocess,'Popen',return_value=proc),patch.object(capture,'wait_for',side_effect=wait),patch.object(capture.time,'sleep'):
            capture.capture_one(d)
        self.assertEqual(json.loads((d/'capture-status.json').read_text())['status'],'CAPTURE_FAILURE')

    def test_measurement_patch_preserves_metric_assignments(self):
        base=Path(__file__).resolve().parent
        driver=(base/'measure.py').read_text(); saved=(base.parents[2]/'src/mtc/benchmark.py').read_text()
        # Evaluate only source transformations; never execute the benchmark.
        transforms=driver[driver.index('def once('):driver.index("exec(compile(source,")]
        namespace=dict(source=saved,os=os)
        with patch.dict(os.environ,MEASUREMENT_PCAP='1'):
            exec(compile(transforms,'offline-patch-check','exec'),namespace)
        changed=namespace['source'];ast.parse(changed)
        original_line=next(line for line in saved.splitlines() if "'transport_read_bytes':m[" in line)
        self.assertIn(original_line,changed)
        self.assertIn("'handshake_wall_ms':m['handshake_wall_ms']",changed)
        self.assertIn("wall=(time.perf_counter()-t)*1000",changed)
        self.assertIn('with observation(',changed)
        disabled=dict(source=saved,os=os)
        with patch.dict(os.environ,MEASUREMENT_PCAP='0'):
            exec(compile(transforms,'offline-disabled-check','exec'),disabled)
        self.assertNotIn('with observation(',disabled['source'])
        self.assertNotIn('-keylogfile',disabled['source'])


if __name__=='__main__':unittest.main()
