"""Cheap synthetic full/preflight checks: no Docker, TLS, probes or real results."""
import csv
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch,Mock

spec=importlib.util.spec_from_file_location('validation_run',Path(__file__).with_name('run.py'));run=importlib.util.module_from_spec(spec);spec.loader.exec_module(run)
import results,gate
spec=importlib.util.spec_from_file_location('validation_measure',Path(__file__).with_name('measure.py'));measure=importlib.util.module_from_spec(spec);spec.loader.exec_module(measure)


def write_csv(path,rows):
    if not rows:return
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)


def dataset(root,fail=False):
    root.mkdir(exist_ok=True);pcaps=[];good=[];warm=[];failed=[]
    for is_warm,n in [(1,1),(0,2)]:
        for i in range(n):
            identity=dict(campaign_id='test',round_id=i+1,round=i,scenario='pq',is_warmup=is_warm,order_in_round=1)
            random=f'{i+1+is_warm*10:064x}';row=dict(identity,client_random=random,tcp_connect_wall_ms_native=10+i,handshake_wall_ms=20+i,connection_establishment_wall_ms_native=40+i)
            failure=not is_warm and i==1 and fail
            if failure:
                row.update(handshake_wall_ms=None,connection_establishment_wall_ms_native=None);failed.append(row)
            elif is_warm:warm.append(row)
            else:good.append(row)
            if is_warm:continue
            folder=root/f'pcap/sample-{i:04d}-pq';folder.mkdir(parents=True)
            (folder/'observation.json').write_text(json.dumps(identity));(folder/'handshakes.pcap').write_bytes(b'synthetic-'+bytes([i]));digest=hashlib.sha256((folder/'handshakes.pcap').read_bytes()).hexdigest()
            (folder/'capture-status.json').write_text(json.dumps(dict(status='SUCCESS',pcap_sha256=digest)))
            (folder/'tls.keys').write_text('CLIENT_RANDOM '+random+' '+'ab'*48+'\n')
            metrics=dict(scenario='pq',client_random=random,tcp_stream=i+7,tcp_connect_wall_ms=5+i,tls_from_pcap_wall_ms=None if failure else 15+i,connection_handshake_wall_ms=None if failure else 30+i)
            for key in ['connection_handshake_packets','connection_handshake_tcp_payload_bytes','connection_handshake_ip_bytes','connection_handshake_frame_bytes','connection_handshake_retransmission_frames']:metrics[key]=None if failure else 8
            (folder/'summary.json').write_text(json.dumps(dict(pcap_sha256=digest,scenarios=[metrics])))
            pcaps.append(dict(identity,client_random=random,association_confidence='client_random',artifact_directory=str(folder.relative_to(root)),pcap_sha256=digest,metrics=metrics,capture_status='SUCCESS',analysis_status='PARTIAL' if failure else 'SUCCESS',tls_status='TLS_MEASUREMENT_FAILURE' if failure else 'SUCCESS'))
    write_csv(root/'samples.csv',good);write_csv(root/'warmups.csv',warm);write_csv(root/'failures.csv',failed)
    # Reverse PCAP order to prove that row position never establishes pairing.
    (root/'pcap-metrics.jsonl').write_text(''.join(json.dumps(p)+'\n' for p in reversed(pcaps)))
    return good,failed


class FullTests(unittest.TestCase):
    def test_preflight_shared_counts(self):
        with patch.object(run,'execute_condition') as call:run.execute_condition_preflight(Path('unused'),'local')
        self.assertEqual(call.call_args.args[2:],('preflight',1,1))

    def test_full_shared_counts(self):
        with patch.object(run,'execute_condition') as call:run.execute_condition_full(Path('unused'),'constrained',Path('gate'))
        self.assertEqual(call.call_args.args[2:],('full',30,5,Path('gate')))

    def test_design_totals(self):
        self.assertEqual((run.design('full')['warmup_attempts'],run.design('full')['measured_attempts']),(15,90))
        self.assertEqual((run.design('preflight')['warmup_attempts'],run.design('preflight')['measured_attempts']),(3,3))

    def collect(self,change=None,fail=False,preflight=False):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);dataset(root,fail)
            if change:change(root)
            return results.collect(root,'constrained','test',2,1,True,preflight=preflight)

    def test_pair_by_identity_not_position(self):
        pairs,counts=self.collect();self.assertEqual([p['tcp_stream'] for p in pairs],[7,8]);self.assertEqual(counts['successful_native_pcap_pairs'],2)

    def test_missing_random(self):
        def change(root):
            rows=results.read_csv(root/'samples.csv');rows[0]['client_random']='';write_csv(root/'samples.csv',rows)
        with self.assertRaisesRegex(RuntimeError,'client_random'):self.collect(change)

    def test_duplicate_identity(self):
        def change(root):
            rows=results.read_csv(root/'samples.csv');rows.append(rows[0]);write_csv(root/'samples.csv',rows)
        with self.assertRaisesRegex(RuntimeError,'Duplicate'):self.collect(change)

    def test_duplicate_pcap(self):
        def change(root):
            p=root/'pcap-metrics.jsonl';text=p.read_text();p.write_text(text+text.splitlines()[0]+'\n')
        with self.assertRaisesRegex(RuntimeError,'Duplicate'):self.collect(change)

    def test_failure_retained_not_paired(self):
        pairs,c=self.collect(fail=True)
        self.assertEqual((c['measured_attempts'],c['successful_tls_observations'],c['failed_tls_observations']),(2,1,1))
        self.assertEqual(len(pairs),1);self.assertEqual(c['partial_analyses'],1)
        self.assertEqual(pairs[0]['round_id'],'1')

    def test_successful_tls_analysis_failure_is_unpairable_when_failure_aware(self):
        def change(root):
            p=root/'pcap-metrics.jsonl'
            rows=[json.loads(s) for s in p.read_text().splitlines()]
            target=next(r for r in rows if r['round_id']==2)
            target['analysis_status']='ANALYSIS_FAILURE'
            target['metrics']=None
            target['error']='Stage-1 extractor failed; see analysis.log'
            p.write_text(''.join(json.dumps(r)+'\n' for r in rows))

        pairs,c=self.collect(change)

        self.assertEqual(len(pairs),1)
        self.assertEqual(pairs[0]['round_id'],'1')
        self.assertEqual(c['successful_tls_observations'],2)
        self.assertEqual(c['successful_native_pcap_pairs'],1)
        self.assertEqual(c['incomplete_or_unpairable_observations'],1)
        self.assertEqual(c['unavailable_captures'],0)


    def test_successful_tls_analysis_failure_is_fatal_when_not_failure_aware(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            dataset(root)

            p=root/'pcap-metrics.jsonl'
            rows=[json.loads(s) for s in p.read_text().splitlines()]
            target=next(r for r in rows if r['round_id']==2)
            target['analysis_status']='ANALYSIS_FAILURE'
            target['metrics']=None
            target['error']='Stage-1 extractor failed; see analysis.log'
            p.write_text(''.join(json.dumps(r)+'\n' for r in rows))

            with self.assertRaisesRegex(
                RuntimeError,
                'analysis_status'
            ):
                results.collect(
                    root,'latency-100','test',2,1,False
                )
    def test_incomplete_never_has_tls_full(self):
        def change(root):
            p=root/'pcap-metrics.jsonl';rows=[json.loads(s) for s in p.read_text().splitlines()];rows[0]['metrics']['tls_from_pcap_wall_ms']=1
            folder=root/rows[0]['artifact_directory'];summary=json.loads((folder/'summary.json').read_text());summary['scenarios'][0]=rows[0]['metrics'];(folder/'summary.json').write_text(json.dumps(summary));p.write_text(''.join(json.dumps(r)+'\n' for r in rows))
        with self.assertRaisesRegex(RuntimeError,'Fabricated'):self.collect(change,fail=True)

    def test_accounting_mismatch(self):
        def change(root):
            rows=results.read_csv(root/'samples.csv');write_csv(root/'samples.csv',rows[:1])
        with self.assertRaisesRegex(RuntimeError,'accounting'):self.collect(change)

    def test_sha_mismatch(self):
        def change(root):(root/'pcap/sample-0000-pq/handshakes.pcap').write_bytes(b'substituted')
        with self.assertRaisesRegex(RuntimeError,'SHA'):self.collect(change)

    def test_preflight_failure_still_invalid(self):
        with self.assertRaisesRegex(RuntimeError,'Preflight requires'):self.collect(fail=True,preflight=True)

    def test_native_connection_failure_null(self):
        self.assertEqual(measure.native_failure('NATIVE_CONNECTION_METRICS {"tcp_connect_wall_ms_native":null,"connection_establishment_wall_ms_native":null}')['tcp_connect_wall_ms_native'],None)

    def test_native_tcp_only(self):
        d=measure.native_failure('NATIVE_CONNECTION_METRICS {"tcp_connect_wall_ms_native":12.5,"connection_establishment_wall_ms_native":null}')
        self.assertEqual(d['tcp_connect_wall_ms_native'],12.5);self.assertIsNone(d['handshake_wall_ms']);self.assertIsNone(d['connection_establishment_wall_ms_native'])

    def test_failed_completed_handshake_not_reliability(self):
        with self.assertRaisesRegex(RuntimeError,'not an incomplete'):measure.native_failure('PROFILE_METRICS {"handshake_wall_ms":1}')

    def test_timeout_bytes_preserved(self):
        with patch.object(measure.subprocess,'run',side_effect=subprocess.TimeoutExpired(['client'],30,output=b'out',stderr=b'err')):
            r=measure.run_client(['client'],30)
        self.assertEqual(r.returncode,124);self.assertIn('err',r.stderr)

    def test_bootstrap_success_only_deterministic_10000(self):
        paired,_=self.collect();failure={'condition':'constrained','tls_status':'TLS_MEASUREMENT_FAILURE'}
        a=results.summarize(paired+[failure],'constrained');b=results.summarize(paired,'constrained')
        self.assertEqual(a,b)
        for summary in a.values():self.assertEqual((summary['n_successful_pairs'],summary['bootstrap_resamples']),(2,10000))
        real=results.random.Random(results.BOOTSTRAP_SEED)
        with patch.object(results.random,'Random',return_value=Mock(wraps=real)) as factory:
            results.summarize(paired,'constrained')
            self.assertEqual(factory.return_value.randrange.call_count,20000)

    def test_bootstrap_too_few(self):
        paired,_=self.collect(fail=True)
        with self.assertRaisesRegex(RuntimeError,'Too few'):results.summarize(paired,'constrained')

    def test_full_gate_absent_no_execution(self):
        with tempfile.TemporaryDirectory(dir=run.REPO/'artifacts/results') as tmp:
            root=Path(tmp)/'new-full';bad=Path(tmp)/'gate';bad.mkdir()
            (bad/'tests-status.json').write_text('{"passed":true}');(bad/'preflight-status.json').write_text('{"passed":false}')
            with patch.object(run,'execute_condition_full') as execute:
                with self.assertRaisesRegex(RuntimeError,'Successful'):run.execute_full(root,bad)
                execute.assert_not_called();self.assertFalse(root.exists())

    def test_gate_requires_three_conditions(self):
        with tempfile.TemporaryDirectory(dir=run.REPO/'artifacts/results') as tmp:
            root=Path(tmp);(root/'tests-status.json').write_text('{"passed":true}');(root/'preflight-status.json').write_text('{"passed":true,"conditions":{"local":{"passed":true}}}')
            with self.assertRaisesRegex(RuntimeError,'three'):gate.validate(run.REPO,root,run.CONDITIONS,Mock())

    def test_gate_only_exact_source_transition(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp);root=repo/'evidence';root.mkdir();p=repo/'core.py';p.write_bytes(b'before');old=gate.sha(p);p.write_bytes(b'after');new=gate.sha(p)
            (root/'baseline-source-sha256.json').write_text(json.dumps({'core.py':old}));(repo/'fixture.pem').write_bytes(b'fixture');(root/'fixture-sha256.json').write_text(json.dumps({'fixture.pem':gate.sha(repo/'fixture.pem')}))
            transition={'core.py':{'before':old,'after':new}}
            self.assertIn('core.py',gate.check_hashes(repo,root,transition))
            p.write_bytes(b'unreviewed')
            with self.assertRaisesRegex(RuntimeError,'Preservation'):gate.check_hashes(repo,root,transition)

    def test_failure_aware_driver_records_every_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);fixture=root/'fixture';fixture.mkdir()
            for name in ['root.pem','server.pem','server.key']:(fixture/name).write_text('synthetic')
            env=dict(MEASUREMENT_RUN_ROOT=str(root),MEASUREMENT_CAMPAIGN_ID='test',MEASUREMENT_SEED='42',VALIDATION_NETWORK_FAMILY='combined')
            failure=subprocess.CompletedProcess(['mock'],1,'','NATIVE_CONNECTION_METRICS {"tcp_connect_wall_ms_native":12,"connection_establishment_wall_ms_native":null}')
            from contextlib import nullcontext
            with patch.dict(measure.os.environ,env),patch.object(measure,'FIXTURE',fixture),patch.object(sys,'argv',['measure.py','--runs','2','--warmup','1','--image-id','synthetic','--failure-aware']),patch.object(measure,'run_client',return_value=failure),patch.object(measure,'observation',side_effect=lambda *a: nullcontext(None)):
                measure.main()
            rows=results.read_csv(root/'test/failures.csv')
            self.assertEqual(len(rows),3);self.assertEqual([r['is_warmup'] for r in rows],['1','0','0'])
            self.assertTrue(all(r['tcp_connect_wall_ms_native']=='12' and not r['handshake_wall_ms'] and not r['connection_establishment_wall_ms_native'] for r in rows))
            self.assertFalse((root/'test/samples.csv').exists())

    def test_partial_without_clienthello_uses_existing_incomplete_mode(self):
        import pcap_capture
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);d=root/'pcap/sample-0000-pq';d.mkdir(parents=True)
            ident=dict(campaign_id='test',round_id=1,round=0,scenario='pq',is_warmup=0,order_in_round=1)
            (d/'observation.json').write_text(json.dumps(ident));(d/'handshakes.pcap').write_bytes(b'mock');digest=hashlib.sha256((d/'handshakes.pcap').read_bytes()).hexdigest()
            (d/'capture-status.json').write_text(json.dumps(dict(status='SUCCESS',pcap_sha256=digest)))
            write_csv(root/'failures.csv',[dict(ident,client_random='')])
            metrics=dict(scenario='pq',tcp_stream=7,pcap_analysis_status='PARTIAL',tcp_connect_wall_ms=1,tls_from_pcap_wall_ms=None,connection_handshake_wall_ms=None)
            (d/'summary.json').write_text(json.dumps(dict(pcap_sha256=digest,scenarios=[metrics])))
            with patch.dict(pcap_capture.os.environ,MEASUREMENT_PCAP_CLIENT_RANDOM_STREAM='1'),patch.object(pcap_capture.subprocess,'run',return_value=Mock(returncode=0,stdout='',stderr='')) as call:
                pcap_capture.analyze(root,allow_failed=True)
            self.assertIn('--allow-incomplete',call.call_args.args[0]);self.assertNotIn('--client-random',call.call_args.args[0])
            row=json.loads((d/'derived.json').read_text());self.assertEqual(row['analysis_status'],'PARTIAL')
            self.assertIsNone(row['metrics']['tls_from_pcap_wall_ms']);self.assertIsNone(row['metrics']['connection_handshake_wall_ms'])

    def test_full_cannot_write_inside_approved_root(self):
        with tempfile.TemporaryDirectory(dir=run.REPO/'artifacts/results') as tmp:
            gate_root=Path(tmp)
            with self.assertRaisesRegex(SystemExit,'outside'):run.execute_full(gate_root/'new-full',gate_root)
            self.assertFalse((gate_root/'new-full').exists())

    def test_gate_reuses_recorded_campaign_identifier(self):
        with tempfile.TemporaryDirectory(dir=run.REPO/'artifacts/results') as tmp:
            root=Path(tmp);tests=dict(passed=True,network_image_id='network',capture_image_id='capture')
            (root/'tests-status.json').write_text(json.dumps(tests));conditions={}
            for condition in run.CONDITIONS:
                row=dict(passed=True,condition=condition,scenario='pq',campaign_id=f'legacy-{condition}-preflight',association_valid=True,integrity_valid=True,image_identity_valid=True,capture_status='SUCCESS',analysis_status='SUCCESS',tls_status='SUCCESS',network_image_id='network',capture_image_id='capture')
                conditions[condition]=row
                (root/f'preflight-{condition}-status.json').write_text(json.dumps(row))
            (root/'preflight-status.json').write_text(json.dumps(dict(passed=True,conditions=conditions)))
            collect=Mock()
            with patch.object(gate,'check_hashes',return_value={}):gate.validate(run.REPO,root,run.CONDITIONS,collect)
            self.assertEqual([c.args[2] for c in collect.call_args_list],[f'legacy-{name}-preflight' for name in run.CONDITIONS])
            bad=conditions['local'];bad['campaign_id']='../legacy-local-preflight'
            (root/'preflight-local-status.json').write_text(json.dumps(bad));(root/'preflight-status.json').write_text(json.dumps(dict(passed=True,conditions=conditions)))
            with patch.object(gate,'check_hashes',return_value={}):
                with self.assertRaisesRegex(RuntimeError,'identifier'):gate.validate(run.REPO,root,run.CONDITIONS,Mock())

    def test_full_refuses_existing_output(self):
        with tempfile.TemporaryDirectory(dir=run.REPO/'artifacts/results') as tmp:
            with self.assertRaisesRegex(SystemExit,'nonexistent'):run.execute_full(Path(tmp),Path('gate'))

if __name__=='__main__':unittest.main()
