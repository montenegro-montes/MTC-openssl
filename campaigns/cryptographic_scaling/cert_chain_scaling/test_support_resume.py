"""Capability and resume tests never execute Docker or measurement campaigns."""
import contextlib
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import capabilities
import measure
import result_state
import run


class CapabilityTests(unittest.TestCase):
    def test_crypto_and_tls_are_distinct(self):
        signatures='ECDSA ML-DSA-44 ML-DSA-65 ML-DSA-87 SLH-DSA-SHA2-128s SLH-DSA-SHA2-192s SLH-DSA-SHA2-256s'
        tls='ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:mldsa44:mldsa65:mldsa87:sphincssha2128ssimple'
        table=capabilities.support_table(signatures,tls)
        self.assertEqual(sum(r['signature_supported'] for r in table),9)
        self.assertEqual(sum(r['tls_signature_supported'] for r in table),6)
        self.assertFalse(any(r['tls_signature_supported'] for r in table if r['family']=='SLH-DSA'))

    def test_current_provider_names_supported_without_sphincs_substitution(self):
        table=capabilities.support_table('ECDSA mldsa65 slhdsasha2128s','p384_mldsa65:slhdsasha2128s')
        by={r['profile']:r for r in table}
        self.assertFalse(by['mldsa65']['tls_signature_supported'])
        self.assertTrue(by['slhdsa128s']['tls_signature_supported'])
        self.assertFalse(by['slhdsa192s']['tls_signature_supported'])

    def test_absent_capability_evidence_is_not_assumed(self):
        with self.assertRaises(ValueError):capabilities.load_support({'signature_algorithms':'mldsa65'})

    def test_metadata_uses_frozen_configuration(self):
        for name,p in measure.PROFILES.items():
            row=measure.profile_metadata(name,5)
            self.assertEqual(row['security_level'],p['level'])
            self.assertEqual(row['family'],p['family']);self.assertEqual(row['certificate_depth'],5)
            self.assertTrue(row['TLS_signature_supported'])


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.fixture=self.root/'fixtures/ecdsa-p256/depth-2';self.fixture.mkdir(parents=True)
        (self.fixture/'manifest.json').write_text(json.dumps({'profile':'ecdsa-p256','depth_including_root':2,'files_sha256':{}}))
        self.hash=result_state.digest(self.fixture/'manifest.json');self.output=self.root/'results';self.output.mkdir()
        self.manifest={'profiles':['ecdsa-p256'],'depths':[2],'campaigns':1,'repetitions':2,'warmups':0,'seed':41000,
                       'image_id':'sha256:test','git_commit':'original','cells':[{'profile':'ecdsa-p256','depth':2,'campaign':1}]}
        (self.output/'manifest.json').write_text(json.dumps(self.manifest))
        (self.output/'fixture_hashes.json').write_text(json.dumps({'ecdsa-p256/depth-2/manifest.json':self.hash}))
        self.env=self.root/'environment.json';self.env.write_text(json.dumps({'image_id':'sha256:test',
            'signature_algorithms':'ECDSA','tls_signature_algorithms':'ecdsa_secp256r1_sha256'}))
        self.cell=self.output/'ecdsa-p256-d2-c1'

    def args(self):return run.parser().parse_args(['--fixtures',str(self.root/'fixtures'),'--output',str(self.output),'--resume','--environment',str(self.env)])

    def complete(self):
        data=self.cell/'data';(data/'logs').mkdir(parents=True);(data/'server-metrics').mkdir()
        rows=[]
        for i in (1,2):
            key=f'{i:064x}';row={k:1 for k in result_state.METRICS}
            row.update(campaign='ecdsa-p256-d2-c1',scenario='ecdsa-p256-d2',success=1,is_warmup=0,round=i,
                       seed=41201,chain_depth=2,fixture_hash=self.hash,image_id='sha256:test',git_commit='original',client_random=key,
                       security_level='',family='X.509',algorithm='ecdsa-p256')
            rows.append(row);(data/'logs'/f'sample-{i:04d}.log').write_text('Verify return code: 0 (ok)')
            (data/'server-metrics'/(key+'.json')).write_text(json.dumps({'reused':False,'certificate_message_bytes':1}))
        for name,values in [('observations.csv',rows),('warmups.csv',[])]:
            with (data/name).open('w',newline='') as f:
                w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(values)
        (data/'validation.json').write_text(json.dumps({'passed':True,'measured_handshakes':2,'warmup_handshakes':0}))

    def test_completion_and_dry_run_are_read_only(self):
        self.complete();before={p:result_state.digest(p) for p in self.output.rglob('*') if p.is_file()}
        with patch.object(run.subprocess,'run') as docker:
            plan,_=run.build_plan(self.args(),run.parser())
        docker.assert_not_called();self.assertEqual(plan['counts']['COMPLETE'],1)
        self.assertEqual(before,{p:result_state.digest(p) for p in self.output.rglob('*') if p.is_file()})

    def test_directory_is_not_completion(self):
        self.cell.mkdir();plan,_=run.build_plan(self.args(),run.parser());self.assertEqual(plan['counts']['INVALID_INCOMPLETE'],1)

    def test_missing_and_corrupt_measurements(self):
        plan,_=run.build_plan(self.args(),run.parser());self.assertEqual(plan['counts']['MISSING'],1)
        self.complete();(self.cell/'data/server-metrics'/f'{1:064x}.json').unlink()
        plan,_=run.build_plan(self.args(),run.parser());self.assertEqual(plan['counts']['INVALID_INCOMPLETE'],1)

    def test_image_change_is_rejected(self):
        data=json.loads(self.env.read_text());data['image_id']='different';self.env.write_text(json.dumps(data))
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):run.build_plan(self.args(),run.parser())

    def test_resume_dry_run_cli_needs_no_docker_and_writes_nothing(self):
        import os,subprocess,sys
        self.complete();before={p:result_state.digest(p) for p in self.output.rglob('*') if p.is_file()}
        command=[sys.executable,run.__file__,'--fixtures',str(self.root/'fixtures'),'--output',str(self.output),
                 '--resume','--dry-run','--environment',str(self.env)]
        result=subprocess.run(command,capture_output=True,text=True,env={**os.environ,'PATH':''})
        self.assertEqual(result.returncode,0,result.stderr);self.assertIn('SKIP complete',result.stdout)
        self.assertEqual(before,{p:result_state.digest(p) for p in self.output.rglob('*') if p.is_file()})

    def test_deleted_campaign_cannot_be_resumed(self):
        args=self.args();args.output=self.root/'deleted'
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):run.build_plan(args,run.parser())

    def test_single_campaign_filter_keeps_frozen_settings(self):
        args=self.args();args.campaign=[1];args.profile=['ecdsa-p256'];args.depth=[2]
        plan,_=run.build_plan(args,run.parser())
        self.assertTrue(plan['cells'][0]['selected']);self.assertEqual(plan['repetitions'],2)
        args.repetitions=30
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):run.build_plan(args,run.parser())

    def test_unsupported_is_explicit_not_missing_or_failed(self):
        data=json.loads(self.env.read_text());data['tls_signature_algorithms']='';self.env.write_text(json.dumps(data))
        plan,_=run.build_plan(self.args(),run.parser())
        self.assertEqual(plan['counts']['SKIPPED_UNSUPPORTED_TLS'],1)
        self.assertEqual(plan['counts']['MISSING'],0)
        self.assertEqual(plan['counts']['INVALID_INCOMPLETE'],0)

    def test_resume_attempt_is_detected_without_mutating_original(self):
        self.complete();destination=self.output/'resume/attempt/cells'/self.cell.name
        destination.parent.mkdir(parents=True);self.cell.rename(destination)
        (destination.parent.parent/'execution.json').write_text(json.dumps({'git_commit':'original'}))
        self.cell.mkdir();(self.cell/'server-failure.log').write_text('previous failure')
        plan,_=run.build_plan(self.args(),run.parser())
        self.assertEqual(plan['counts']['COMPLETE'],1)
        self.assertEqual((self.cell/'server-failure.log').read_text(),'previous failure')

    def test_analysis_enriches_legacy_rows_without_rewriting(self):
        import analyze
        self.complete();path=self.cell/'data/observations.csv';before=path.read_bytes()
        rows,excluded,support=analyze.collect(self.output,json.loads(self.env.read_text()))
        self.assertEqual(len(rows),2);self.assertEqual(rows[0]['security_level'],1)
        self.assertEqual(path.read_bytes(),before)

    def test_diagnostics_before_cleanup_on_server_failure(self):
        import subprocess
        args=self.args();attempt=self.root/'attempt';attempt.mkdir();calls=[]
        cell={'profile':'ecdsa-p256','depth':2,'campaign':1,'fixture_hash':self.hash}
        def invoke(cmd,**kw):
            calls.append(cmd)
            if 'up' in cmd:raise subprocess.CalledProcessError(1,cmd)
            return subprocess.CompletedProcess(cmd,0,stdout='server-id' if '-q' in cmd else 'diagnostic',stderr='')
        with patch.object(run.subprocess,'run',side_effect=invoke),self.assertRaises(subprocess.CalledProcessError):
            run.execute_cell(cell,args,self.manifest,attempt,'original')
        self.assertEqual(calls[-1][-1],'down')
        self.assertTrue((attempt/'failure-ecdsa-p256-d2-c1/inspect.json').exists())
        self.assertTrue(any('logs' in cmd for cmd in calls[:-1]))

if __name__=='__main__':unittest.main()
