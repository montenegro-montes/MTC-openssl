"""Reproducibility gates; every experiment/fixture directory is new."""
import argparse,datetime,hashlib,json,shutil,subprocess
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
LEGACY_N16_RESULTS='artifacts/results/paper-n16-20260910T050955152797Z'  # Immutable published evidence path.
IMAGE='sha256:4b04891fc50251a422c3357f35f355151ea50150d0e678dadde8c8f97b968b43'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def read(p):return json.loads(p.read_text())
def audit(root):
 counts={}
 for name in ['baseline-source-sha256.json','fixture-sha256.json','scaling-fixture-sha256.json']:
  values=read(root/name)
  for path,digest in values.items():assert sha(REPO/path)==digest,path
  counts[name]=len(values)
 dump(root/'preservation-after.json',{'passed':True,'counts':counts,'checked_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
 return counts

def main():
 p=argparse.ArgumentParser();p.add_argument('stage',choices=['init','tests-before','generate','tests-after','audit']);p.add_argument('root',type=Path);a=p.parse_args();root=a.root.resolve()
 assert root.is_relative_to(REPO/'artifacts/results')
 if a.stage=='init':
  root.mkdir();tracked=subprocess.check_output(['git','ls-files','-z'],cwd=REPO).decode().split('\0')
  dump(root/'baseline-source-sha256.json',{s:sha(REPO/s) for s in tracked if s and (REPO/s).is_file()})
  files=[f for b in ['artifacts/certs','artifacts/compact/batch16','artifacts/mtc/batch16-v2',LEGACY_N16_RESULTS] for f in (REPO/b).rglob('*') if f.is_file()]
  dump(root/'fixture-sha256.json',{str(f.relative_to(REPO)):sha(f) for f in files})
  dump(root/'metadata.json',{'git_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),'sizes':[1,4,16,64,256,1024],'status':'initialized','source_change_policy':'New metadata and separate existing detail timer collection only; native protocol and primary driver frozen'})
 if a.stage in ['tests-before','tests-after']:
  after=a.stage=='tests-after';status=root/('tests-after-status.json' if after else 'tests-status.json');assert not status.exists()
  image=json.loads(subprocess.check_output(['docker','image','inspect',IMAGE],text=True))[0];assert image['Id']==IMAGE
  if after:assert read(root/'campaign-status.json')['passed']
  else:
   dump(root/'images-before.json',[image]);(root/'environment.json').write_text(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True))
  with (root/('tests-after.log' if after else 'tests.log')).open('w') as log:r=subprocess.run(['docker','run','--rm','--network','none','-v',str(REPO/'artifacts')+':/work:ro',IMAGE,'sh','/opt/measurement/tests.sh'],stdout=log,stderr=subprocess.STDOUT)
  dump(status,{'passed':r.returncode==0,'exit_code':r.returncode,'image_id':IMAGE});assert r.returncode==0,'Regression failure; stop and document'
 if a.stage=='generate':
  assert read(root/'tests-status.json')['passed'];parent=REPO/'artifacts/scaling';parent.mkdir(exist_ok=True);dest=parent/root.name;assert not dest.exists()
  dump(root/'fixture-location.json',{'host':str(dest.relative_to(REPO)),'container':'/work/scaling/'+root.name})
  with (root/'generation.log').open('w') as log:r=subprocess.run(['docker','run','--rm','--network','none','-v',str(REPO/'artifacts')+':/work:ro','-v',str(parent)+':/work/scaling','-v',str(REPO/'campaigns/scaling_campaign')+':/opt/scaling:ro',IMAGE,'python3','/opt/scaling/generate.py','--output','/work/scaling/'+root.name],stdout=log,stderr=subprocess.STDOUT)
  dump(root/'generation-status.json',{'passed':r.returncode==0,'exit_code':r.returncode});assert r.returncode==0
 if a.stage=='audit':
  assert read(root/'tests-status.json')['passed'] and read(root/'tests-after-status.json')['passed'] and read(root/'campaign-status.json')['passed']
  counts=audit(root);snapshot=root/'source';assert not snapshot.exists();snapshot.mkdir()
  shutil.copytree(REPO/'campaigns/scaling_campaign',snapshot/'campaigns/scaling_campaign',ignore=shutil.ignore_patterns('__pycache__'));(snapshot/'docker').mkdir();shutil.copyfile(REPO/'docker/compose.scaling.yaml',snapshot/'docker/compose.scaling.yaml')
  dump(root/'source-sha256.json',{str(f.relative_to(snapshot)):sha(f) for f in snapshot.rglob('*') if f.is_file()})
  code="import hashlib,json;from pathlib import Path;files=[Path('/opt/openssl-measurement/bin/openssl'),Path('/opt/openssl-mtc/lib/libssl.so.3'),Path('/opt/openssl-mtc/lib/libcrypto.so.3')]+[p for d in ['/opt/measurement','/opt/mtc','/opt/profiling','/opt/compact'] for p in Path(d).glob('*') if p.is_file()];print(json.dumps({str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in files},indent=2))"
  (root/'container-source-sha256.json').write_text(subprocess.check_output(['docker','run','--rm','--network','none',IMAGE,'python3','-c',code],text=True))
  (root/'environment-after.json').write_text(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True))
  active=subprocess.check_output(['docker','ps','--filter','label=com.docker.compose.project=mtscaling','--format','{{.ID}}'],text=True).strip();assert not active,'Experiment containers still active'
  dump(root/'final-audit.json',{'passed':True,'preserved_counts':counts,'experiment_containers_stopped':True,'native_image_unchanged':IMAGE,'tracked_source_files_changed':False,'new_files':'campaigns/scaling_campaign/* and docker/compose.scaling.yaml','completed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
  metadata=read(root/'metadata.json');metadata.update(status='complete with documented timing limitations',image_id=IMAGE,fixture_location=read(root/'fixture-location.json'),protocol={'tls':'1.3','group':'X25519','cipher':'TLS_AES_256_GCM_SHA384','pq_authentication':'ML-DSA-65','classic_authentication':'ECDSA P-256','server_authentication_only':True,'resumption':False,'tickets':False},campaigns_per_n_per_mode=5,seed_policy='1000*i+N for i=1..5',warmup_rounds=5,measured_rounds=30,counts=read(root/'analysis-status.json'),primary_driver='/opt/measurement/measure.py unchanged',detail_driver='campaigns/scaling_campaign/detail_measure.py; existing detail flag only',previous_n16_samples_reused=False,source_policy='Existing tracked source unchanged; new campaigns/scaling_campaign scripts and compose added',final_audit='final-audit.json',limitations=['No isolated MTC proof CPU timer','Two slower primary campaigns retained; timing causal attribution provisional','Five campaigns per N; ascending N execution order','Architectural comparisons are not security-equivalent'])
  dump(root/'metadata.json',metadata)
  from analyze import refresh_report
  refresh_report(root)
 print(a.stage,'PASS',root)
if __name__=='__main__':main()
