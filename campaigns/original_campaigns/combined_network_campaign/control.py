"""Initialize, regression-gate, and audit the manually run experiment."""
import argparse,datetime,hashlib,json,shutil,subprocess,sys
from pathlib import Path
from config import *
REPO=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(REPO/'campaigns'))
from common.image_chain import ensure
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def load(p):return json.loads(p.read_text())
def verify(root):
    for name in ['baseline-source-sha256.json','fixture-sha256.json']:
        for path,digest in load(root/name).items():
            if sha(REPO/path)!=digest:raise RuntimeError('preservation mismatch: '+path)
def main():
 p=argparse.ArgumentParser();p.add_argument('stage',choices=['init','tests','audit']);p.add_argument('root',type=Path);a=p.parse_args();root=a.root.resolve()
 if not root.is_relative_to(REPO/'artifacts/results'):raise SystemExit('root must be under artifacts/results')
 if a.stage=='init':
  if root.exists():raise SystemExit('refusing overwrite')
  root.mkdir();tracked=subprocess.check_output(['git','ls-files','-z'],cwd=REPO).decode().split('\0');save(root/'baseline-source-sha256.json',{x:sha(REPO/x) for x in tracked if x and (REPO/x).is_file()});fixtures=[f for b in ['artifacts/certs','artifacts/compact/batch16','artifacts/mtc/batch16-v2'] for f in (REPO/b).rglob('*') if f.is_file()];save(root/'fixture-sha256.json',{str(f.relative_to(REPO)):sha(f) for f in fixtures});commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip();status=subprocess.check_output(['git','status','--short'],cwd=REPO,text=True);save(root/'metadata.json',{'experiment':'combined-network','preparation_commit':commit,'git_commit_before':commit,'git_status_before':status,'profiles':PROFILES,'scenarios':SCENARIOS,'N':16,'TLS':'1.3','group':'X25519','cipher':'TLS_AES_256_GCM_SHA384','server_authentication_only':True,'tickets':False,'resumption':False,'status':'initialized','git_commit_after_experiment':None})
 elif a.stage=='tests':
  save(root/'tests-status.json',{'passed':False,'state':'resolving images','image_ref':IMAGE,'base_image_ref':BASE_IMAGE})
  resolved=ensure('network');image=resolved['target'];base=resolved['images']['measurement']
  for tool in ['tc','ping','nstat','iperf3']:subprocess.run(['docker','run','--rm','--network','none',image['Id'],'sh','-c','command -v "$1"','sh',tool],check=True,capture_output=True)
  with (root/'tests.log').open('w') as log:r=subprocess.run(['docker','run','--rm','--network','none','-v',str(REPO/'artifacts')+':/work:ro',image['Id'],'sh','/opt/measurement/tests.sh'],stdout=log,stderr=subprocess.STDOUT)
  if r.returncode:
   save(root/'tests-status.json',{'passed':False,'exit_code':r.returncode,'image_id':image['Id'],'base_image_id':base['Id'],'required_tools':['tc','ping','nstat','iperf3']})
   raise SystemExit('regression failure')
  save(root/'images.json',{'network_image':image,'base_image':base,'automatic_rebuilds':resolved['rebuilt']});(root/'environment.json').write_text(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True));verify(root)
  metadata=load(root/'metadata.json');metadata.update(base_image_id=base['Id'],network_image_id=image['Id']);save(root/'metadata.json',metadata)
  save(root/'tests-status.json',{'passed':True,'exit_code':0,'image_id':image['Id'],'base_image_id':base['Id'],'base_layers_verified':True,'required_tools':['tc','ping','nstat','iperf3']})
 else:
  for name in ['tests-status.json','preflight-status.json','smoke-status.json','campaign-status.json','analysis-status.json']:
   if not load(root/name)['passed']:raise SystemExit(name+' incomplete')
  verify(root);snap=root/'source'
  if snap.exists():
   if not (root/'source-sha256.json').is_file():raise RuntimeError('source snapshot exists without source-sha256.json')
   for path,digest in load(root/'source-sha256.json').items():
    if sha(snap/path)!=digest:raise RuntimeError('source snapshot mismatch: '+path)
  else:
   snap.mkdir();shutil.copytree(REPO/'campaigns/original_campaigns/combined_network_campaign',snap/'campaigns/original_campaigns/combined_network_campaign',ignore=shutil.ignore_patterns('__pycache__'));(snap/'docker').mkdir();shutil.copyfile(REPO/'docker/original_campaigns/compose.network-combined.yaml',snap/'docker/original_campaigns/compose.network-combined.yaml');save(root/'source-sha256.json',{str(f.relative_to(snap)):sha(f) for f in snap.rglob('*') if f.is_file()})
  active=subprocess.check_output(['docker','ps','--filter','label=com.docker.compose.project=mtcombined','--format','{{.ID}}'],text=True).strip()
  if active:raise RuntimeError('containers remain active')
  m=load(root/'metadata.json');m.update(status='complete',authentication_or_protocol_source_changed=False,completed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat());save(root/'metadata.json',m)
 print(a.stage,'PASS',root)
if __name__=='__main__':main()
