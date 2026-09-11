"""Initialize, regression-gate and audit a manually executed loss experiment."""
import argparse,datetime,hashlib,json,shutil,subprocess,sys
from pathlib import Path
from config import BASE_IMAGE,IMAGE,LOSSES,RTT_MS,HANDSHAKE_TIMEOUT_SECONDS

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'campaigns'))
from common.image_chain import ensure
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def load(path):return json.loads(path.read_text())
def verify(root):
    counts={}
    for name in ['baseline-source-sha256.json','fixture-sha256.json']:
        values=load(root/name)
        for path,digest in values.items():
            file=REPO/path
            if not file.is_file() or sha(file)!=digest:raise RuntimeError('Preservation mismatch: '+path)
        counts[name]=len(values)
    return counts
def main():
    p=argparse.ArgumentParser();p.add_argument('stage',choices=['init','tests','audit']);p.add_argument('root',type=Path);a=p.parse_args();root=a.root.resolve()
    if not root.is_relative_to(REPO/'artifacts/results'):raise SystemExit('root must be under artifacts/results')
    if a.stage=='init':
        if root.exists():raise SystemExit('Refusing to overwrite result directory')
        root.mkdir();tracked=subprocess.check_output(['git','ls-files','-z'],cwd=REPO).decode().split('\0')
        save(root/'baseline-source-sha256.json',{path:sha(REPO/path) for path in tracked if path and (REPO/path).is_file()})
        files=[file for base in ['artifacts/certs','artifacts/compact/batch16','artifacts/mtc/batch16-v2'] for file in (REPO/base).rglob('*') if file.is_file()]
        save(root/'fixture-sha256.json',{str(file.relative_to(REPO)):sha(file) for file in files})
        commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip();status=subprocess.check_output(['git','status','--short'],cwd=REPO,text=True)
        save(root/'metadata.json',{'experiment':'packet-loss-only','preparation_commit':commit,'git_commit_before':commit,'git_status_before':status,'base_image_ref':BASE_IMAGE,'base_image_id':None,'loss_conditions_percent':LOSSES,'configured_rtt_ms':RTT_MS,'handshake_timeout_seconds':HANDSHAKE_TIMEOUT_SECONDS,'campaigns_per_condition':5,'warmup_rounds':5,'measured_rounds':30,'loss_scope':'independent percentage on each endpoint egress; not end-to-end probability','bandwidth_limiter':False,'status':'initialized','git_commit_after_experiment':None})
    elif a.stage=='tests':
        save(root/'tests-status.json',{'passed':False,'state':'resolving images','image_ref':IMAGE,'base_image_ref':BASE_IMAGE})
        resolved=ensure('network');image=resolved['target'];base=resolved['images']['measurement']
        for command in ['tc','ping','nstat']:
            subprocess.run(['docker','run','--rm','--network','none',image['Id'],'sh','-c','command -v "$1"','sh',command],check=True,capture_output=True)
        with (root/'tests.log').open('w') as log:result=subprocess.run(['docker','run','--rm','--network','none','-v',str(REPO/'artifacts')+':/work:ro','-v',str(REPO/'campaigns/packet_loss_campaign')+':/opt/network-loss:ro',image['Id'],'sh','/opt/measurement/tests.sh'],stdout=log,stderr=subprocess.STDOUT)
        if result.returncode:
            save(root/'tests-status.json',{'passed':False,'exit_code':result.returncode,'image_id':image['Id'],'base_image_id':base['Id'],'required_tools':['tc','ping','nstat']})
            raise SystemExit('Regression failure; do not continue')
        save(root/'images.json',{'network_image':image,'base_image':base,'automatic_rebuilds':resolved['rebuilt']});(root/'environment.json').write_text(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True));verify(root)
        metadata=load(root/'metadata.json');metadata.update(base_image_id=base['Id'],network_image_id=image['Id']);save(root/'metadata.json',metadata)
        save(root/'tests-status.json',{'passed':True,'exit_code':0,'image_id':image['Id'],'base_image_id':base['Id'],'base_layers_verified':True,'required_tools':['tc','ping','nstat']})
    else:
        if not load(root/'tests-status.json')['passed'] or not load(root/'preflight-status.json')['passed'] or not load(root/'smoke-status.json')['passed'] or not load(root/'campaign-status.json')['passed'] or not load(root/'analysis-status.json')['passed']:raise SystemExit('A required gate is incomplete')
        counts=verify(root);snapshot=root/'source';snapshot.mkdir();shutil.copytree(REPO/'campaigns/packet_loss_campaign',snapshot/'campaigns/packet_loss_campaign',ignore=shutil.ignore_patterns('__pycache__'));(snapshot/'docker').mkdir();shutil.copyfile(REPO/'docker/compose.network-loss.yaml',snapshot/'docker/compose.network-loss.yaml');save(root/'source-sha256.json',{str(file.relative_to(snapshot)):sha(file) for file in snapshot.rglob('*') if file.is_file()})
        active=subprocess.check_output(['docker','ps','--filter','label=com.docker.compose.project=mtloss','--format','{{.ID}}'],text=True).strip()
        if active:raise RuntimeError('Experiment containers remain active')
        save(root/'preservation-after.json',{'passed':True,'checked_files':counts,'authentication_or_protocol_source_changed':False,'containers_stopped':True,'completed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
        metadata=load(root/'metadata.json');metadata.update(status='complete',network_image_id=load(root/'tests-status.json')['image_id'],authentication_or_protocol_source_changed=False);save(root/'metadata.json',metadata)
    print(a.stage,'PASS',root)
if __name__=='__main__':main()
