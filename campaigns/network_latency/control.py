"""Initialize, test and audit one immutable latency experiment."""
import argparse,datetime,hashlib,json,shutil,subprocess,sys
from pathlib import Path

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'campaigns'))
from common.image_chain import ensure
BASE='mt-tls-measurement:local'
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value): path.write_text(json.dumps(value,indent=2)+'\n')
def load(path): return json.loads(path.read_text())
def hashes(root):
    counts={}
    for name in ['baseline-source-sha256.json','fixture-sha256.json']:
        values=load(root/name)
        for path,digest in values.items():
            if sha(REPO/path)!=digest: raise RuntimeError('Preservation mismatch: '+path)
        counts[name]=len(values)
    return counts
def main():
    p=argparse.ArgumentParser();p.add_argument('stage',choices=['init','tests','audit']);p.add_argument('root',type=Path);a=p.parse_args();root=a.root.resolve()
    if a.stage=='init':
        if root.exists(): raise SystemExit('Refusing to overwrite result directory')
        root.mkdir();tracked=subprocess.check_output(['git','ls-files','-z'],cwd=REPO).decode().split('\0')
        save(root/'baseline-source-sha256.json',{s:sha(REPO/s) for s in tracked if s and (REPO/s).is_file()})
        fixtures=[f for b in ['artifacts/certs','artifacts/compact/batch16','artifacts/mtc/batch16-v2'] for f in (REPO/b).rglob('*') if f.is_file()]
        save(root/'fixture-sha256.json',{str(f.relative_to(REPO)):sha(f) for f in fixtures})
        save(root/'metadata.json',{'experiment':'latency-only','git_commit_before':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),'git_status_before':subprocess.check_output(['git','status','--short'],cwd=REPO,text=True),'base_image_ref':BASE,'base_image_id':None,'rtt_targets_ms':[0,10,20,50,100,200],'campaigns_per_condition':5,'warmup_rounds':5,'measured_rounds':30,'status':'initialized'})
    elif a.stage=='tests':
        save(root/'tests-status.json',{'passed':False,'state':'resolving images','image_ref':'mt-tls-network:latency','base_image_ref':BASE})
        resolved=ensure('network');image=resolved['target'];base=resolved['images']['measurement']
        with (root/'tests.log').open('w') as log:r=subprocess.run(['docker','run','--rm','--network','none','-v',str(REPO/'artifacts')+':/work:ro',image['Id'],'sh','/opt/measurement/tests.sh'],stdout=log,stderr=subprocess.STDOUT)
        if r.returncode:
            save(root/'tests-status.json',{'passed':False,'exit_code':r.returncode,'image_id':image['Id'],'base_image_id':base['Id']})
            raise SystemExit('Regression failure')
        save(root/'images.json',{'network_image':image,'base_image':base,'automatic_rebuilds':resolved['rebuilt']});(root/'environment.json').write_text(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True));hashes(root)
        metadata=load(root/'metadata.json');metadata.update(base_image_id=base['Id'],network_image_id=image['Id']);save(root/'metadata.json',metadata)
        save(root/'tests-status.json',{'passed':True,'exit_code':0,'image_id':image['Id'],'base_image_id':base['Id'],'base_layers_verified':True})
    else:
        if not load(root/'campaign-status.json')['passed'] or not load(root/'analysis-status.json')['passed']: raise SystemExit('Incomplete experiment')
        counts=hashes(root);snapshot=root/'source';snapshot.mkdir();shutil.copytree(REPO/'campaigns/network_latency',snapshot/'campaigns/network_latency',ignore=shutil.ignore_patterns('__pycache__'));(snapshot/'docker').mkdir();shutil.copyfile(REPO/'docker/Dockerfile.network',snapshot/'docker/Dockerfile.network');shutil.copyfile(REPO/'docker/Dockerfile.network.dockerignore',snapshot/'docker/Dockerfile.network.dockerignore');shutil.copyfile(REPO/'docker/compose.network-latency.yaml',snapshot/'docker/compose.network-latency.yaml')
        save(root/'source-sha256.json',{str(f.relative_to(snapshot)):sha(f) for f in snapshot.rglob('*') if f.is_file()})
        active=subprocess.check_output(['docker','ps','--filter','label=com.docker.compose.project=mtlatency','--format','{{.ID}}'],text=True).strip()
        if active: raise RuntimeError('Latency containers remain active')
        save(root/'preservation-after.json',{'passed':True,'checked_files':counts,'protocol_source_changed':False,'containers_stopped':True,'completed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
        metadata=load(root/'metadata.json');metadata.update(status='complete',network_image_id=load(root/'tests-status.json')['image_id'],protocol_source_changed=False,git_commit_after_experiment=None);save(root/'metadata.json',metadata)
    print(a.stage,'PASS',root)
if __name__=='__main__':main()
