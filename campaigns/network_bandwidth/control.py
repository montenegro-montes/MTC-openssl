"""Initialize, gate and audit one bandwidth-only result directory."""
import argparse,datetime,hashlib,json,os,shutil,subprocess,sys
from pathlib import Path

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'campaigns'))
from common.image_chain import ensure
IMAGE='mt-tls-network:latency'
BASE='mt-tls-measurement:local'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def load(path):return json.loads(path.read_text())
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def verify(root):
    counts={}
    for name in ['baseline-source-sha256.json','fixture-sha256.json']:
        values=load(root/name)
        for path,digest in values.items():
            if not (REPO/path).is_file() or sha(REPO/path)!=digest:raise RuntimeError('Preservation mismatch: '+path)
        counts[name]=len(values)
    return counts
def main():
    p=argparse.ArgumentParser();p.add_argument('stage',choices=['init','tests','audit']);p.add_argument('root',type=Path);a=p.parse_args();root=a.root.resolve()
    if a.stage=='init':
        if root.exists():raise SystemExit('Refusing to overwrite output')
        root.mkdir();tracked=subprocess.check_output(['git','ls-files','-z'],cwd=REPO).decode().split('\0')
        save(root/'baseline-source-sha256.json',{s:sha(REPO/s) for s in tracked if s and (REPO/s).is_file()})
        files=[f for b in ['artifacts/certs','artifacts/compact/batch16','artifacts/mtc/batch16-v2'] for f in (REPO/b).rglob('*') if f.is_file()]
        save(root/'fixture-sha256.json',{str(f.relative_to(REPO)):sha(f) for f in files})
        save(root/'metadata.json',{'experiment':'bandwidth-limited','git_commit_before':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),'git_status_before':subprocess.check_output(['git','status','--short'],cwd=REPO,text=True),'base_image_ref':BASE,'base_image_id':None,'rtt_targets_ms':[10,50,100],'bandwidth_targets_mbps':[100,20,10,5,1],'goodput_acceptance_ratio':[0.80,1.05],'goodput_scope':'mean TCP payload rate over the final two non-omitted one-second iperf3 intervals, independently per direction','goodput_gate_revision':'Frozen before the definitive experiment after excluded runs showed that whole-run TCP averages confound slow-start with TBF steady capacity at high bandwidth-delay product','rate_scope':'per direction; same TBF rate on client and server egress','tbf_burst_policy':'max(1600 bytes, ten milliseconds of configured rate); conservative rate/HZ sizing with HZ=100','queue_latency_ms':1000,'status':'initialized','git_commit_after_experiment':None})
    elif a.stage=='tests':
        save(root/'tests-status.json',{'passed':False,'state':'running','image_ref':IMAGE,'base_image_ref':BASE})
        if not os.access(REPO/'campaigns/network_bandwidth/client.sh',os.X_OK):raise RuntimeError('campaigns/network_bandwidth/client.sh is not executable')
        resolved=ensure('network');image=resolved['target'];base=resolved['images']['measurement']
        with (root/'tests.log').open('w') as log:r=subprocess.run(['docker','run','--rm','--network','none','-v',str(REPO/'artifacts')+':/work:ro',image['Id'],'sh','/opt/measurement/tests.sh'],stdout=log,stderr=subprocess.STDOUT)
        if r.returncode:
            save(root/'tests-status.json',{'passed':False,'exit_code':r.returncode,'image_id':image['Id'],'base_image_id':base['Id'],'error':'Regression failure'})
            raise SystemExit('Regression failure')
        save(root/'images.json',{'network_image':image,'base_image':base,'automatic_rebuilds':resolved['rebuilt']});(root/'environment.json').write_text(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True));verify(root)
        metadata=load(root/'metadata.json');metadata.update(base_image_id=base['Id'],network_image_id=image['Id']);save(root/'metadata.json',metadata)
        save(root/'tests-status.json',{'passed':True,'exit_code':0,'image_id':image['Id'],'base_image_id':base['Id'],'base_image_ref':BASE,'base_layers_verified':True})
    else:
        if not load(root/'campaign-status.json')['passed'] or not load(root/'analysis-status.json')['passed']:raise SystemExit('Experiment incomplete')
        counts=verify(root);snapshot=root/'source';snapshot.mkdir();shutil.copytree(REPO/'campaigns/network_bandwidth',snapshot/'campaigns/network_bandwidth',ignore=shutil.ignore_patterns('__pycache__'));(snapshot/'docker').mkdir();shutil.copyfile(REPO/'docker/compose.network-bandwidth.yaml',snapshot/'docker/compose.network-bandwidth.yaml')
        save(root/'source-sha256.json',{str(f.relative_to(snapshot)):sha(f) for f in snapshot.rglob('*') if f.is_file()})
        active=subprocess.check_output(['docker','ps','--filter','label=com.docker.compose.project=mtbandwidth','--format','{{.ID}}'],text=True).strip()
        if active:raise RuntimeError('Bandwidth containers remain active')
        save(root/'preservation-after.json',{'passed':True,'checked_files':counts,'protocol_source_changed':False,'containers_stopped':True,'completed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()})
        meta=load(root/'metadata.json');meta.update(status='complete',network_image_id=load(root/'tests-status.json')['image_id'],protocol_source_changed=False);save(root/'metadata.json',meta)
    print(a.stage,'PASS',root)
if __name__=='__main__':main()
