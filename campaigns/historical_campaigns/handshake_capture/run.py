"""Host orchestration for a separate, non-performance packet capture."""
import argparse,datetime,hashlib,json,os,subprocess,time
from pathlib import Path
from config import SCENARIOS,SEED

REPO=Path(__file__).resolve().parents[3]
COMPOSE=['docker','compose','-f',str(REPO/'docker/historical_campaigns/compose.capture.yaml')]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def image(reference):return json.loads(subprocess.check_output(['docker','image','inspect',reference],text=True))[0]
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--scenarios',nargs='+',choices=SCENARIOS,default=SCENARIOS);args=parser.parse_args()
    root=args.root.resolve()
    if not root.is_relative_to(REPO/'artifacts/captures'):parser.error('root must be under artifacts/captures')
    if root.exists():parser.error('output exists; choose a new directory')
    root.mkdir(parents=True);tracked=subprocess.check_output(['git','ls-files','-z'],cwd=REPO).decode().split('\0')
    sources={p:sha(REPO/p) for p in tracked if p and (REPO/p).is_file()};measurement=image('mt-tls-measurement:local');capture=image('mt-tls-capture:local')
    metadata={'experiment':'diagnostic-handshake-capture','performance_results':False,'scenarios':args.scenarios,'seed':SEED,'git_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),'git_status':subprocess.check_output(['git','status','--short'],cwd=REPO,text=True),'source_sha256':sources,'images':{'measurement':{'reference':'mt-tls-measurement:local','id':measurement['Id']},'capture':{'reference':'mt-tls-capture:local','id':capture['Id']}},'capture':{'interface':'eth0','bpf_filter':'tcp portrange 4433-4446','snapshot_length':0,'tls_keylog':True},'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'status':'running'};save(root/'metadata.json',metadata)
    env=os.environ.copy();env.update(CAPTURE_ROOT=str(root),CAPTURE_SEED=str(SEED));passed=False
    try:
        with (root/'startup.log').open('w') as log:subprocess.run(COMPOSE+['up','-d','--force-recreate','--wait','server','capture'],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        time.sleep(1)
        with (root/'client-driver.log').open('w') as log:subprocess.run(COMPOSE+['run','--rm','client','python3','/opt/handshake-capture/client.py','--output','/capture','--scenarios',*args.scenarios],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        passed=True
    finally:
        subprocess.run(COMPOSE+['kill','-s','SIGINT','capture'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False);time.sleep(.5)
        (root/'tcpdump.log').write_text(subprocess.run(COMPOSE+['logs','--no-color','capture'],env=env,text=True,capture_output=True).stdout)
        with (root/'shutdown.log').open('w') as log:subprocess.run(COMPOSE+['down'],env=env,stdout=log,stderr=subprocess.STDOUT,check=False)
        preserved=all((REPO/path).is_file() and sha(REPO/path)==digest for path,digest in sources.items())
        metadata.update(status='captured' if passed and preserved else 'failed',source_preserved=preserved,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
        if (root/'handshakes.pcap').is_file():metadata['pcap_sha256']=sha(root/'handshakes.pcap');metadata['pcap_bytes']=(root/'handshakes.pcap').stat().st_size
        if (root/'tls.keys').is_file():metadata['tls_keylog_sha256']=sha(root/'tls.keys')
        save(root/'metadata.json',metadata)
    if metadata['status']!='captured':raise SystemExit('capture failed; inspect logs and source preservation')
    print(root)
if __name__=='__main__':main()
