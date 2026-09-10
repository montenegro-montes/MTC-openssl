"""Latency-only campaigns using the frozen N=16 measurement driver."""
import argparse,csv,datetime,hashlib,json,os,random,re,subprocess
from pathlib import Path

REPO=Path(__file__).resolve().parents[2]
RTTS=[0,10,20,50,100,200]
SCENARIOS=['pq','pq-rpk','pq-compact-warm','pq-compact-cold','pq-mtc-experimental-landmark','pq-mtc-experimental-standalone']
COMPOSE=['docker','compose','-f',str(REPO/'docker/compose.network-latency.yaml')]

def load(path): return json.loads(path.read_text())
def save(path,value): path.write_text(json.dumps(value,indent=2)+'\n')
def parse_ping(text):
    values=[float(x) for x in re.findall(r'time=([0-9.]+) ms',text)]
    if len(values)!=20: raise RuntimeError(f'Expected 20 RTT probes, got {len(values)}')
    values.sort()
    return {'measured_rtt_min_ms':values[0],'measured_rtt_median_ms':(values[9]+values[10])/2,'measured_rtt_max_ms':values[-1],
            'probes_sent':20,'probes_received':len(values),'packet_loss_percent':0.0}
def hashes_ok(root):
    for name in ['baseline-source-sha256.json','fixture-sha256.json']:
        for path,digest in load(root/name).items():
            file=REPO/path
            if not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest()!=digest: raise RuntimeError('Preservation mismatch: '+path)
def enrich(path,values,experiment):
    rows=list(csv.DictReader(path.open()))
    fields=list(rows[0])+[k for k in values if k not in rows[0]]+['experiment']
    for row in rows: row.update(values,experiment=experiment)
    with path.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows(rows)
    return rows
def validate(directory,seed,rtt,runs,warmups,probe):
    seen=set()
    for filename,count,warm in [('warmups.csv',warmups,1),('samples.csv',runs,0)]:
        rows=enrich(directory/filename,{'rtt_target_ms':rtt,'rtt_measured_ms':probe['measured_rtt_median_ms']},'latency-only')
        if len(rows)!=count*len(SCENARIOS): raise RuntimeError('Wrong sample count')
        rng=random.Random(seed)
        if warm==0:
            for _ in range(warmups): order=SCENARIOS.copy();rng.shuffle(order)
        for round_id in range(1,count+1):
            order=SCENARIOS.copy();rng.shuffle(order)
            actual=sorted((r for r in rows if int(r['round_id'])==round_id),key=lambda r:int(r['order_in_round']))
            if [r['scenario'] for r in actual]!=order: raise RuntimeError('Randomization mismatch')
        for row in rows:
            if row['scenario'] not in SCENARIOS or int(row['tree_size'])!=16 or int(row['seed'])!=seed: raise RuntimeError('Sample identity mismatch')
            if row['client_random'] in seen: raise RuntimeError('Repeated handshake identity')
            seen.add(row['client_random'])
            log=(directory/'logs'/f'{"warmup" if warm else "sample"}-{int(row["round"]):04d}-{row["scenario"]}.log').read_text()
            if 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384' not in log or 'Peer Temp Key: X25519' not in log or 'no client certificate available' not in log: raise RuntimeError('TLS controls missing')
            if float(row['certificate_verify_bytes'])<=0: raise RuntimeError('CertificateVerify missing')
            if '-compact-' in row['scenario'] and 'Compact verification: OK' not in log: raise RuntimeError('Compact fallback/failure')
            if '-mtc-experimental-' in row['scenario'] and 'MTC verification: OK' not in log: raise RuntimeError('MTC fallback/failure')
    save(directory/'validation.json',{'passed':True,'tree_size':16,'seed':seed,'rtt_target_ms':rtt,**probe,
         'checks':['TLS1.3/X25519/cipher','no client authentication','no resumption','CertificateVerify active','expected Compact/MTC authentication marker','paired randomized rounds']})

def main():
    parser=argparse.ArgumentParser();parser.add_argument('root',type=Path);parser.add_argument('--smoke',action='store_true');args=parser.parse_args()
    root=args.root.resolve();gate=load(root/'tests-status.json')
    if not gate['passed']: raise SystemExit('ABORT: tests did not pass')
    image=json.loads(subprocess.check_output(['docker','image','inspect','mt-tls-network:latency'],text=True))[0]['Id']
    if image!=gate['image_id']: raise SystemExit('ABORT: untested image')
    hashes_ok(root)
    status_path=root/('smoke-status.json' if args.smoke else 'campaign-status.json')
    if status_path.exists(): raise SystemExit('Refusing to overwrite/retry')
    output=root/('smoke' if args.smoke else 'campaigns');output.mkdir()
    status={'experiment':'latency-only','image_id':image,'passed':False,'failed_campaign':None,'campaigns':[]};save(status_path,status)
    env=os.environ.copy();env['PAPER_RUN_ROOT']='/work/'+str(output.relative_to(REPO/'artifacts'))
    rtts=[0,50,100] if args.smoke else RTTS;campaigns=[1] if args.smoke else range(1,6);runs,warmups=(5,3) if args.smoke else (30,5)
    resources0=network0=None;containers=set()
    try:
        for rtt in rtts:
            for index in campaigns:
                seed=100000+rtt*100+index;cid=f'latency-rtt{rtt}-c{index}';directory=output/cid;directory.mkdir()
                env.update(PAPER_CAMPAIGN_ID=cid,PAPER_SEED=str(seed),NETWORK_HALF_DELAY_MS=str(rtt/2))
                record={'campaign_id':cid,'rtt_target_ms':rtt,'seed':seed,'state':'starting','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()};status['campaigns'].append(record);save(status_path,status)
                with (directory/'server-start.log').open('w') as log: subprocess.run(COMPOSE+['up','-d','--force-recreate','--wait','server'],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
                container=subprocess.check_output(COMPOSE+['ps','-q','server'],env=env,text=True).strip();cfg=json.loads(subprocess.check_output(['docker','inspect',container],text=True))[0]
                if container in containers or cfg['Image']!=image: raise RuntimeError('Server identity/image mismatch')
                containers.add(container);resources={k:cfg['HostConfig'].get(k) for k in ['NanoCpus','CpuPeriod','CpuQuota','CpusetCpus','Memory','MemorySwap','PidsLimit']};networks={k:v['NetworkID'] for k,v in cfg['NetworkSettings']['Networks'].items()}
                if resources0 is None: resources0,network0=resources,networks
                if resources!=resources0 or networks!=network0: raise RuntimeError('Resource/network changed')
                if rtt: subprocess.run(['docker','exec',container,'tc','qdisc','add','dev','eth0','root','netem','delay',f'{rtt/2}ms'],check=True)
                server_qdisc=subprocess.check_output(['docker','exec',container,'tc','-s','qdisc','show','dev','eth0'],text=True);(directory/'server-qdisc-before.txt').write_text(server_qdisc)
                probe_result=subprocess.run(COMPOSE+['run','--rm','client','probe'],env=env,text=True,capture_output=True,check=True);(directory/'network-probe.txt').write_text(probe_result.stdout+probe_result.stderr);(directory/'network-validation.log').write_text(probe_result.stdout+probe_result.stderr);probe=parse_ping(probe_result.stdout+probe_result.stderr)
                tolerance=max(5.0,rtt*.15)
                if rtt and abs(probe['measured_rtt_median_ms']-rtt)>tolerance: raise RuntimeError('Measured RTT outside declared tolerance')
                if not rtt and probe['measured_rtt_median_ms']>3: raise RuntimeError('Unexpected baseline RTT')
                with (directory/'driver.log').open('w') as log: subprocess.run(COMPOSE+['run','--rm','client','measure','--runs',str(runs),'--warmup',str(warmups),'--seed',str(seed),'--image-id',image,'--scenarios',*SCENARIOS],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
                server_after=subprocess.check_output(['docker','exec',container,'tc','-s','qdisc','show','dev','eth0'],text=True);(directory/'server-qdisc-after.txt').write_text(server_after);(directory/'server-qdisc-statistics.txt').write_text(server_after)
                driver=(directory/'driver.log').read_text();match=re.search(r'QDISC_CLIENT_AFTER_BEGIN\n(.*?)QDISC_CLIENT_AFTER_END',driver,re.S)
                if not match: raise RuntimeError('Missing client qdisc statistics')
                (directory/'client-qdisc-statistics.txt').write_text(match.group(1))
                validate(directory,seed,rtt,runs,warmups,probe);record.update(state='complete',measured_handshakes=runs*6,warmup_handshakes=warmups*6,**probe,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat());save(status_path,status)
                print(cid,'PASS',runs*6,'measured',warmups*6,'warmup',flush=True)
        status['passed']=True;save(status_path,status);hashes_ok(root)
    except BaseException as error:
        status['failed_campaign']=status['campaigns'][-1]['campaign_id'] if status['campaigns'] else None;status['error']=repr(error)
        if status['campaigns']: status['campaigns'][-1]['state']='failed'
        save(status_path,status);raise
    finally:
        with (root/('smoke-shutdown.log' if args.smoke else 'shutdown.log')).open('w') as log: subprocess.run(COMPOSE+['down'],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
if __name__=='__main__': main()
