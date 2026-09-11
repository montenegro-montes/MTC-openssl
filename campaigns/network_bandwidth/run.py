"""Controlled RTT x per-direction bandwidth campaigns; aborts on validation or drops."""
import argparse,csv,datetime,hashlib,json,os,random,re,subprocess
from pathlib import Path

REPO=Path(__file__).resolve().parents[2]
RTTS=[10,50,100];RATES=[100,20,10,5,1]
SCENARIOS=['pq','pq-rpk','pq-compact-warm','pq-compact-cold','pq-mtc-experimental-landmark','pq-mtc-experimental-standalone']
COMPOSE=['docker','compose','-f',str(REPO/'docker/compose.network-bandwidth.yaml')]
def load(path):return json.loads(path.read_text())
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def burst(rate):return max(1600,int(rate*1_000_000/8/1000))
def parse_ping(text):
    values=sorted(float(x) for x in re.findall(r'time=([0-9.]+) ms',text))
    if len(values)!=20:raise RuntimeError('RTT probe loss/failure')
    return {'measured_rtt_min_ms':values[0],'measured_rtt_median_ms':(values[9]+values[10])/2,'measured_rtt_max_ms':values[-1],'ping_loss_percent':0.0}
def json_objects(text):
    decoder=json.JSONDecoder();objects=[];offset=0
    while True:
        start=text.find('{',offset)
        if start<0:break
        try:value,end=decoder.raw_decode(text[start:])
        except json.JSONDecodeError:offset=start+1;continue
        if isinstance(value,dict) and 'end' in value and 'sum_received' in value['end']:objects.append(value)
        offset=start+end
    return objects
def parse_probe(text,target):
    ping=parse_ping(text);objects=json_objects(text)
    if len(objects)!=2:raise RuntimeError('Expected forward and reverse iperf JSON')
    rates=[o['end']['sum_received']['bits_per_second']/1e6 for o in objects];retrans=[o['end'].get('sum_sent',{}).get('retransmits',0) for o in objects]
    result={**ping,'bandwidth_forward_mbps':rates[0],'bandwidth_reverse_mbps':rates[1],'bandwidth_measured_mbps':min(rates),'iperf_retransmits_forward':retrans[0],'iperf_retransmits_reverse':retrans[1]}
    if any(abs(v-target)/target>.15 for v in rates):raise RuntimeError(f'Throughput outside predeclared ±15% tolerance: {rates}')
    if any(retrans):raise RuntimeError(f'Unexpected iperf retransmissions: {retrans}')
    return result
def drops(text):return sum(int(x) for x in re.findall(r'dropped\s+(\d+)',text))
def hashes(root):
    for name in ['baseline-source-sha256.json','fixture-sha256.json']:
        for path,digest in load(root/name).items():
            if hashlib.sha256((REPO/path).read_bytes()).hexdigest()!=digest:raise RuntimeError('Preservation mismatch: '+path)
def enrich(path,condition,experiment):
    rows=list(csv.DictReader(path.open()));fields=list(rows[0])+[k for k in condition if k not in rows[0]]+['experiment']
    for row in rows:row.update(condition,experiment=experiment,theoretical_serialization_ms=float(row['transport_total_bytes'])*8/(float(condition['bandwidth_measured_mbps'])*1e3))
    if 'theoretical_serialization_ms' not in fields:fields.append('theoretical_serialization_ms')
    with path.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
    return rows
def validate(directory,seed,rtt,rate,runs,warmups,probe):
    seen=set()
    for filename,count,warm in [('warmups.csv',warmups,1),('samples.csv',runs,0)]:
        rows=enrich(directory/filename,{'rtt_target_ms':rtt,'rtt_measured_ms':probe['measured_rtt_median_ms'],'bandwidth_target_mbps':rate,'bandwidth_measured_mbps':probe['bandwidth_measured_mbps']},'bandwidth-limited')
        if len(rows)!=count*6:raise RuntimeError('Wrong sample count')
        rng=random.Random(seed)
        if not warm:
            for _ in range(warmups):order=SCENARIOS.copy();rng.shuffle(order)
        for round_id in range(1,count+1):
            order=SCENARIOS.copy();rng.shuffle(order);actual=sorted((x for x in rows if int(x['round_id'])==round_id),key=lambda x:int(x['order_in_round']))
            if [x['scenario'] for x in actual]!=order:raise RuntimeError('Order mismatch')
        for row in rows:
            if row['client_random'] in seen:raise RuntimeError('Duplicate handshake ID')
            seen.add(row['client_random']);log=(directory/'logs'/f'{"warmup" if warm else "sample"}-{int(row["round"]):04d}-{row["scenario"]}.log').read_text()
            if 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384' not in log or 'Peer Temp Key: X25519' not in log or 'no client certificate available' not in log or float(row['certificate_verify_bytes'])<=0:raise RuntimeError('TLS control failure')
            if '-compact-' in row['scenario'] and 'Compact verification: OK' not in log:raise RuntimeError('Compact failure/fallback')
            if '-mtc-experimental-' in row['scenario'] and 'MTC verification: OK' not in log:raise RuntimeError('MTC failure/fallback')
    save(directory/'validation.json',{'passed':True,'seed':seed,'rtt_target_ms':rtt,'bandwidth_target_mbps':rate,**probe,'qdisc_drops':0,'throughput_tolerance_percent':15})
def main():
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('--smoke',action='store_true');a=p.parse_args();root=a.root.resolve();gate=load(root/'tests-status.json')
    if not gate['passed']:raise SystemExit('ABORT: regression gate failed')
    image=json.loads(subprocess.check_output(['docker','image','inspect','mt-tls-network:latency'],text=True))[0]['Id']
    if image!=gate['image_id']:raise SystemExit('ABORT: image differs from tested image')
    hashes(root);status_path=root/('smoke-status.json' if a.smoke else 'campaign-status.json')
    if status_path.exists():raise SystemExit('Refusing to overwrite/retry')
    output=root/('smoke' if a.smoke else 'campaigns');output.mkdir();status={'experiment':'bandwidth-limited','passed':False,'image_id':image,'failed_campaign':None,'campaigns':[]};save(status_path,status)
    conditions=[(50,x) for x in [20,5,1]] if a.smoke else [(r,b) for r in RTTS for b in RATES];campaigns=[1] if a.smoke else range(1,6);runs,warmups=(5,3) if a.smoke else (30,5);env=os.environ.copy();env['MEASUREMENT_RUN_ROOT']='/work/'+str(output.relative_to(REPO/'artifacts'));resources0=network0=None;containers=set()
    try:
        for rtt,rate in conditions:
            for index in campaigns:
                code=RATES.index(rate)+1;seed=200000+rtt*1000+code*10+index;cid=f'bandwidth-rtt{rtt}-bw{rate}-c{index}';directory=output/cid;directory.mkdir();env.update(MEASUREMENT_CAMPAIGN_ID=cid,MEASUREMENT_SEED=str(seed),NETWORK_HALF_DELAY_MS=str(rtt/2),NETWORK_RATE_MBIT=str(rate),NETWORK_BURST_BYTES=str(burst(rate)),NETWORK_QUEUE_LATENCY_MS='1000')
                rec={'campaign_id':cid,'rtt_target_ms':rtt,'bandwidth_target_mbps':rate,'rate_scope':'per direction','burst_bytes':burst(rate),'queue_latency_ms':1000,'seed':seed,'state':'starting','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()};status['campaigns'].append(rec);save(status_path,status)
                with (directory/'server-start.log').open('w') as log:subprocess.run(COMPOSE+['up','-d','--force-recreate','--wait','server'],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
                container=subprocess.check_output(COMPOSE+['ps','-q','server'],env=env,text=True).strip();cfg=json.loads(subprocess.check_output(['docker','inspect',container],text=True))[0]
                if container in containers or cfg['Image']!=image:raise RuntimeError('Server/image mismatch')
                containers.add(container);resources={k:cfg['HostConfig'].get(k) for k in ['NanoCpus','CpuQuota','CpusetCpus','Memory','MemorySwap','PidsLimit']};network={k:v['NetworkID'] for k,v in cfg['NetworkSettings']['Networks'].items()}
                if resources0 is None:resources0,network0=resources,network
                if resources!=resources0 or network!=network0:raise RuntimeError('Resource/network changed')
                subprocess.run(['docker','exec',container,'tc','qdisc','add','dev','eth0','root','handle','1:','tbf','rate',f'{rate}mbit','burst',f'{burst(rate)}b','latency','1000ms'],check=True);subprocess.run(['docker','exec',container,'tc','qdisc','add','dev','eth0','parent','1:1','handle','10:','netem','delay',f'{rtt/2}ms'],check=True);subprocess.run(['docker','exec',container,'iperf3','-s','-D'],check=True)
                before=subprocess.check_output(['docker','exec',container,'tc','-s','qdisc','show','dev','eth0'],text=True);(directory/'server-qdisc-before.txt').write_text(before)
                probe_run=subprocess.run(COMPOSE+['run','--rm','client','probe'],env=env,text=True,capture_output=True);probe_text=probe_run.stdout+probe_run.stderr;(directory/'network-validation.log').write_text(probe_text)
                if probe_run.returncode:raise RuntimeError(f'Network probe failed with exit code {probe_run.returncode}; inspect {directory / "network-validation.log"}')
                probe=parse_probe(probe_text,rate)
                if abs(probe['measured_rtt_median_ms']-rtt)>max(4,rtt*.15):raise RuntimeError('Measured RTT outside tolerance')
                if drops(probe_text):raise RuntimeError('Probe qdisc drop')
                with (directory/'driver.log').open('w') as log:subprocess.run(COMPOSE+['run','--rm','client','measure','--runs',str(runs),'--warmup',str(warmups),'--seed',str(seed),'--image-id',image,'--scenarios',*SCENARIOS],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
                driver=(directory/'driver.log').read_text();server_after=subprocess.check_output(['docker','exec',container,'tc','-s','qdisc','show','dev','eth0'],text=True);(directory/'server-qdisc-after.txt').write_text(server_after);match=re.search(r'QDISC_CLIENT_AFTER_BEGIN\n(.*?)QDISC_CLIENT_AFTER_END',driver,re.S)
                if not match:raise RuntimeError('Missing client qdisc statistics')
                client_after=match.group(1);(directory/'client-qdisc-after.txt').write_text(client_after)
                if drops(server_after)+drops(client_after):raise RuntimeError('Bandwidth-only campaign invalid: qdisc drops')
                validate(directory,seed,rtt,rate,runs,warmups,probe);rec.update(state='complete',measured_handshakes=runs*6,warmup_handshakes=warmups*6,**probe,qdisc_drops=0,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat());save(status_path,status);print(cid,'PASS',runs*6,'measured',flush=True)
        status['passed']=True;save(status_path,status);hashes(root)
    except BaseException as error:
        status['failed_campaign']=status['campaigns'][-1]['campaign_id'] if status['campaigns'] else None;status['error']=repr(error)
        if status['campaigns']:status['campaigns'][-1]['state']='invalid'
        save(status_path,status);raise
    finally:
        with (root/('smoke-shutdown.log' if a.smoke else 'shutdown.log')).open('w') as log:subprocess.run(COMPOSE+['down'],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
if __name__=='__main__':main()
