"""Manual packet-loss runner. No retries and no overwrite of campaign directories."""
import argparse,csv,datetime,hashlib,json,os,random,re,subprocess,sys
from pathlib import Path
from config import *
from network import *
from pcap_adapter import capture_session

REPO=Path(__file__).resolve().parents[3]
COMPOSE=['docker','compose','-f',str(REPO/'docker/original_campaigns/compose.network-loss.yaml')]
def load(path):return json.loads(path.read_text())
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def plan(root,mode):
    losses=['0'] if mode=='preflight' else (['0','1','5'] if mode=='smoke' else LOSSES);campaigns=[1] if mode in ['preflight','smoke'] else range(1,6);runs,warmups=(2,1) if mode=='preflight' else ((5,3) if mode=='smoke' else (30,5))
    return {'mode':mode,'output_directory':str(root),'loss_conditions_percent':losses,'campaigns':len(losses)*len(campaigns),'measured_attempts':len(losses)*len(campaigns)*runs*len(SCENARIOS),'warmup_attempts':len(losses)*len(campaigns)*warmups*len(SCENARIOS),'seeds':[{'loss_target_percent':loss,'campaign':i,'seed':seed(loss,i)} for loss in losses for i in campaigns],'commands':{'compose':' '.join(COMPOSE),'server_qdisc':'tc qdisc replace dev eth0 root netem delay 25ms loss LOSS%','client':'docker compose run --rm client measure ...'},'network':'independent symmetric per-egress loss and 25ms delay; no bandwidth limiter','timeout_seconds':HANDSHAKE_TIMEOUT_SECONDS,'probe_packets':200 if mode!='full' else 2000}
def hashes(root):
    for name in ['baseline-source-sha256.json','fixture-sha256.json']:
        for path,digest in load(root/name).items():
            if hashlib.sha256((REPO/path).read_bytes()).hexdigest()!=digest:raise RuntimeError('Preservation mismatch: '+path)
def enrich(path,condition,success):
    if not path.exists():return []
    rows=list(csv.DictReader(path.open()));
    if not rows:return []
    fields=list(rows[0])+[k for k in condition if k not in rows[0]]
    if 'success' not in fields:fields.append('success')
    for row in rows:row.update(condition,success=success)
    with path.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
    return rows
def empty_failures(path):
    if path.exists():return
    fields=['experiment','loss_target_percent','campaign_id','round_id','seed','scenario','order_in_round','is_warmup','success','failure_reason','timeout','TLS_error','returncode']
    with path.open('w',newline='') as f:csv.DictWriter(f,fieldnames=fields).writeheader()
def validate_observations(directory,condition,runs,warmups):
    successes=[];failures=read_csv(directory/'failures.csv')
    for name,count,warm in [('samples.csv',runs,0),('warmups.csv',warmups,1)]:
        good=enrich(directory/name,condition,1);bad=[r for r in failures if int(r['is_warmup'])==warm];expected=count*len(SCENARIOS)
        if len(good)+len(bad)!=expected:raise RuntimeError(f'Attempt accounting mismatch: {name}')
        rounds={i:{s:0 for s in SCENARIOS} for i in range(1,count+1)}
        for row in good+bad:
            if row['scenario'] not in SCENARIOS or int(row['round_id']) not in rounds:raise RuntimeError('Observation identity mismatch')
            rounds[int(row['round_id'])][row['scenario']]+=1
        if any(v!=1 for round_ in rounds.values() for v in round_.values()):raise RuntimeError('Missing/duplicate scenario attempt')
        for row in good:
            log=(directory/'logs'/f'{"warmup" if warm else "sample"}-{int(row["round"]):04d}-{row["scenario"]}.log').read_text()
            if 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384' not in log or 'Shared groups: x25519' not in log or 'no client certificate available' not in log or float(row['certificate_verify_bytes'])<=0:raise RuntimeError('TLS controls missing')
            if '-compact-' in row['scenario'] and 'Compact verification: OK' not in log:raise RuntimeError('Compact fallback/failure')
            if '-mtc-experimental-' in row['scenario'] and 'MTC verification: OK' not in log:raise RuntimeError('MTC fallback/failure')
        successes+=good
    return successes,failures
def read_csv(path):
    with path.open() as f:return list(csv.DictReader(f))
def parse_nstat(text):
    values={}
    for name in ['TcpRetransSegs','TcpOutSegs','TcpInSegs']:
        match=re.search(r'^'+name+r'\s+(\d+)',text,re.M)
        if not match:raise RuntimeError('Missing nstat '+name)
        values[name]=int(match.group(1))
    return values
def execute(root,mode,pcap=False):
    gate=load(root/'tests-status.json');image=json.loads(subprocess.check_output(['docker','image','inspect',IMAGE],text=True))[0]['Id']
    if not gate['passed'] or gate['image_id']!=image:raise SystemExit('ABORT: tested image mismatch')
    if mode!='preflight' and not load(root/'preflight-status.json')['passed']:raise SystemExit('ABORT: preflight has not passed')
    if mode=='full' and not load(root/'smoke-status.json')['passed']:raise SystemExit('ABORT: smoke has not passed')
    hashes(root);spec=plan(root,mode);losses=spec['loss_conditions_percent'];campaign_ids=[1] if mode in ['preflight','smoke'] else range(1,6);runs,warmups=(2,1) if mode=='preflight' else ((5,3) if mode=='smoke' else (30,5));probe_packets=spec['probe_packets']
    if pcap: spec.update(pcap_enabled=True,measurement_population='pcap-enabled; separate from uncaptured')
    status_path=root/(mode+'-status.json' if mode!='full' else 'campaign-status.json')
    if status_path.exists():raise SystemExit('Refusing to overwrite or retry')
    output=root/(mode if mode!='full' else 'campaigns');output.mkdir();status={'experiment':'packet-loss-only','mode':mode,'passed':False,'image_id':image,'failed_campaign':None,'campaigns':[],'expected':spec};save(status_path,status)
    env=os.environ.copy();env['MEASUREMENT_PCAP']='1' if pcap else '0';env['MEASUREMENT_RUN_ROOT']='/work/'+str(output.relative_to(REPO/'artifacts'));env['LOSS_PROBE_PACKETS']=str(probe_packets);env['HANDSHAKE_TIMEOUT_SECONDS']=str(HANDSHAKE_TIMEOUT_SECONDS);resources0=network0=None;containers=set()
    try:
        for loss in losses:
            for index in campaign_ids:
                campaign_seed=seed(loss,index);slug=loss.replace('.','p');cid=f'loss-{slug}-c{index}';directory=output/cid;directory.mkdir();env.update(MEASUREMENT_CAMPAIGN_ID=cid,MEASUREMENT_SEED=str(campaign_seed),LOSS_TARGET_PERCENT=loss)
                rec={'campaign_id':cid,'loss_target_percent':loss,'loss_code':LOSS_CODES[loss],'configured_rtt_ms':RTT_MS,'client_egress_loss_percent':loss,'server_egress_loss_percent':loss,'loss_scope':'independent per-direction netem probability; not end-to-end probability','seed':campaign_seed,'state':'starting','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()};status['campaigns'].append(rec);save(status_path,status)
                with (directory/'server-start.log').open('w') as log:subprocess.run(COMPOSE+['up','-d','--force-recreate','--wait','server'],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
                container=subprocess.check_output(COMPOSE+['ps','-q','server'],env=env,text=True).strip();cfg=json.loads(subprocess.check_output(['docker','inspect',container],text=True))[0]
                if container in containers or cfg['Image']!=image:raise RuntimeError('Server/image mismatch')
                containers.add(container);resources={k:cfg['HostConfig'].get(k) for k in ['NanoCpus','CpuQuota','CpusetCpus','Memory','MemorySwap','PidsLimit']};network={k:v['NetworkID'] for k,v in cfg['NetworkSettings']['Networks'].items()}
                if resources0 is None:resources0,network0=resources,network
                if resources!=resources0 or network!=network0:raise RuntimeError('Resource/network changed')
                # replace removes any root TBF/HTB inherited in this fresh namespace.
                subprocess.run(['docker','exec',container,'tc','qdisc','replace','dev','eth0','root','netem','delay','25ms','loss',loss+'%'],check=True)
                server_before=subprocess.check_output(['docker','exec',container,'tc','-s','qdisc','show','dev','eth0'],text=True);validate_qdisc(server_before,loss);(directory/'server-qdisc-before.txt').write_text(server_before)
                tcp_server_before=parse_nstat(subprocess.check_output(['docker','exec',container,'nstat','-az','TcpRetransSegs','TcpOutSegs','TcpInSegs'],text=True))
                probe_run=subprocess.run(COMPOSE+['run','--rm','client','probe'],env=env,text=True,capture_output=True,check=True);probe_text=probe_run.stdout+probe_run.stderr;(directory/'network-validation.log').write_text(probe_text);client_qdisc=section(probe_text,'QDISC_CLIENT_BEGIN','QDISC_CLIENT_END');validate_qdisc(client_qdisc,loss);probe=parse_ping(probe_text,probe_packets)
                if abs(probe['measured_rtt_median_ms']-RTT_MS)>10:raise RuntimeError('Measured RTT outside predeclared ±10ms operational gate')
                if loss=='0' and probe['loss_measured_percent']!=0:raise RuntimeError('Unexpected loss in zero-loss condition')
                with capture_session(COMPOSE,directory,env,pcap,runs*len(SCENARIOS)):
                    with (directory/'driver.log').open('w') as log:subprocess.run(COMPOSE+['run','--rm','client','measure','--runs',str(runs),'--warmup',str(warmups),'--seed',str(campaign_seed),'--image-id',image,'--scenarios',*SCENARIOS],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
                empty_failures(directory/'failures.csv');condition={'experiment':'packet-loss-only','loss_target_percent':loss,'configured_rtt_ms':RTT_MS,'rtt_measured_ms':probe['measured_rtt_median_ms']};successes,failures=validate_observations(directory,condition,runs,warmups)
                driver=(directory/'driver.log').read_text();client_after=section(driver,'QDISC_CLIENT_AFTER_BEGIN','QDISC_CLIENT_AFTER_END');validate_qdisc(client_after,loss);server_after=subprocess.check_output(['docker','exec',container,'tc','-s','qdisc','show','dev','eth0'],text=True);validate_qdisc(server_after,loss);(directory/'client-qdisc-after.txt').write_text(client_after);(directory/'server-qdisc-after.txt').write_text(server_after)
                cb=counters(driver,'CLIENT_BEFORE');ca=counters(driver,'CLIENT_AFTER');tcp_server_after=parse_nstat(subprocess.check_output(['docker','exec',container,'nstat','-az','TcpRetransSegs','TcpOutSegs','TcpInSegs'],text=True));tcp={'client':delta(cb,ca),'server':delta(tcp_server_before,tcp_server_after)};save(directory/'tcp-counters.json',tcp)
                validation={'passed':True,**probe,'configured_rtt_ms':RTT_MS,'loss_target_percent':loss,'client_qdisc':client_qdisc,'server_qdisc':server_after,'unexpected_bandwidth_limiter':False,'qdisc_dropped_packets':qdisc_drops(client_after)+qdisc_drops(server_after),'successful_attempts':len(successes),'failed_attempts':len(failures),'timeout_seconds':HANDSHAKE_TIMEOUT_SECONDS,'low_loss_note':'qdisc configuration is authoritative; finite probes need not observe exactly the target probability'};save(directory/'validation.json',validation)
                rec.update(state='complete',measured_attempts=runs*6,warmup_attempts=warmups*6,successful_attempts=len(successes),failed_attempts=len(failures),**probe,tcp_counters=tcp,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat());save(status_path,status);print(cid,'PASS',len(successes),'successes',len(failures),'failures',flush=True)
        hashes(root);status['passed']=True;save(status_path,status)
    except BaseException as error:
        status['failed_campaign']=status['campaigns'][-1]['campaign_id'] if status['campaigns'] else None;status['error']=repr(error)
        if status['campaigns']:status['campaigns'][-1]['state']='invalid'
        save(status_path,status);raise
    finally:
        with (root/(mode+'-shutdown.log')).open('w') as log:subprocess.run(COMPOSE+['down'],env=env,stdout=log,stderr=subprocess.STDOUT,check=False)
def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--pcap',action='store_true');m=p.add_mutually_exclusive_group();m.add_argument('--preflight',action='store_true');m.add_argument('--smoke',action='store_true');m.add_argument('--dry-run',action='store_true');a=p.parse_args();root=a.root.resolve();mode='preflight' if a.preflight else ('smoke' if a.smoke else 'full')
    if a.dry_run:
        spec=plan(root,'full')
        if a.pcap: spec.update(pcap_enabled=True,measurement_population='pcap-enabled; separate from uncaptured')
        print(json.dumps(spec,indent=2));return
    if not root.is_relative_to(REPO/'artifacts/results'):raise SystemExit('root must be under artifacts/results')
    execute(root,mode,a.pcap)
if __name__=='__main__':main()
