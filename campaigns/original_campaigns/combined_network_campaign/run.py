"""Manual combined-network runner: preflight, smoke, full or side-effect-free plan."""
import argparse,csv,datetime,hashlib,json,os,re,subprocess
from pathlib import Path
from config import *
from network import commands,own_tbf_drops,parse_iperf,parse_ping,qdisc_kind_drops,section,validate_qdisc,validate_throughput
REPO=Path(__file__).resolve().parents[3]
COMPOSE=['docker','compose','-f',str(REPO/'docker/original_campaigns/compose.network-combined.yaml')]
def load(p): return json.loads(p.read_text())
def save(p,v): p.write_text(json.dumps(v,indent=2)+'\n')
def design(mode, selected=None):
    names=['baseline'] if mode=='preflight' else (['baseline','constrained','adverse'] if mode=='smoke' else list(PROFILES))
    campaigns=[1] if mode!='full' else list(range(1,6)); runs,warm=(2,1) if mode=='preflight' else ((5,3) if mode=='smoke' else (30,5))
    scenarios=selected or SCENARIOS
    return {'mode':mode,'profiles':names,'profile_definitions':{n:PROFILES[n] for n in names},'campaigns_per_profile':len(campaigns),'measured_rounds':runs,'warmup_rounds':warm,'scenarios':scenarios,'measured_attempts':len(names)*len(campaigns)*runs*len(scenarios),'warmup_attempts':len(names)*len(campaigns)*warm*len(scenarios),'seeds':[{'profile':n,'campaign':c,'seed':seed(n,c)} for n in names for c in campaigns],'network_order':'root TBF then child netem for limited profiles; root netem for baseline','probe_packets':200 if mode!='full' else 2000,'timeout_seconds':TIMEOUT_SECONDS}
def verify_hashes(root):
    for name in ['baseline-source-sha256.json','fixture-sha256.json']:
        for path,digest in load(root/name).items():
            if hashlib.sha256((REPO/path).read_bytes()).hexdigest()!=digest: raise RuntimeError('preservation mismatch: '+path)
def rows(path):
    if not path.exists(): return []
    with path.open() as f:return list(csv.DictReader(f))
def add_fields(path, extra):
    data=rows(path)
    if not data:return data
    fields=list(data[0])+[k for k in extra if k not in data[0]]
    for row in data:row.update(extra)
    with path.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(data)
    return data
def ensure_failures(path):
    if path.exists():return
    fields=['experiment','network_profile','configured_loss_percent','campaign_id','round_id','seed','scenario','order_in_round','is_warmup','success','failure_reason','timeout','TLS_error','returncode']
    with path.open('w',newline='') as f:csv.DictWriter(f,fieldnames=fields).writeheader()
def validate_attempts(directory, good, failures, rounds, warmups, scenarios):
    for warm,count,label in [(False,rounds,'sample'),(True,warmups,'warmup')]:
        observed={(str(i),s):0 for i in range(1,count+1) for s in scenarios}
        selected=[r for r in good if (r.get('is_warmup','0')=='1')==warm]+[r for r in failures if (r.get('is_warmup','0')=='1')==warm]
        for row in selected:
            key=(row.get('round_id',row.get('round')),row['scenario'])
            if key not in observed:raise RuntimeError('observation identity mismatch')
            observed[key]+=1
        if any(v!=1 for v in observed.values()):raise RuntimeError('missing or duplicate attempt')
    for row in good:
        label='warmup' if row.get('is_warmup','0')=='1' else 'sample';number=int(row.get('round',row.get('round_id')))
        log=(directory/'logs'/f'{label}-{number:04d}-{row["scenario"]}.log').read_text()
        if 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384' not in log or 'Peer Temp Key: X25519' not in log or 'no client certificate available' not in log or float(row['certificate_verify_bytes'])<=0:raise RuntimeError('TLS controls missing')
        if '-compact-' in row['scenario'] and 'Compact verification: OK' not in log:raise RuntimeError('Compact fallback/failure')
        if '-mtc-experimental-' in row['scenario'] and 'MTC verification: OK' not in log:raise RuntimeError('MTC fallback/failure')
def parse_nstat(text):
    out={}
    for key in ['TcpRetransSegs','TcpOutSegs','TcpInSegs']:
        m=re.search(r'^'+key+r'\s+(\d+)',text,re.M)
        if not m:raise RuntimeError('missing '+key)
        out[key]=int(m.group(1))
    return out
def execute(root,mode,selected):
    spec=design(mode,selected); gate=load(root/'tests-status.json'); image=json.loads(subprocess.check_output(['docker','image','inspect',IMAGE],text=True))[0]['Id']
    if not gate['passed'] or gate['image_id']!=image:raise SystemExit('ABORT: tested image mismatch')
    if mode!='preflight' and not load(root/'preflight-status.json')['passed']:raise SystemExit('ABORT: preflight required')
    if mode=='full' and not load(root/'smoke-status.json')['passed']:raise SystemExit('ABORT: smoke required')
    verify_hashes(root); out=root/('campaigns' if mode=='full' else mode); status_path=root/('campaign-status.json' if mode=='full' else mode+'-status.json')
    if status_path.exists():raise SystemExit('refusing overwrite/retry')
    if out.exists():raise SystemExit('refusing existing output directory: '+str(out))
    out.mkdir()
    status={'experiment':'combined-network','passed':False,'failed_campaign':None,'expected':spec,'campaigns':[]};save(status_path,status)
    env=os.environ.copy(); campaigns=range(1,6) if mode=='full' else [1]
    try:
      for name in spec['profiles']:
       profile=PROFILES[name]
       for campaign in campaigns:
        cid=f'{name}-c{campaign}'; directory=out/cid;directory.mkdir(); s=seed(name,campaign)
        env.update(MEASUREMENT_RUN_ROOT='/work/'+str(out.relative_to(REPO/'artifacts')),MEASUREMENT_CAMPAIGN_ID=cid,MEASUREMENT_SEED=str(s),NETWORK_PROFILE_JSON=json.dumps(profile),LOSS_TARGET_PERCENT=profile['loss_percent'],PROBE_PACKETS=str(spec['probe_packets']),HANDSHAKE_TIMEOUT_SECONDS=str(TIMEOUT_SECONDS))
        rec={'campaign_id':cid,'profile':name,**profile,'seed':s,'state':'starting','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()};status['campaigns'].append(rec);save(status_path,status)
        with (directory/'server-start.log').open('w') as log:subprocess.run(COMPOSE+['up','-d','--force-recreate','--wait','server'],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        container=subprocess.check_output(COMPOSE+['ps','-q','server'],env=env,text=True).strip(); before=subprocess.check_output(['docker','exec',container,'tc','-s','qdisc','show','dev','eth0'],text=True);validate_qdisc(before,profile);(directory/'server-qdisc-before.txt').write_text(before)
        tcp0=parse_nstat(subprocess.check_output(['docker','exec',container,'nstat','-az','TcpRetransSegs','TcpOutSegs','TcpInSegs'],text=True))
        probe_run=subprocess.run(COMPOSE+['run','--rm','client','probe'],env=env,text=True,capture_output=True,check=True);probe_text=probe_run.stdout+probe_run.stderr;(directory/'network-validation.log').write_text(probe_text);validate_qdisc(section(probe_text,'QDISC_CLIENT_BEGIN','QDISC_CLIENT_END'),profile);probe=parse_ping(probe_text,spec['probe_packets']);throughput=parse_iperf(probe_text)
        if abs(probe['measured_rtt_median_ms']-profile['rtt_ms'])>10:raise RuntimeError('RTT outside +/-10 ms gate')
        validate_throughput(throughput,profile['rate_mbit'])
        with (directory/'driver.log').open('w') as log:subprocess.run(COMPOSE+['run','--rm','client','measure','--runs',str(spec['measured_rounds']),'--warmup',str(spec['warmup_rounds']),'--seed',str(s),'--image-id',image,'--scenarios',*spec['scenarios']],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        ensure_failures(directory/'failures.csv');failure=add_fields(directory/'failures.csv',{'experiment':'combined-network','network_profile':name,'configured_loss_percent':profile['loss_percent']});good=add_fields(directory/'samples.csv',{'experiment':'combined-network','network_profile':name,'is_warmup':'0','configured_rtt_ms':profile['rtt_ms'],'configured_bandwidth_mbit':profile['rate_mbit'] if profile['rate_mbit'] is not None else 'unconstrained','configured_loss_percent':profile['loss_percent'],'measured_rtt_ms':probe['measured_rtt_median_ms'],'measured_bandwidth_mbit':throughput});warm=add_fields(directory/'warmups.csv',{'experiment':'combined-network','network_profile':name,'is_warmup':'1'})
        expected=(spec['measured_rounds']+spec['warmup_rounds'])*len(spec['scenarios'])
        if len(good)+len(warm)+len(failure)!=expected:raise RuntimeError('attempt accounting mismatch')
        validate_attempts(directory,good+warm,failure,spec['measured_rounds'],spec['warmup_rounds'],spec['scenarios'])
        driver=(directory/'driver.log').read_text();client_after=section(driver,'QDISC_CLIENT_AFTER_BEGIN','QDISC_CLIENT_AFTER_END');validate_qdisc(client_after,profile);(directory/'client-qdisc-after.txt').write_text(client_after)
        after=subprocess.check_output(['docker','exec',container,'tc','-s','qdisc','show','dev','eth0'],text=True);validate_qdisc(after,profile);(directory/'server-qdisc-after.txt').write_text(after);server_drops=qdisc_kind_drops(after);client_drops=qdisc_kind_drops(client_after)
        server_tbf_own=own_tbf_drops(server_drops);client_tbf_own=own_tbf_drops(client_drops)
        if server_tbf_own or client_tbf_own:raise RuntimeError('unexpected TBF-own queue drops')
        tcp1=parse_nstat(subprocess.check_output(['docker','exec',container,'nstat','-az','TcpRetransSegs','TcpOutSegs','TcpInSegs'],text=True));save(directory/'tcp-counters.json',{k:tcp1[k]-tcp0[k] for k in tcp0})
        save(directory/'validation.json',{'passed':True,'profile':name,**profile,**probe,'measured_bandwidth_mbit':throughput,'bandwidth_gate':'positive descriptive throughput' if profile['rate_mbit'] is None else 'positive and no more than 15% above configured cap','server_qdisc_drops_by_kind':server_drops,'client_qdisc_drops_by_kind':client_drops,'server_tbf_own_drops':server_tbf_own,'client_tbf_own_drops':client_tbf_own,'tbf_parent_drop_accounting':'TBF raw total includes child netem drops; own=max(tbf-netem,0)','qdisc_configuration_authoritative_for_loss':True,'qdisc_configuration_authoritative_for_bandwidth_cap':True})
        rec.update(state='complete',measured_attempts=spec['measured_rounds']*len(spec['scenarios']),warmup_attempts=spec['warmup_rounds']*len(spec['scenarios']),successful_measured=len(good),failed_attempts=len(failure),**probe,measured_bandwidth_mbit=throughput);save(status_path,status)
      status['passed']=True;save(status_path,status);verify_hashes(root)
    except BaseException as e:
      status['failed_campaign']=status['campaigns'][-1]['campaign_id'] if status['campaigns'] else None;status['error']=repr(e);save(status_path,status);raise
    finally:
      with (root/(mode+'-shutdown.log')).open('w') as log:subprocess.run(COMPOSE+['down'],env=env,stdout=log,stderr=subprocess.STDOUT,check=False)
def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);g=p.add_mutually_exclusive_group();g.add_argument('--preflight',action='store_true');g.add_argument('--smoke',action='store_true');g.add_argument('--dry-run',action='store_true');p.add_argument('--scenarios',nargs='+',choices=SCENARIOS);a=p.parse_args();mode='preflight' if a.preflight else ('smoke' if a.smoke else 'full')
    if a.dry_run:print(json.dumps(design(mode,a.scenarios),indent=2));return
    root=a.root.resolve()
    if not root.is_relative_to(REPO/'artifacts/results'):raise SystemExit('root must be under artifacts/results')
    execute(root,mode,a.scenarios)
if __name__=='__main__':main()
