"""Host-side gated campaign runner. Never retries or overwrites a campaign."""
import argparse,datetime,hashlib,json,os,subprocess,sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[3]
p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--preflight',action='store_true');p.add_argument('--pcap',action='store_true',help='Opt-in instrumented per-observation capture');a=p.parse_args();root=a.root.resolve()
if not root.is_relative_to(REPO/'artifacts/results'):p.error('root must be under artifacts/results')
base=['docker','compose','-f',str(REPO/'docker/original_campaigns/compose.measurement.yaml')]
image=json.loads(subprocess.check_output(['docker','image','inspect','mt-tls-measurement:local'],text=True))[0]
tests=json.loads((root/'tests-status.json').read_text())
if not tests['passed'] or tests['image_id']!=image['Id']:raise SystemExit('ABORT: current image has not passed tests')
if not a.preflight:
    gate=json.loads((root/'measurement-preflight-status.json').read_text())
    if not gate['passed'] or gate['image_id']!=image['Id']:raise SystemExit('ABORT: measurement preflight has not passed')
env=os.environ.copy();env['MEASUREMENT_PCAP']='1' if a.pcap else '0';env['MEASUREMENT_RUN_ROOT']='/work/'+str(root.relative_to(REPO/'artifacts'))
status_path=root/('preflight-run-status.json' if a.preflight else 'campaign-status.json')
if status_path.exists():raise SystemExit('Output status already exists; never silently repeat a campaign')
status={'image_id':image['Id'],'campaigns':[],'shared_docker_desktop_session':True,'failed_campaign':None}
if a.pcap:
    capture_image=json.loads(subprocess.check_output(['docker','image','inspect','mt-tls-capture:local'],text=True))[0]
    status.update(pcap_enabled=True,capture_image_id=capture_image['Id'],performance_comparable_to_uncaptured=False)
resource_baseline=None;network_baseline=None;seen_containers=set()
def hashes_unchanged():
    for name in ['baseline-source-sha256.json','fixture-sha256.json']:
        for path,digest in json.loads((root/name).read_text()).items():
            f=REPO/path
            if not f.exists() or hashlib.sha256(f.read_bytes()).hexdigest()!=digest:raise RuntimeError('Preservation failure: '+path)
def save():status_path.write_text(json.dumps(status,indent=2)+'\n')
try:
    hashes_unchanged()
    for index,seed in enumerate([42] if a.preflight else range(42,52),1):
        cid='measurement-preflight' if a.preflight else f'campaign-{index:02d}'
        directory=root/cid
        if directory.exists():raise RuntimeError('Directory already exists: '+cid)
        directory.mkdir();env.update(MEASUREMENT_CAMPAIGN_ID=cid,MEASUREMENT_SEED=str(seed))
        record={'pcap_enabled':a.pcap,'campaign_id':cid,'seed':seed,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'state':'starting'}
        status['campaigns'].append(record);save()
        if a.pcap:
            subprocess.run(base+['rm','-s','-f','capture'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
        with (directory/'server-start.log').open('w') as log:
            subprocess.run(base+['up','-d','--force-recreate','--wait','server'],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        container=subprocess.check_output(base+['ps','-q','server'],env=env,text=True).strip()
        current=json.loads(subprocess.check_output(['docker','inspect',container],text=True))[0]
        if container in seen_containers:raise RuntimeError('Server container was not recreated')
        seen_containers.add(container)
        names=['NanoCpus','CpuPeriod','CpuQuota','CpuShares','CpusetCpus','Memory','MemorySwap','MemoryReservation','PidsLimit']
        resources={k:current['HostConfig'].get(k) for k in names}
        networks={k:v['NetworkID'] for k,v in current['NetworkSettings']['Networks'].items()}
        if resource_baseline is None:resource_baseline=resources;network_baseline=networks
        if resource_baseline!=resources or network_baseline!=networks:raise RuntimeError('Resource/network configuration changed')
        record.update(server_container_id=container,server_started_at=current['State']['StartedAt'],resources=resources,networks=networks,state='measuring')
        (directory/'server-environment.json').write_text(json.dumps(record,indent=2)+'\n');save()
        client_options=[]
        if a.pcap:
            with (directory/'capture-start.log').open('w') as log:
                started=subprocess.run(base+['up','-d','--no-deps','--force-recreate','capture'],env=env,stdout=log,stderr=subprocess.STDOUT,check=False)
            record['capture_start_returncode']=started.returncode
            client_options=['-v',str(REPO/'campaigns/original_campaigns/controlled_n16_campaign')+':/opt/measurement:ro']
        try:
            with (directory/'driver.log').open('w') as log:
                subprocess.run(base+['run','--rm',*client_options,'client','python3','/opt/measurement/measure.py','--runs','2' if a.preflight else '30','--warmup','1' if a.preflight else '5','--seed',str(seed),'--image-id',image['Id']],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
        finally:
            if a.pcap:
                # Analysis runs only after the measurement driver stops.
                with (directory/'pcap-analysis.log').open('w') as log:
                    analyzed=subprocess.run(base+['run','--rm','--no-deps','capture','python3','/opt/measurement/capture.py','analyze',env['MEASUREMENT_RUN_ROOT']+'/'+cid],env=env,stdout=log,stderr=subprocess.STDOUT,check=False)
                record['pcap_analysis_returncode']=analyzed.returncode
                if analyzed.returncode:
                    (directory/'pcap-analysis-status.json').write_text(json.dumps({'status':'ANALYSIS_FAILURE','metrics':None,'reason':'analysis process failed; see pcap-analysis.log'})+'\n')
                subprocess.run(base+['stop','capture'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False)
                save()
        import csv
        rows=list(csv.DictReader((directory/'samples.csv').open()));warm=list(csv.DictReader((directory/'warmups.csv').open()))
        expected=2 if a.preflight else 30;warming=1 if a.preflight else 5
        scenarios=json.loads((directory/'metadata.json').read_text())['scenarios']
        assert len(scenarios)==14
        for group,n in [(rows,expected),(warm,warming)]:
            assert len(group)==14*n
            for r in range(1,n+1):
                batch=[x for x in group if int(x['round_id'])==r]
                assert sorted(x['scenario'] for x in batch)==sorted(scenarios)
                assert sorted(int(x['order_in_round']) for x in batch)==list(range(1,15))
            for row in group:
                assert row['campaign_id']==cid and int(row['seed'])==seed and int(row['tree_size'])==16
                assert float(row['transport_total_bytes'])==float(row['transport_read_bytes'])+float(row['transport_written_bytes'])
                assert float(row['certificate_verify_bytes'])>0
                if '-compact-' in row['scenario'] or '-mtc-experimental-' in row['scenario']:
                    assert float(row['setup_wall_ms'])>0 and float(row['setup_cpu_ms'])>0
                logname=('warmup' if int(row['is_warmup']) else 'sample')+f'-{int(row["round"]):04d}-{row["scenario"]}.log'
                text=(directory/'logs'/logname).read_text()
                assert 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384' in text
                assert 'Shared groups: x25519' in text
                assert 'no client certificate available' in text
        record.update(state='complete',measured_handshakes=len(rows),warmup_handshakes=len(warm),finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat());save()
        print(cid,'PASS',len(rows),'measured',len(warm),'warmup',flush=True)
    hashes_unchanged()
    (root/('measurement-preflight-status.json' if a.preflight else 'preservation-after.json')).write_text(json.dumps({'passed':True,'image_id':image['Id'],'source_and_fixture_hashes_unchanged':True},indent=2)+'\n')
except BaseException as error:
    if status['campaigns']:
        status['failed_campaign']=status['campaigns'][-1]['campaign_id'];status['campaigns'][-1]['state']='failed'
    status['error']=str(error);save();raise
finally:
    with (root/('preflight-shutdown.log' if a.preflight else 'shutdown.log')).open('w') as log:subprocess.run(base+['down'],env=env,stdout=log,stderr=subprocess.STDOUT,check=False)
