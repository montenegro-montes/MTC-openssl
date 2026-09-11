"""Five campaigns per N, frozen primary driver, separate existing detail timers."""
import argparse,csv,datetime,hashlib,json,os,random,re,subprocess
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
SIZES=[1,4,16,64,256,1024]
PRIMARY=[f+s for f in ['classic','pq'] for s in ['', '-rpk','-compact-warm','-compact-cold','-mtc-experimental-standalone','-mtc-experimental-landmark']]
DETAIL=[s for s in PRIMARY if s.startswith('pq-') and not s.endswith('-rpk')]
def dump(path,data):path.write_text(json.dumps(data,indent=2)+'\n')
def read(path):return json.loads(path.read_text())
def validate(directory,scenarios,seed,n,detail,runs,warmups):
 rng=random.Random(seed);seen=set();component_rows=[]
 for filename,count,warm in [('warmups.csv',warmups,1),('samples.csv',runs,0)]:
  rows=list(csv.DictReader((directory/filename).open()));assert len(rows)==len(scenarios)*count
  for round_id in range(1,count+1):
   order=scenarios.copy();rng.shuffle(order);batch=[r for r in rows if int(r['round_id'])==round_id];assert [r['scenario'] for r in batch]==order
   assert [int(r['scenario_order']) for r in batch]==list(range(1,len(order)+1))
  for row in rows:
   assert int(row['tree_size'])==n and int(row['seed'])==seed and int(row['is_warmup'])==warm
   key=row['client_random'];assert key not in seen;seen.add(key)
   log=(directory/'logs'/f'{"warmup" if warm else "sample"}-{int(row["round"]):04d}-{row["scenario"]}.log').read_text()
   assert 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384' in log and 'Peer Temp Key: X25519' in log and 'no client certificate available' in log
   assert float(row['certificate_verify_bytes'])>0
   assert float(row['transport_total_bytes'])==float(row['transport_read_bytes'])+float(row['transport_written_bytes'])
   client=json.loads(re.findall(r'^PROFILE_METRICS (\{.*\})$',log,re.M)[0]);server=read(directory/'server-metrics'/f'{key}.json')
   for side,m in [('client',client),('server',server)]:
    assert m['detail']==detail and m['profile_valid'] and not m['reused'] and m['client_random']==key and m['side']==side
    assert m['server_cert_type']==(2 if '-compact-' in row['scenario'] or row['scenario'].endswith('-rpk') else 0)
    for name,values in m['components'].items():
     if not detail:assert values['calls']==0
     else:component_rows.append({'tree_size':n,'campaign_id':row['campaign_id'],'round_id':row['round_id'],'seed':seed,'scenario_order':row['scenario_order'],'is_warmup':warm,'scenario':row['scenario'],'side':side,'component':name,**values})
   if '-compact-' in row['scenario']:
    assert 'Compact verification: OK' in log
    if detail:assert client['components']['merkle_proof']['calls']==1
   if '-mtc-experimental-' in row['scenario']:assert 'MTC verification: OK' in log
   if detail:
    assert client['components']['certificate_verify_verify']['calls']==1 and server['components']['certificate_verify_sign']['calls']==1
  if filename=='samples.csv':measured=len(rows)
 if detail and component_rows:
  with (directory/'components.csv').open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(component_rows[0]));w.writeheader();w.writerows(component_rows)
 meta=read(directory/'metadata.json');assert meta['configuration']['detail']==detail
 for family in ['classic','pq']:assert meta['fixture'][family]['tree_size']==n and meta['compact'][family]['leaves']==n
 dump(directory/'validation.json',{'passed':True,'measured_handshakes':measured,'warmup_handshakes':len(scenarios)*warmups,'tree_size':n,'mode':'detail' if detail else 'primary','checks':['TLS1.3/X25519/cipher','no resumption','CertificateVerify active','expected cert type and auth success','MTC success requires negotiated/confirmed exact trust ID including landmark suffix','randomized round membership','signed fixture population linked by immutable paths and input hashes'],'tree_size_evidence':'sample metadata plus hashed credential/proof/checkpoint files; native log does not separately print population N'})
 return measured,len(scenarios)*warmups

def main():
 p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('--preflight',action='store_true');a=p.parse_args();root=a.root.resolve()
 gate=read(root/'tests-status.json');assert gate['passed'];image=gate['image_id'];assert json.loads(subprocess.check_output(['docker','image','inspect',image],text=True))[0]['Id']==image
 for name in ['baseline-source-sha256.json','fixture-sha256.json','scaling-fixture-sha256.json']:
  for file,h in read(root/name).items():assert hashlib.sha256((REPO/file).read_bytes()).hexdigest()==h,file
 if not a.preflight:assert read(root/'preflight-status.json')['passed']
 statepath=root/('preflight-status.json' if a.preflight else 'campaign-status.json');assert not statepath.exists()
 state={'passed':False,'image_id':image,'campaigns':[],'failed_campaign':None};dump(statepath,state)
 base=['docker','compose','-f',str(REPO/'docker/compose.scaling.yaml')];env=os.environ.copy();env['SCALING_IMAGE']=image;env['SCALING_FIXTURES']=read(root/'fixture-location.json')['container']
 output=root/('preflight' if a.preflight else 'campaigns');output.mkdir();env['MEASUREMENT_RUN_ROOT']='/work/'+str(output.relative_to(REPO/'artifacts'))
 resources0=None;network0=None;containers=set()
 try:
  for detail in [0,1]:
   scenarios=DETAIL if detail else PRIMARY
   for n in ([1,16,1024] if a.preflight else SIZES):
    for index in ([1] if a.preflight else range(1,6)):
     seed=1000*index+n;cid=f'{"detail" if detail else "primary"}-n{n}-c{index}';directory=output/cid;assert not directory.exists();directory.mkdir()
     env.update(TREE_SIZE=str(n),SCALING_DETAIL=str(detail),MEASUREMENT_CAMPAIGN_ID=cid,MEASUREMENT_SEED=str(seed))
     record={'campaign_id':cid,'tree_size':n,'seed':seed,'detail':detail,'state':'starting','started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()};state['campaigns'].append(record);dump(statepath,state)
     with (directory/'server-start.log').open('w') as log:subprocess.run(base+['up','-d','--force-recreate','--wait','server'],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
     container=subprocess.check_output(base+['ps','-q','server'],env=env,text=True).strip();assert container not in containers;containers.add(container)
     cfg=json.loads(subprocess.check_output(['docker','inspect',container],text=True))[0]
     resources={k:cfg['HostConfig'].get(k) for k in ['NanoCpus','CpuPeriod','CpuQuota','CpuShares','CpusetCpus','Memory','MemorySwap','MemoryReservation','PidsLimit']};network={k:v['NetworkID'] for k,v in cfg['NetworkSettings']['Networks'].items()}
     if resources0 is None:resources0=resources;network0=network
     assert resources==resources0 and network==network0
     dump(directory/'environment.json',{'container_id':container,'resources':resources,'network':network,'image_id':cfg['Image'],'started_at':cfg['State']['StartedAt']});assert cfg['Image']==image
     runs,warmups=(2,1) if a.preflight else (30,5)
     with (directory/'driver.log').open('w') as log:subprocess.run(base+['run','--rm','client','python3','/opt/scaling/detail_measure.py' if detail else '/opt/measurement/measure.py','--runs',str(runs),'--warmup',str(warmups),'--seed',str(seed),'--image-id',image,'--scenarios',*scenarios],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
     count,warm=validate(directory,scenarios,seed,n,detail,runs,warmups);record.update(state='complete',measured_handshakes=count,warmup_handshakes=warm,finished_utc=datetime.datetime.now(datetime.timezone.utc).isoformat());dump(statepath,state)
     print(cid,'PASS',count,'measured',warm,'warmup',flush=True)
  state['passed']=True;dump(statepath,state)
 except BaseException as e:
  if state['campaigns']:state['failed_campaign']=state['campaigns'][-1]['campaign_id'];state['campaigns'][-1]['state']='failed'
  state['error']=repr(e);dump(statepath,state);raise
 finally:
  with (root/('preflight-shutdown.log' if a.preflight else 'shutdown.log')).open('w') as log:subprocess.run(base+['down'],env=env,stdout=log,stderr=subprocess.STDOUT,check=True)
if __name__=='__main__':main()
