"""Host-side Docker orchestration. Run after /opt/mtc/prepare_scaling.py has completed."""
import argparse,csv,datetime,json,os,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--fixtures',default='/work/mtc/scaling-20260910');p.add_argument('--runs',type=int,default=3);p.add_argument('--sizes',nargs='+',type=int,default=[1,4,16,64,256,1024]);a=p.parse_args()
root=Path(__file__).resolve().parents[3];out=root/'artifacts/results'/('mtc-scaling-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));out.mkdir()
image=subprocess.check_output(['docker','image','inspect','mt-tls-mtc:local','--format','{{.Id}}'],text=True).strip();runs=[]
scenarios=[f'{f}-{s}' for f in ['classic','pq'] for s in ['compact-warm','compact-cold','mtc-experimental-standalone','mtc-experimental-landmark']]
base=['docker','compose','-f',str(root/'docker/original_campaigns/compose.mtc.yaml')]
try:
    for n in a.sizes:
        env=os.environ.copy();env.update(COMPACT_BATCH=f'{a.fixtures}/compact-{n}',MTC_BATCH=f'{a.fixtures}/mtc-{n}')
        with (out/f'server-{n}.log').open('w') as stream:subprocess.run(base+['up','-d','--force-recreate','--wait','server'],env=env,check=True,stdout=stream,stderr=subprocess.STDOUT)
        with (out/f'run-{n}.log').open('w') as stream:subprocess.run(base+['run','--rm','client','python3','/opt/mtc/benchmark.py','--runs',str(a.runs),'--image-id',image,'--scenarios',*scenarios],env=env,check=True,stdout=stream,stderr=subprocess.STDOUT)
        lines=(out/f'run-{n}.log').read_text().splitlines();path=next(x for x in reversed(lines) if x.startswith('/work/results/'))
        runs.append({'tree_size':n,'path':path.replace('/work/', 'artifacts/'),'rounds':a.runs});print(n,path,flush=True)
        (out/'manifest.json').write_text(json.dumps({'image_id':image,'runs':runs,'fixtures':a.fixtures,'kind':'exploratory scaling; independently generated MTC CA per N'},indent=2)+'\n')
finally:subprocess.run(base+['down'],check=False)
rows=[]
for run in runs:
    directory=root/run['path'];meta=json.loads((directory/'metadata.json').read_text())
    for r in csv.DictReader((directory/'summary.csv').open()):
        s=r['scenario'];family='pq' if s.startswith('pq') else 'classic';mtc='mtc-experimental' in s;n=run['tree_size']
        proof_bytes=meta['fixture'][family]['sizes'][s.rsplit('-',1)[1]]['mtc_inclusion_proof_bytes'] if mtc else meta['compact'][family]['proof0_bytes']
        rows.append({'tree_size':n,'scenario':s,'rounds':a.runs,'actual_proof_bytes':proof_bytes,
            'proof_definition':'MTC hash array only' if mtc else 'compact MTP1 encoded proof including root/header',
            'actual_encoded_proof_bytes':meta['fixture'][family]['sizes'][s.rsplit('-',1)[1]]['mtc_proof_encoded_bytes'] if mtc else proof_bytes,
            'theoretical_compact_hash_array_bytes':32*(n-1).bit_length() if not mtc else '',
            'theoretical_mtc_leaf0_hash_array_bytes':32*max(0,(n-1).bit_length()-1) if mtc and n&(n-1)==0 else '',
            'transport_total_bytes_median':r['transport_total_bytes_median'],'handshake_wall_ms_median':r['handshake_wall_ms_median'],
            'handshake_client_cpu_ms_median':r['handshake_client_cpu_ms_median'],'client_process_http_wall_ms_median':r['client_process_http_wall_ms_median'],
            'offline_setup_ms':meta['fixture'][family]['setup_ms'] if mtc else meta['compact'][family]['offline_timings']['snapshot_ms'],
            'client_trust_setup_ms_median':r['mtc_setup_ms_median'] if mtc else r['compact_root_setup_ms_median']})
with (out/'scaling.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
print(out)
