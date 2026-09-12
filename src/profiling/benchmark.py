"""Join endpoint telemetry by TLS ClientHello random (public, no wire modification)."""
import argparse
import csv
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import shutil
import statistics
import subprocess
import time
from scenarios import OPENSSL,SCENARIOS,BATCH,base,is_rpk,pin,client_args
p=argparse.ArgumentParser();p.add_argument('--runs',type=int,default=30);p.add_argument('--warmup',type=int,default=3)
p.add_argument('--seed',type=int,default=42);p.add_argument('--host',default=os.environ.get('TLS_HOST','server'))
a=p.parse_args()
if a.runs<2 or a.warmup<0:p.error('runs >= 2 and warmup >= 0 required')
detail=int(os.environ.get('PROFILE_DETAIL','0'))
if detail not in (0,1):p.error('PROFILE_DETAIL must be 0 or 1')
output=Path('/work/results')/('profile-detail'+str(detail)+'-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
output.mkdir();(output/'logs').mkdir();(output/'server-metrics').mkdir()
metadata={'detail':detail,'runs':a.runs,'warmup':a.warmup,'seed':a.seed,'scenarios':SCENARIOS,
    'profile_sha256':Path('/opt/openssl-profile/PROFILE_SHA256').read_text().strip(),
    'phase2_sha256':Path('/opt/openssl-compact/COMPACT_SHA256').read_text().strip(),
    'openssl':subprocess.check_output([OPENSSL,'version','-a'],text=True),
    'platform':platform.platform(),'cpus':os.cpu_count(),'pins':{s:pin(s) for s in ['classic','pq']},
    'pin_scope':'trusted local mapping server -> SHA256(SPKI); no DNS query, chain, validity or batch semantics',
    'timing_scope':'endpoint handshake wall and process CPU; setup/TCP/HTTP excluded',
    'components_scope':'inclusive timers, nested categories must not be summed',
    'join':'TLS ClientHello random, not a new extension','batch':str(BATCH)}
for name in ['cpu.max','memory.max']:
    path=Path('/sys/fs/cgroup')/name
    if path.exists():metadata[name]=path.read_text().strip()
metadata['driver_sha256']={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in Path('/opt/profiling').glob('*.py')}
metadata['input_sha256']={str(f):hashlib.sha256(f.read_bytes()).hexdigest() for family in ['classic','pq'] for f in [
    BATCH/family/'manifest.json',BATCH/family/'root.signed',BATCH/family/'bundle-0000.bin',
    BATCH/family/'x509-merkle/root.bin',BATCH/family/'x509-merkle/proof-0000.bin',
    Path('/work/certs')/family/'server.pem',Path('/work/certs')/family/'ca.pem']}
(output/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
rows=[];component_rows=[];rng=random.Random(a.seed)

def csv_write(path,values):
    if not values:return
    with path.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=list(values[0]));writer.writeheader();writer.writerows(values)

def sample(scenario,round_number,warm):
    start=time.perf_counter_ns()
    result=subprocess.run(client_args(scenario,a.host,4433+SCENARIOS.index(scenario)),input='GET / HTTP/1.0\r\n\r\n',
                          capture_output=True,text=True,timeout=20)
    wall=(time.perf_counter_ns()-start)/1e6
    log=result.stdout+result.stderr
    (output/'logs'/f'{"warmup" if warm else "sample"}-{round_number:04d}-{scenario}.log').write_text(log)
    matches=re.findall(r'^PROFILE_METRICS (\{.*\})$',result.stderr,re.M)
    if result.returncode or len(matches)!=1 or 'HTTP/1.0 200' not in log:raise RuntimeError('Handshake failed: '+scenario)
    client=json.loads(matches[0]);key=client['client_random']
    if not re.fullmatch('[0-9a-f]{64}',key):raise RuntimeError('Invalid handshake identity')
    files=list(Path('/work/results').glob('profile-server-*/'+key+'.json'))
    if len(files)!=1:raise RuntimeError('Missing or ambiguous server telemetry for '+key)
    server=json.loads(files[0].read_text())
    for side,m in [('client',client),('server',server)]:
        if m['side']!=side or m['client_random']!=key or not m['profile_valid'] or m['detail']!=detail or m['reused']:
            raise RuntimeError('Endpoint/measurement mismatch')
        if m['server_cert_type']!=(2 if is_rpk(scenario) else 0):raise RuntimeError('Unexpected certificate type')
        if not detail and any(x['calls'] for x in m['components'].values()):raise RuntimeError('Detailed timers active in coarse run')
    if client['certificate_message_bytes']!=server['certificate_message_bytes'] or client['certificate_verify_message_bytes']!=server['certificate_verify_message_bytes']:
        raise RuntimeError('Message size mismatch across endpoints')
    if detail:
        if client['components']['peer_auth']['calls']!=1 or client['components']['certificate_verify_verify']['calls']!=1 or server['components']['certificate_verify_sign']['calls']!=1:
            raise RuntimeError('Missing native TLS measurement')
        if '-compact-' in scenario and client['components']['merkle_proof']['calls']!=1:raise RuntimeError('Missing proof measurement')
        if scenario.endswith('compact-cold') and client['components']['root_signature']['calls']!=1:raise RuntimeError('Missing root signature measurement')
    marker='Compact verification: OK' if '-compact-' in scenario else ('Merkle verification: OK' if scenario.endswith('-mt') else 'Verify return code: 0 (ok)')
    if marker not in log:raise RuntimeError('Authentication not confirmed')
    shutil.copyfile(files[0],output/'server-metrics'/files[0].name)
    bootstrap=re.findall(r'^ROOT_SIGNATURE_SETUP (\{.*\})$',result.stderr,re.M)
    setup=json.loads(bootstrap[0]) if bootstrap else {'wall_ms':0,'cpu_ms':0}
    row={'scenario':scenario,'round':round_number,'client_random':key,'detail':detail,
         'client_handshake_wall_ms':client['handshake_wall_ms'],'client_handshake_cpu_ms':client['handshake_cpu_ms'],
         'server_handshake_wall_ms':server['handshake_wall_ms'],'server_handshake_cpu_ms':server['handshake_cpu_ms'],
         'combined_handshake_cpu_ms':client['handshake_cpu_ms']+server['handshake_cpu_ms'],
         'client_process_http_wall_ms':wall,'root_signature_setup_wall_ms':setup['wall_ms'],'root_signature_setup_cpu_ms':setup['cpu_ms'],
         'transport_total_bytes':client['transport_read_bytes']+client['transport_written_bytes'],
         'certificate_message_bytes':client['certificate_message_bytes'],'certificate_verify_message_bytes':client['certificate_verify_message_bytes']}
    if not warm:
        rows.append(row)
        for side,m in [('client',client),('server',server)]:
            for name,value in m['components'].items():component_rows.append({'scenario':scenario,'round':round_number,'client_random':key,'side':side,'component':name,**value})
        csv_write(output/'samples.csv',rows);csv_write(output/'components.csv',component_rows)

for warm,rounds in [(True,a.warmup),(False,a.runs)]:
    for round_number in range(rounds):
        order=SCENARIOS.copy();rng.shuffle(order)
        for scenario in order:sample(scenario,round_number,warm)
        print('warmup' if warm else 'round',round_number+1,flush=True)
fields=[name for name in rows[0] if name not in ['scenario','round','client_random','detail']]
summary=[]
for scenario in SCENARIOS:
    group=[r for r in rows if r['scenario']==scenario];entry={'scenario':scenario,'n':len(group)}
    for field in fields:entry[field+'_median']=statistics.median(r[field] for r in group)
    summary.append(entry)
csv_write(output/'summary.csv',summary)
parts=[]
for scenario in SCENARIOS:
    for side in ['client','server']:
        for name in sorted({r['component'] for r in component_rows}):
            group=[r for r in component_rows if r['scenario']==scenario and r['side']==side and r['component']==name]
            parts.append({'scenario':scenario,'side':side,'component':name,'wall_ms_median':statistics.median(r['wall_ms'] for r in group),
                          'cpu_ms_median':statistics.median(r['cpu_ms'] for r in group),'calls_median':statistics.median(r['calls'] for r in group)})
csv_write(output/'component-summary.csv',parts)
comparisons=[]
for scenario in SCENARIOS:
    baselines=[] if scenario in ['classic','pq'] else [base(scenario)]
    if '-compact-' in scenario:baselines.append(base(scenario)+'-rpk')
    for baseline in baselines:
        for field in ['client_handshake_wall_ms','client_handshake_cpu_ms','server_handshake_cpu_ms','combined_handshake_cpu_ms','transport_total_bytes']:
            x={r['round']:r[field] for r in rows if r['scenario']==scenario};y={r['round']:r[field] for r in rows if r['scenario']==baseline}
            differences=[x[i]-y[i] for i in sorted(x)];boot=sorted(statistics.median(rng.choices(differences,k=len(differences))) for _ in range(2000))
            comparisons.append({'scenario':scenario,'baseline':baseline,'metric':field,'paired_delta_median':statistics.median(differences),'bootstrap95_low':boot[49],'bootstrap95_high':boot[1949]})
csv_write(output/'comparisons.csv',comparisons)
report=['# Exploratory endpoint profiling','',f'Detailed timers: {detail}. RPK pin is a diagnostic control, not a PKI replacement.','',
        '| Scenario | TLS bytes | Client wall ms | Client CPU ms | Server CPU ms | Combined CPU ms |','|---|---:|---:|---:|---:|---:|']
for r in summary:
    report.append(f"| {r['scenario']} | {r['transport_total_bytes_median']:.0f} | {r['client_handshake_wall_ms_median']:.3f} | {r['client_handshake_cpu_ms_median']:.3f} | {r['server_handshake_cpu_ms_median']:.3f} | {r['combined_handshake_cpu_ms_median']:.3f} |")
report+=['','Components are inclusive/nested; do not sum them. Endpoint CPU sums are not elapsed handshake time.',
         'Warm root signature setup remains outside handshake and inside full client process time. No persistent cache or optimized verifier has been introduced.']
(output/'report.md').write_text('\n'.join(report)+'\n')
print(output)
