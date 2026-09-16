"""Paired-round benchmark: same native metrics, isolated MTC experiment outputs."""
import argparse,csv,datetime,hashlib,json,os,platform,random,re,shutil,statistics,subprocess,time
from pathlib import Path
from scenarios import *
p=argparse.ArgumentParser();p.add_argument('--runs',type=int,default=30);p.add_argument('--warmup',type=int,default=3);p.add_argument('--seed',type=int,default=42)
p.add_argument('--scenarios',nargs='+',choices=ALL_SCENARIOS,default=SCENARIOS);p.add_argument('--host',default='server');p.add_argument('--image-id',default=os.environ.get('MTC_IMAGE_ID','unknown'))
a=p.parse_args()
if a.runs<2 or a.warmup<0 or len(set(a.scenarios))!=len(a.scenarios):p.error('runs >=2; warmup >=0; distinct scenarios')
out=Path('/work/results')/('mtc-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));out.mkdir();(out/'logs').mkdir();(out/'server-metrics').mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
fixture={f:json.loads((MTC_BATCH/f/'manifest.json').read_text()) for f in ['classic','pq']}
compact={f:json.loads((BATCH/f/'manifest.json').read_text()) for f in ['classic','pq']}
if any(fixture[f]['tree_size']!=compact[f]['leaves'] for f in fixture):raise RuntimeError('Population size mismatch')
# Verify identity of the source population against the hashes recorded at MTC issuance.
for f,meta in fixture.items():
    for name,value in meta['input_sha256'].items():
        if sha(Path(name))!=value:raise RuntimeError('Source population changed')
meta={'draft':'draft-ietf-plants-merkle-tree-certs-05','trust_anchor_draft':'draft-ietf-tls-trust-anchor-ids-04','status':'MTC-experimental',
      'openssl':subprocess.check_output([OPENSSL,'version','-a'],text=True),'image_id':a.image_id,'architecture':platform.machine(),'platform':platform.platform(),
      'visible_cpus':os.cpu_count(),'memory':Path('/proc/meminfo').read_text().splitlines()[:3],
      'seed':a.seed,'runs':a.runs,'warmup':a.warmup,'scenarios':a.scenarios,'fixture':fixture,'compact':compact,
      'configuration':{'tls':'1.3','group':'X25519','cipher':'TLS_AES_256_GCM_SHA384','resumption':False,'tickets':False,'new_client_per_sample':True,'persistent_servers':True,'detail':0},
      'deviations':['private trust_anchors codepoint 0xffa7','exact ID matching only; no groups/retry','single initial log/landmark snapshot','local cosigner; no public transparency','direct CA and X509 leaf validation; no general MTC PKIX chains'],
      'byte_definitions':{'transport':'TLS BIO bytes through client handshake-done, no network headers or retransmissions','certificate_message':'TLS handshake header plus body','certificate_verify':'TLS handshake header plus body; not a Merkle proof','mtc_certificate':'DER','mtc_tbs':'DER TBSCertificate','mtc_inclusion_proof':'hash array payload excluding vector length','mtc_signature':'raw CA subtree signature','mtc_cosignature':'raw additional signatures','mtc_checkpoint':'zero in TLS; separate OOB trust file','mtc_landmark_reference':'12 bytes MTCProof start/end; no explicit landmark number in certificate','mtc_predistributed':'entire local landmark configuration file, including trust keys/signatures'},
      'timing_definitions':{'handshake':'same INFO start/done wall/process CPU as profile phase','tcp_connect_wall_ms_native':'native connection entry to successful return (init_client in current s_client, BIO_do_connect where available); may include resolver/address selection; not equal to PCAP TCP timing','connection_establishment_wall_ms_native':'original native connect entry through SSL_CB_HANDSHAKE_DONE, including the application gap; client side only','mtc_setup':'per-client config loading plus landmark validation before handshake','mtc_trust_validation':'checkpoint signatures checked in setup','client_process_http':'subprocess start through successful HTTP and exit'},
      'timing_limit':'new process each sample, not persistent application cache; paired-round intervals conditional on this run'}
for name,path in {'openssl_commit':'/opt/openssl/SOURCE_COMMIT','liboqs_commit':'/opt/oqs/SOURCE_COMMIT','oqs_provider_commit':'/opt/oqs/PROVIDER_COMMIT','mtc_hash':'/opt/openssl-mtc/MTC_SHA256','compact_hash':'/opt/openssl-compact/COMPACT_SHA256','profile_hash':'/opt/openssl-profile/PROFILE_SHA256'}.items():meta[name]=Path(path).read_text().strip()
meta['versions']={'openssl':'3.5.8','liboqs':'0.14.0','oqs_provider':'0.10.0'}
meta['source_hashes']={str(f.relative_to('/opt/mtc')):sha(f) for f in Path('/opt/mtc').glob('*') if f.is_file()}
meta['inputs']={str(f):sha(f) for family in ['classic','pq'] for f in (MTC_BATCH/family).glob('*') if f.is_file() and f.suffix!='.key'}
for name in ['cpu.max','memory.max']:
    path=Path('/sys/fs/cgroup')/name
    if path.exists():meta[name]=path.read_text().strip()
(out/'metadata.json').write_text(json.dumps(meta,indent=2)+'\n')
rows=[];rng=random.Random(a.seed)
def write_csv(path,values):
    if not values:return
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(values[0]));w.writeheader();w.writerows(values)
def sample(scenario,round_number,order,warm):
    t=time.perf_counter();result=subprocess.run(client_args(scenario,a.host,4433+ALL_SCENARIOS.index(scenario)),input='GET / HTTP/1.0\r\n\r\n',text=True,capture_output=True,timeout=20);wall=(time.perf_counter()-t)*1000
    log=result.stdout+result.stderr;(out/'logs'/f'{"warmup" if warm else "sample"}-{round_number:04d}-{scenario}.log').write_text(log)
    values=re.findall(r'^PROFILE_METRICS (\{.*\})$',result.stderr,re.M)
    if result.returncode or len(values)!=1 or 'HTTP/1.0 200' not in log:raise RuntimeError('Handshake failed: '+scenario)
    m=json.loads(values[0]);key=m['client_random']
    if not re.fullmatch('[0-9a-f]{64}',key):raise RuntimeError('Invalid correlation')
    paths=list(Path('/work/results').glob('mtc-server-*/'+key+'.json'))
    if len(paths)!=1:raise RuntimeError('Missing server metric')
    server=json.loads(paths[0].read_text());shutil.copyfile(paths[0],out/'server-metrics'/paths[0].name)
    for side,x in [('client',m),('server',server)]:
        if x['side']!=side or x['client_random']!=key or not x['profile_valid'] or x['reused'] or x['detail'] or x['server_cert_type']!=(2 if is_rpk(scenario) else 0):raise RuntimeError('Endpoint mismatch')
    if m['certificate_message_bytes']!=server['certificate_message_bytes'] or m['certificate_verify_message_bytes']!=server['certificate_verify_message_bytes']:raise RuntimeError('Message size mismatch')
    if not m['certificate_verify_message_bytes']:raise RuntimeError('Missing CertificateVerify')
    mtc='-mtc-experimental-' in scenario;comp='-compact-' in scenario;family=base(scenario);mode=scenario.rsplit('-',1)[1] if mtc else 'none'
    marker='MTC verification: OK' if mtc else ('Compact verification: OK' if comp else ('Merkle verification: OK' if scenario.endswith('-mt') else 'Verify return code: 0 (ok)'))
    if marker not in log:raise RuntimeError('Authentication missing')
    row={'crypto_family':family,'credential_scheme':'MTC-experimental' if mtc else ('compact-experimental' if comp else ('RPK' if scenario.endswith('-rpk') else ('X509+MT' if scenario.endswith('-mt') else 'X509'))),
         'mtc_mode':mode,'tree_size':fixture[family]['tree_size'],'root_or_landmark_distribution':'predistributed' if mode=='landmark' or scenario.endswith('-warm') else ('in-handshake' if mtc or comp else 'CA-or-pin'),
         'scenario':scenario,'round':round_number,'order':order,'client_random':key,
         'handshake_wall_ms':m['handshake_wall_ms'],'handshake_client_cpu_ms':m['handshake_cpu_ms'],'handshake_server_cpu_ms':server['handshake_cpu_ms'],'handshake_total_cpu_ms':m['handshake_cpu_ms']+server['handshake_cpu_ms'],
         'tcp_connect_wall_ms_native':m.get('tcp_connect_wall_ms_native'),'connection_establishment_wall_ms_native':m.get('connection_establishment_wall_ms_native'),
         'transport_read_bytes':m['transport_read_bytes'],'transport_written_bytes':m['transport_written_bytes'],'transport_total_bytes':m['transport_read_bytes']+m['transport_written_bytes'],
         'certificate_message_bytes':m['certificate_message_bytes'],'certificate_verify_bytes':m['certificate_verify_message_bytes'],'encrypted_extensions_bytes':m['encrypted_extensions_bytes'],'client_process_http_wall_ms':wall}
    fields=['mtc_certificate_bytes','mtc_tbs_bytes','mtc_inclusion_proof_bytes','mtc_proof_encoded_bytes','mtc_signature_bytes','mtc_cosignature_bytes','mtc_checkpoint_bytes','mtc_landmark_reference_bytes','mtc_predistributed_bytes']
    row.update({f:fixture[family]['sizes'][mode][f] if mtc else 0 for f in fields})
    row.update({'mtc_setup_ms':0,'mtc_trust_validation_ms':0,'mtc_trust_file_bytes':0,'mtc_credential_auth_ms':0,'compact_root_setup_ms':0})
    for prefix in ['MTC_SETUP','MTC_VERIFY','ROOT_SIGNATURE_SETUP']:
        matches=re.findall(r'^'+prefix+r' (\{.*\})$',result.stderr,re.M)
        if matches:
            data=json.loads(matches[0])
            if prefix=='ROOT_SIGNATURE_SETUP':row['compact_root_setup_ms']=data['wall_ms']
            else:row.update(data)
        elif mtc and prefix!='ROOT_SIGNATURE_SETUP':raise RuntimeError('MTC timing missing')
    if not warm:rows.append(row);write_csv(out/'samples.csv',rows)
for warm,rounds in [(True,a.warmup),(False,a.runs)]:
    for r in range(rounds):
        order=a.scenarios.copy();rng.shuffle(order)
        for i,scenario in enumerate(order):sample(scenario,r,i,warm)
        print('warmup' if warm else 'round',r+1,flush=True)
metrics=[k for k,v in rows[0].items() if isinstance(v,(int,float)) and k not in ['round','order','tree_size']]
for name in ['tcp_connect_wall_ms_native','connection_establishment_wall_ms_native']:
    if name not in metrics: metrics.append(name)
summary=[]
for scenario in a.scenarios:
    group=[r for r in rows if r['scenario']==scenario];row={'scenario':scenario,'n':len(group)}
    for metric in metrics:
        values=[r[metric] for r in group if r.get(metric) is not None]
        if not values: continue
        for suffix,fn in [('median',statistics.median),('min',min),('max',max)]:row[metric+'_'+suffix]=fn(values)
    summary.append(row)
write_csv(out/'summary.csv',summary)
comparisons=[];pairs=[]
for scenario in a.scenarios:
    if scenario!=base(scenario) and base(scenario) in a.scenarios:pairs.append((scenario,base(scenario)))
for family in ['classic','pq']:
    for comp,mtc in [('warm','landmark'),('cold','standalone')]:
        left=f'{family}-compact-{comp}';right=f'{family}-mtc-experimental-{mtc}'
        if left in a.scenarios and right in a.scenarios:pairs.append((left,right))
for left,right in pairs:
    for metric in ['transport_total_bytes','handshake_wall_ms','handshake_client_cpu_ms','handshake_total_cpu_ms','client_process_http_wall_ms']:
        x={r['round']:r[metric] for r in rows if r['scenario']==left};y={r['round']:r[metric] for r in rows if r['scenario']==right}
        dif=[x[i]-y[i] for i in sorted(x)];boots=sorted(statistics.median(rng.choices(dif,k=len(dif))) for _ in range(2000))
        comparisons.append({'scenario':left,'baseline':right,'metric':metric,
                            'paired_delta_median':statistics.median(dif),'bootstrap95_low':boots[49],
                            'bootstrap95_high':boots[1949],
                            'percentage_byte_difference':100*(statistics.median(x.values())/statistics.median(y.values())-1) if metric=='transport_total_bytes' else '',
                            'protocol_equivalent':False})
write_csv(out/'comparisons.csv',comparisons)
lines=['# MTC-experimental: controlled local measurements','',f'Draft: {meta["draft"]}. Rounds: {a.runs}. Seed: {a.seed}. Tree population: {fixture["pq"]["tree_size"]}.','',
       '| Scenario | TLS bytes median [min,max] | Client wall ms | Client CPU ms | Total CPU ms |','|---|---:|---:|---:|---:|']
for r in summary:lines.append(f'| {r["scenario"]} | {r["transport_total_bytes_median"]:.0f} [{r["transport_total_bytes_min"]},{r["transport_total_bytes_max"]}] | {r["handshake_wall_ms_median"]:.3f} | {r["handshake_client_cpu_ms_median"]:.3f} | {r["handshake_total_cpu_ms_median"]:.3f} |')
lines+=['','MTC-experimental is NOT a claim of full IETF compliance. See metadata deviations.',
        'Standalone requires CA plus one local cosigner. X509 baseline has no SCTs. Compact and MTC pairs are architectural comparisons, not protocol-equivalent.',
        'Landmark trust validation is before each new client handshake, not an amortized persistent cache. Setup time and predistributed bytes are separate columns.',
        'Timestamped checkpoint bytes in TLS: zero. CertificateVerify is native TLS proof of possession and is not part of MTCProof.',
        'Transport bytes exclude TCP/IP headers and retransmissions. Detailed timing definitions and input/source hashes are in metadata.json.']
(out/'report.md').write_text('\n'.join(lines)+'\n');print(out)
