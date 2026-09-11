"""Five independent campaigns per N; never bootstrap individual handshakes."""
import csv,hashlib,json,math,random,re,statistics as st,sys
from pathlib import Path
SIZES=[1,4,16,64,256,1024]
SUFFIXES=['','-rpk','-compact-warm','-compact-cold','-mtc-experimental-standalone','-mtc-experimental-landmark']
TIMING=['handshake_wall_ms','handshake_client_cpu_ms','handshake_server_cpu_ms','handshake_total_cpu_ms','client_process_http_wall_ms']
EXTRA=['setup_wall_ms','setup_cpu_ms','root_validation_ms','trust_validation_ms','mtc_credential_auth_ms','mtc_trust_validation_ms']
BYTES=['transport_total_bytes','transport_read_bytes','transport_written_bytes','certificate_message_bytes','certificate_verify_bytes','encrypted_extensions_bytes','predistributed_bytes','predistributed_incremental_bytes']
def read(p):
 with p.open(newline='') as f:return list(csv.DictReader(f))
def write(p,rows):
 if not rows:return
 fields=list(dict.fromkeys(k for r in rows for k in r))
 with p.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
def q(v,p):
 v=sorted(v);i=(len(v)-1)*p;a=math.floor(i);b=math.ceil(i);return v[a]+(v[b]-v[a])*(i-a)
def effect(x,y):
 if set(x)!=set(y):raise ValueError('Unpaired rounds')
 return st.median(x[k]-y[k] for k in x)
RNG=random.Random(20260910);RESAMPLES=[RNG.choices(range(5),k=5) for _ in range(10000)]
def bootstrap(v):
 if len(v)!=5:raise ValueError('Exactly five campaign effects required')
 values=[st.median(v[i] for i in indices) for indices in RESAMPLES];return q(values,.025),q(values,.975)
def stability(v,lo,hi):
 if lo<=0<=hi:return 'uncertain: interval includes zero'
 if min(sum(x<0 for x in v),sum(x>0 for x in v))>=2:return 'unstable: at least two campaigns per sign'
 return 'direction supported in these campaigns'
def linfit(x,y):
 mx=st.mean(x);my=st.mean(y);s=sum((a-mx)*(b-my) for a,b in zip(x,y))/sum((a-mx)**2 for a in x);b=my-s*mx;res=[v-(s*t+b) for t,v in zip(x,y)];ss=sum((v-my)**2 for v in y)
 return {'slope':s,'intercept':b,'r_squared':1-sum(v*v for v in res)/ss if ss else None,'residual_min':min(res),'residual_max':max(res),'residuals':json.dumps(res)}
def pairs(f):
 return [(f+s,f,'baseline') for s in SUFFIXES[1:]]+[(f+'-compact-warm',f+'-rpk','layer'),(f+'-mtc-experimental-landmark',f+'-rpk','layer'),(f+'-compact-warm',f+'-mtc-experimental-landmark','architectural'),(f+'-compact-cold',f+'-mtc-experimental-standalone','architectural')]
def fnum(r,k):return float(r[k]) if r.get(k) not in ('',None) else None

def analyze(root):
 status=json.loads((root/'campaign-status.json').read_text());assert status['passed'] and status['failed_campaign'] is None and len(status['campaigns'])==60
 assert not (root/'all-samples.csv').exists(),'Refusing to overwrite analysis'
 allrows=[];warms=[];details=[];detailwarms=[];components=[];summaries=[];paired=[];outliers=[];seen=set();configs={};natives=[];root_setup=[]
 for rec in status['campaigns']:
  assert rec['state']=='complete';d=root/'campaigns'/rec['campaign_id'];meta=json.loads((d/'metadata.json').read_text());assert json.loads((d/'validation.json').read_text())['passed']
  n=rec['tree_size'];detail=rec['detail'];ci=int(rec['campaign_id'].rsplit('c',1)[1]);assert rec['seed']==1000*ci+n and meta['runs']==30 and meta['warmup']==5 and meta['image_id']==status['image_id']
  natives.append({k:meta[k] for k in ['openssl_commit','liboqs_commit','oqs_provider_commit','mtc_hash','compact_hash','profile_hash']})
  cfg=(detail,n);snap={k:meta[k] for k in ['fixture','compact','inputs','configuration']}
  if cfg in configs:assert configs[cfg]==snap
  configs[cfg]=snap
  rows=read(d/'samples.csv');warm=read(d/'warmups.csv');assert len(rows)==(4 if detail else 12)*30 and len(warm)==(4 if detail else 12)*5
  for row in rows+warm:
   assert row['client_random'] not in seen;seen.add(row['client_random']);assert int(row['tree_size'])==n
   for metric in TIMING:assert math.isfinite(float(row[metric])) and float(row[metric])>0
   if row['scenario'].endswith('-compact-warm'):
    log=(d/'logs'/f'{"warmup" if int(row["is_warmup"]) else "sample"}-{int(row["round"]):04d}-{row["scenario"]}.log').read_text()
    matches=re.findall(r'^ROOT_SIGNATURE_SETUP (\{.*\})$',log,re.M);assert len(matches)==1
    timer=json.loads(matches[0]);root_setup.append({'tree_size':n,'mode':'detail' if detail else 'primary','campaign_id':row['campaign_id'],'round_id':row['round_id'],'scenario':row['scenario'],'is_warmup':row['is_warmup'],'root_signature_setup_wall_ms':timer['wall_ms'],'root_signature_setup_cpu_ms':timer['cpu_ms'],'scope':'signature operation nested inside full pre-handshake setup'})
  (details if detail else allrows).extend(rows);(detailwarms if detail else warms).extend(warm)
  if detail:components.extend(read(d/'components.csv'))
  for scenario in meta['scenarios']:
   group=[r for r in rows if r['scenario']==scenario];summary={'tree_size':n,'mode':'detail' if detail else 'primary','campaign_id':rec['campaign_id'],'seed':rec['seed'],'scenario':scenario,'samples':len(group)}
   for metric in TIMING+EXTRA+BYTES:
    v=[fnum(r,metric) for r in group if fnum(r,metric) is not None]
    for suffix,func in [('median',st.median),('min',min),('max',max)]:summary[metric+'_'+suffix]=func(v) if v else None
    if metric in TIMING:
     lo=q(v,.25)-1.5*(q(v,.75)-q(v,.25));hi=q(v,.75)+1.5*(q(v,.75)-q(v,.25))
     outliers.extend({'tree_size':n,'mode':summary['mode'],'campaign_id':rec['campaign_id'],'scenario':scenario,'round_id':r['round_id'],'metric':metric,'value':fnum(r,metric),'lower_fence':lo,'upper_fence':hi,'retained':True} for r in group if fnum(r,metric)<lo or fnum(r,metric)>hi)
   summaries.append(summary)
  if not detail:
   for family in ['classic','pq']:
    for left,right,kind in pairs(family):
     for metric in TIMING+['transport_total_bytes']+(['setup_wall_ms','setup_cpu_ms','trust_validation_ms'] if kind=='architectural' else []):
      if any(r.get(metric) in ('',None) for r in rows if r['scenario'] in [left,right]):continue
      x={r['round_id']:float(r[metric]) for r in rows if r['scenario']==left};y={r['round_id']:float(r[metric]) for r in rows if r['scenario']==right}
      paired.append({'tree_size':n,'campaign_id':rec['campaign_id'],'scenario':left,'baseline':right,'comparison_class':kind,'metric':metric,'paired_median_difference':effect(x,y),'paired_percent_median':st.median(100*(x[k]-y[k])/y[k] for k in x) if metric=='transport_total_bytes' else None})
 assert all(x==natives[0] for x in natives)
 assert len(allrows)==10800 and len(warms)==1800 and len(details)==3600 and len(detailwarms)==600
 for n in SIZES:
  for suffix in SUFFIXES:
   values={int(r['transport_total_bytes']) for r in allrows if int(r['tree_size'])==n and r['scenario']=='pq'+suffix}
   assert len(values)==1,('Unexpected PQ byte variation',n,suffix,values)
 for suffix in ['', '-rpk']:
  assert len({int(r['transport_total_bytes']) for r in allrows if r['scenario']=='pq'+suffix})==1
 write(root/'root-signature-setup.csv',root_setup)
 for name,rows in [('all-samples.csv',allrows),('all-warmups.csv',warms),('detail-samples.csv',details),('detail-warmups.csv',detailwarms),('detail-components.csv',components),('campaign-summary.csv',summaries),('paired-comparisons.csv',paired),('outliers.csv',outliers)]:write(root/name,rows)
 aggregate=[]
 for mode in ['primary','detail']:
  for n in SIZES:
   for scenario in sorted({r['scenario'] for r in summaries if r['mode']==mode}):
    group=[r for r in summaries if r['mode']==mode and r['tree_size']==n and r['scenario']==scenario];assert len(group)==5
    row={'tree_size':n,'mode':mode,'scenario':scenario,'campaigns':5}
    for metric in TIMING+EXTRA+BYTES:
     v=[r[metric+'_median'] for r in group if r[metric+'_median'] is not None]
     row[metric+'_median']=st.median(v) if v else None;row[metric+'_campaign_min']=min(v) if v else None;row[metric+'_campaign_max']=max(v) if v else None
     row[metric+'_sample_min']=min(r[metric+'_min'] for r in group if r[metric+'_min'] is not None) if v else None;row[metric+'_sample_max']=max(r[metric+'_max'] for r in group if r[metric+'_max'] is not None) if v else None
     row[metric+'_campaign_cv_percent']=100*st.stdev(v)/st.mean(v) if len(v)==5 and st.mean(v)>0 else None
    aggregate.append(row)
 write(root/'scaling-summary.csv',aggregate)
 effects=[]
 for n in SIZES:
  for family in ['classic','pq']:
   for left,right,kind in pairs(family):
    for metric in sorted({r['metric'] for r in paired if r['tree_size']==n and r['scenario']==left and r['baseline']==right}):
     group=[r for r in paired if r['tree_size']==n and r['scenario']==left and r['baseline']==right and r['metric']==metric];assert len(group)==5
     v=[r['paired_median_difference'] for r in group];is_time=metric!='transport_total_bytes';lo,hi=bootstrap(v) if is_time else (None,None)
     effects.append({'tree_size':n,'scenario':left,'baseline':right,'comparison_class':kind,'metric':metric,'median_campaign_paired_difference':st.median(v),'min_campaign_difference':min(v),'max_campaign_difference':max(v),'bootstrap95_low':lo,'bootstrap95_high':hi,'resamples':10000 if is_time else 0,'negative_campaigns':sum(x<0 for x in v),'positive_campaigns':sum(x>0 for x in v),'stability':stability(v,lo,hi) if is_time else 'observed bytes; no bootstrap','median_percent_difference':st.median(r['paired_percent_median'] for r in group) if not is_time else None})
 write(root/'bootstrap-comparisons.csv',effects)
 def get(n,s):return next(r for r in aggregate if r['tree_size']==n and r['scenario']==s and r['mode']=='primary')
 byte_table=[];overhead=[];amort=[];timing=[];break_even=[]
 for n in SIZES:
  for family in ['classic','pq']:
   vals={s:get(n,family+s)['transport_total_bytes_median'] for s in SUFFIXES}
   byte_table.append({'tree_size':n,'crypto_family':family,**{family+s:vals[s] for s in SUFFIXES}})
   for left,right,kind in pairs(family):
    a=get(n,left)['transport_total_bytes_median'];b=get(n,right)['transport_total_bytes_median'];overhead.append({'tree_size':n,'scenario':left,'baseline':right,'difference_bytes':a-b,'difference_percent':100*(a-b)/b,'comparison_class':kind})
   for suffix in ['-compact-warm','-mtc-experimental-landmark']:
    r=get(n,family+suffix);break_even.append({'tree_size':n,'scenario':family+suffix,'x509_bytes':vals[''],'scheme_bytes':vals[suffix],'scheme_ge_x509':vals[suffix]>=vals[''],'observed_sample_min':r['transport_total_bytes_sample_min'],'observed_sample_max':r['transport_total_bytes_sample_max']})
    structural=next(r for r in read(root/'structural-sizes.csv') if int(r['tree_size'])==n and r['crypto_family']==family)
    trust=float(structural['compact_signed_root_bytes' if suffix=='-compact-warm' else 'mtc_predistributed_landmark_bytes']);increment=float(structural['compact_signed_root_bytes' if suffix=='-compact-warm' else 'mtc_landmark_incremental_bytes'])
    for h in [1,10,100,1000,10000]:amort.append({'tree_size':n,'scenario':family+suffix,'H':h,'tls_handshake_bytes':vals[suffix],'predistributed_trust_bytes':trust,'incremental_trust_bytes_excluding_mtc_authority':increment,'amortized_total_per_connection':vals[suffix]+trust/h,'amortized_incremental_trust_per_connection':vals[suffix]+increment/h,'model_only_not_measured_reuse':True})
   for suffix in SUFFIXES:
    r=get(n,family+suffix);timing.append({'tree_size':n,'scenario':family+suffix,**{m:r[m+'_median'] for m in TIMING}})
 for name,rows in [('tls-bytes-table.csv',byte_table),('byte-overhead.csv',overhead),('amortization.csv',amort),('timing-table.csv',timing),('break-even.csv',break_even)]:write(root/name,rows)
 structural=read(root/'structural-sizes.csv');increments=[];slopes=[];decomposition=[]
 for r in structural:
  for scheme,total,path in [('Compact warm object + SPKI','compact_warm_credential_with_spki_bytes','compact_inclusion_hash_bytes'),('MTC landmark DER','mtc_landmark_certificate_der_bytes','mtc_landmark_inclusion_bytes'),('MTC standalone DER','mtc_standalone_certificate_der_bytes','mtc_standalone_inclusion_bytes')]:
   decomposition.append({'tree_size':r['tree_size'],'crypto_family':r['crypto_family'],'object':scheme,'total_serialized_bytes':int(r[total]),'sibling_hash_payload_bytes':int(r[path]),'remaining_fields_and_framing_bytes':int(r[total])-int(r[path]),'scope':'actual object sizes; remainder may change at DER boundaries and with ECDSA signature lengths'})
 write(root/'fixed-and-tree-components.csv',decomposition)
 sizefields=['compact_inclusion_hash_bytes','compact_proof_bytes','compact_bundle_bytes','compact_warm_credential_with_spki_bytes','mtc_landmark_inclusion_bytes','mtc_landmark_proof_bytes','mtc_landmark_certificate_der_bytes','mtc_standalone_certificate_der_bytes']
 for family in ['classic','pq']:
  rows=[r for r in structural if r['crypto_family']==family]
  for metric in sizefields:
   for a,b in zip(rows,rows[1:]):
    levels=math.log2(int(b['tree_size'])/int(a['tree_size']));delta=float(b[metric])-float(a[metric]);increments.append({'crypto_family':family,'metric':metric,'from_n':a['tree_size'],'to_n':b['tree_size'],'additional_levels':levels,'additional_bytes':delta,'bytes_per_added_level':delta/levels})
   for scope in ['all','N>=4']:
    selected=[r for r in rows if scope=='all' or int(r['tree_size'])>=4];x=[math.log2(int(r['tree_size'])) for r in selected];y=[float(r[metric]) for r in selected]
    slopes.append({'crypto_family':family,'metric':metric,'scope':scope,'interpretation':'descriptive serialized-size fit; not a complexity proof',**linfit(x,y)})
  for suffix in SUFFIXES[2:]:
   for a,b in zip(SIZES,SIZES[1:]):
    delta=get(b,family+suffix)['transport_total_bytes_median']-get(a,family+suffix)['transport_total_bytes_median'];increments.append({'crypto_family':family,'metric':family+suffix+' TLS median','from_n':a,'to_n':b,'additional_levels':math.log2(b/a),'additional_bytes':delta,'bytes_per_added_level':delta/math.log2(b/a)})
 write(root/'size-increments.csv',increments);write(root/'size-slopes.csv',slopes)
 # Detailed CPU: summarize within campaign first, retaining all nested timers separately.
 component_campaign=[]
 keys=sorted({(r['tree_size'],r['campaign_id'],r['scenario'],r['side'],r['component']) for r in components if r['is_warmup']=='0'})
 buckets={k:[] for k in keys}
 for r in components:
  if r['is_warmup']=='0':buckets[(r['tree_size'],r['campaign_id'],r['scenario'],r['side'],r['component'])].append(r)
 for (n,cid,s,side,comp),g in buckets.items():
  assert len(g)==30
  component_campaign.append({'tree_size':int(n),'campaign_id':cid,'scenario':s,'side':side,'component':comp,'calls_median':st.median(float(r['calls']) for r in g),'cpu_ms_median':st.median(float(r['cpu_ms']) for r in g),'wall_ms_median':st.median(float(r['wall_ms']) for r in g)})
 write(root/'component-campaign-summary.csv',component_campaign)
 comps=[]
 for n,s,side,comp in sorted({(r['tree_size'],r['scenario'],r['side'],r['component']) for r in component_campaign}):
  g=[r for r in component_campaign if (r['tree_size'],r['scenario'],r['side'],r['component'])==(n,s,side,comp)];assert len(g)==5;calls=st.median(r['calls_median'] for r in g)
  comps.append({'tree_size':n,'scenario':s,'side':side,'component':comp,'calls_median':calls,'available':calls>0,**{m+'_'+stat:fn(r[m+'_median'] for r in g) if calls>0 else None for m in ['cpu_ms','wall_ms'] for stat,fn in [('median',st.median),('campaign_min',min),('campaign_max',max)]}})
 write(root/'component-scaling.csv',comps)
 # No CPU regression is forced; expose all five campaign medians at every depth.
 (root/'analysis-status.json').write_text(json.dumps({'passed':True,'primary_measured':len(allrows),'primary_warmups':len(warms),'detail_measured':len(details),'detail_warmups':len(detailwarms),'bootstrap_unit':'campaign at fixed N','campaigns_per_n_per_mode':5,'resamples':10000,'bootstrap_seed':20260910,'outlier_rows_retained':len(outliers),'hypothesis_tests':0,'timing_regressions':0},indent=2))
 report(root,aggregate,effects,comps,structural)
 print('Analysis complete:',root,flush=True)

def report(root,aggregate,effects,comps,structural):
 def get(n,s):return next(r for r in aggregate if int(r['tree_size'])==n and r['scenario']==s and r['mode']=='primary')
 def val(n,s,k='transport_total_bytes'):return float(get(n,s)[k+'_median'])
 def fmt(x):return f'{float(x):.3f}' if x not in ('',None) else 'unavailable'
 def table(headers,rows):return '\n'.join(['| '+' | '.join(headers)+' |','| '+' | '.join(['---']*len(headers))+' |']+['| '+' | '.join(map(str,r))+' |' for r in rows])
 lines=['# Controlled Merkle population scaling','', '## Scope and validation','', 'Evaluated N = 1, 4, 16, 64, 256, 1024. Thirty primary campaigns (five per N) plus thirty separate detail campaigns. Primary: 10,800 measured handshakes + 1,800 warmups; detail: 3,600 + 600. Separate preflight: 96 measured checks + 48 warmups, excluded from inference. No failed/repeated campaign or individual-sample exclusion. All outliers retained. Post-campaign regression status is recorded in tests-after-status.json; preservation status in preservation-after.json. Do not treat this report as released until those gates pass.','', 'TLS 1.3, X25519, TLS_AES_256_GCM_SHA384, server-only authentication, no tickets/resumption. PQ is ML-DSA-65 authentication, not a post-quantum key exchange. The exact N=16 image and native instrumentation are unchanged. New fixture metadata supplies actual server SPKI DER length. New host orchestration and a separate detail collector do not modify native authentication or encodings. The primary /opt/measurement/measure.py is unchanged.','', 'One 1,024-identity population per family, with prefix N. Identity zero retains the original server key/certificate, DNS name and validity. Additional identities share the server validity interval and fixed issuance policy; keys 1–15 are reused, other keys generated once. MTC CA and local cosigner keys are reused across all N. MTC log serial range changes with N; Compact root validity remains fixed. The surrounding N=16 population is newly issued under this controlled policy, so previous N=16 handshakes are not pooled with these campaigns.','', '## Statistical design','', 'At each N, seeds are 1000+N, 2000+N, 3000+N, 4000+N, 5000+N. Each campaign has five randomized warmup rounds and thirty randomized measured rounds. X.509 and RPK are remeasured within each campaign to retain round pairing, although their credential inputs do not depend on N. Both classic and PQ families have six primary scenarios; detail campaigns have the four PQ Merkle scenarios. Servers are recreated between campaigns; all sixty campaigns retain the same Docker bridge and resources.','', 'Scenario estimates are medians of five campaign medians. Effects are first the median of thirty round-paired differences within each campaign, then the median of five campaign effects. Percentile 95% intervals use 10,000 resamples of five campaigns at fixed N (seed 20260910). With only five campaigns, intervals are coarse and do not establish performance on other hosts. No handshake-level bootstrap is used for final inference. Per-campaign files inherited from the driver contain older within-campaign summaries; they are secondary and are not used for final inference. No bootstrap is used for bytes and no null-hypothesis tests are performed.','', 'N values were executed in ascending order, followed by a separate detail phase. Time trends across N can include host/time drift; no causal CPU complexity claim or forced timing regression is made. PROFILE_DETAIL=1 activates existing nested timers and must not be pooled with PROFILE_DETAIL=0.','', '## Table 1 — PQ TLS handshake bytes','',table(['N','X.509','RPK','Compact warm','MTC landmark','Compact cold','MTC standalone'],[[n,*[f'{val(n,"pq"+s):.0f}' for s in ['','-rpk','-compact-warm','-mtc-experimental-landmark','-compact-cold','-mtc-experimental-standalone']]] for n in SIZES]),'', 'PQ observed min/max and invariance are recorded in scaling-summary.csv. TLS bytes are BIO handshake bytes, excluding IP/TCP headers, HTTP and retransmissions.','', '## Table 2 — PQ overhead over RPK','',table(['N','Compact − RPK (B)','MTC landmark − RPK (B)','Compact − MTC (B)','Compact − MTC (%)'],[[n,f'{val(n,"pq-compact-warm")-val(n,"pq-rpk"):.0f}',f'{val(n,"pq-mtc-experimental-landmark")-val(n,"pq-rpk"):.0f}',f'{val(n,"pq-compact-warm")-val(n,"pq-mtc-experimental-landmark"):.0f}',f'{100*(val(n,"pq-compact-warm")/val(n,"pq-mtc-experimental-landmark")-1):.3f}'] for n in SIZES]),'', 'All requested X.509/RPK differences and percentages, including cold/standalone, are in byte-overhead.csv.','', '## Table 3 — primary PQ handshake wall time (ms)','',table(['N','X.509','RPK','Compact warm','MTC landmark','Compact cold','MTC standalone'],[[n,*[fmt(val(n,'pq'+s,'handshake_wall_ms')) for s in ['','-rpk','-compact-warm','-mtc-experimental-landmark','-compact-cold','-mtc-experimental-standalone']]] for n in SIZES]),'', 'Client/server/total CPU and full-process wall time are in timing-table.csv. All campaign medians and observed ranges are in campaign-summary.csv and scaling-summary.csv. Paired effects, ranges, intervals and sign stability are in bootstrap-comparisons.csv.','', '## Classic family — TLS median [observed min, max]','',table(['N','X.509','RPK','Compact warm','MTC landmark','Compact cold','MTC standalone'],[[n,*[f'{val(n,"classic"+s):g} [{get(n,"classic"+s)["transport_total_bytes_sample_min"]:g}, {get(n,"classic"+s)["transport_total_bytes_sample_max"]:g}]' for s in ['','-rpk','-compact-warm','-mtc-experimental-landmark','-compact-cold','-mtc-experimental-standalone']]] for n in SIZES]),'', 'ECDSA CertificateVerify signatures vary in DER length per handshake. Root/cosigner signatures are serialized once per immutable fixture, so their lengths may vary across N; observed classic medians and min/max are retained.','', '## Explicit answers to the scientific questions','']
 lines += ['1. **Compact proof size:** actual MTP1 = 45 fixed bytes + 32 bytes per sibling. Observed lengths are '+', '.join(f'N={r["tree_size"]}: {r["compact_proof_bytes"]} B' for r in structural if r['crypto_family']=='pq')+'. Each two-level N step adds 64 proof bytes. Its full credential also includes identity, validity, SPKI binding and framing.', '', '2. **MTC landmark certificate size:** '+', '.join(f'N={r["tree_size"]}: {r["mtc_landmark_certificate_der_bytes"]} B' for r in structural if r['crypto_family']=='pq')+'. MTCProof has 18 fixed bytes plus its path; the covering subtree has log2(N)−1 siblings for N≥4, versus zero for N=1. DER length-boundary changes affect the complete certificate.', '', '3. **The N=16 difference is not universally constant:** Compact warm minus MTC landmark is '+', '.join(f'{val(n,"pq-compact-warm")-val(n,"pq-mtc-experimental-landmark"):.0f} B at N={n}' for n in SIZES)+'.', '', '4. **Tree-dependent coefficients:** both raw paths cost 32 B per additional level once N≥4. MTC uses one fewer level due to its covering-subtree structure; this changes an offset, not the per-level hash cost. Full DER/TLS increments can include length framing. size-increments.csv contains actual increments; size-slopes.csv provides descriptive slopes, intercepts, R² and residuals for all N and N≥4 separately. N=1 has no sibling hashes and only one covering subtree; retain it as a corner-case baseline.', '']
 for num,s in [(5,'pq-compact-warm'),(6,'pq-mtc-experimental-landmark')]:
  hit=[n for n in SIZES if val(n,s)>=val(n,'pq')];lines += [f'{num}. **{s} vs PQ X.509:** '+('first evaluated N at/above X.509 is '+str(min(hit))+'.' if hit else 'no evaluated N loses its byte advantage over PQ X.509.')+' No precise unevaluated crossover is extrapolated.','']
 classic=[]
 for s in ['classic-compact-warm','classic-mtc-experimental-landmark']:
  hit=[n for n in SIZES if val(n,s)>=val(n,'classic')];classic.append(s+': '+('first evaluated median crossover N='+str(min(hit)) if hit else 'no evaluated median crossover'))
 lines += ['7. **Classic family:** '+'; '.join(classic)+'. The table retains signature-size ranges; an evaluated crossing does not locate the exact threshold between sampled N.','', '8. **Predistributed material:** '+ '; '.join(f'N={r["tree_size"]}: PQ Compact root {r["compact_signed_root_bytes"]} B; MTC landmark file {r["mtc_predistributed_landmark_bytes"]} B (increment over authority {r["mtc_landmark_incremental_bytes"]} B)' for r in structural if r['crypto_family']=='pq')+'. Full setup CPU/wall and nested validation wall are measured for every new client process. MTC authority keys and checkpoint/subtrees are separately accounted in structural-sizes.csv.','', '9. **Amortization:** amortization.csv applies TLS + trust/H for H=1,10,100,1000,10000. The main stored-material model uses the Compact signed root versus the whole MTC landmark file (including its embedded authority keys); a second column subtracts the MTC authority base for an incremental-trust comparison. Compact CA provisioning is pre-existing. The model excludes distribution headers, retransmissions, storage, cache misses, updates, revocation, failed distribution and the act of trust-anchor provisioning. This is an analytical byte model, not measured persistent cache reuse. Setup/validation repeats per new process and is not divided by H as a measured timing result.','']
 for suffix in ['-compact-warm','-compact-cold']:
  s='pq'+suffix;groups=[r for r in comps if r['scenario']==s and r['side']=='client' and r['component']=='merkle_proof'];lines += [f'10. **{s} proof CPU, separate detail phase:** '+', '.join(f'N={r["tree_size"]}: {1000*float(r["cpu_ms_median"]):.3f} µs [{1000*float(r["cpu_ms_campaign_min"]):.3f}, {1000*float(r["cpu_ms_campaign_max"]):.3f}]' for r in groups)+'. These are campaign medians/ranges; no linear timing model is forced.','']
  first=next(r for r in groups if int(r['tree_size'])==1);last=next(r for r in groups if int(r['tree_size'])==1024)
  delta=float(last['cpu_ms_median'])-float(first['cpu_ms_median'])
  lines += [f'Observed endpoint change N=1→1024: {delta*1000:.3f} µs ({100*delta/float(first["cpu_ms_median"]):.1f}% of the N=1 proof CPU median). This is an absolute/relative descriptive effect, not a paired cross-N inference; see all intermediate campaign ranges before attributing it to depth.','']
 lines += ['**MTC proof-only CPU is unavailable:** existing MTC diagnostics expose aggregate authentication wall time, while generic peer_auth is inclusive. There are no isolated MTC inclusion/subtree-signature/cosignature CPU timers in the frozen binary. Their missing values are not zeros, and no MTC proof-only CPU slope is claimed.','']
 dominance=[];dominates=[]
 for n in SIZES:
  def comp(name):return next(r for r in comps if int(r['tree_size'])==n and r['scenario']=='pq-compact-warm' and r['side']=='client' and r['component']==name)
  sp=comp('spki_encode');pr=comp('merkle_proof');dominance.append(f'N={n}: SPKI encode {fmt(sp["cpu_ms_median"])} ms / proof {fmt(pr["cpu_ms_median"])} ms')
  dominates.append(float(sp['cpu_ms_median'])>float(pr['cpu_ms_median']))
 lines += ['11. **SPKI versus Merkle:** '+'; '.join(dominance)+'. Compare these separate nested categories; do not sum them with inclusive credential_total or handshake CPU. component-scaling.csv retains spki_hash, credential_total and all other available categories.','']
 lines += [('SPKI encoding remains larger than Merkle verification at every evaluated N in the separate detail measurements.' if all(dominates) else 'SPKI encoding does not exceed Merkle verification at every evaluated N; use the per-N values rather than the prior N=16 conclusion.'),'']
 selected=[r for r in effects if r['scenario']=='pq-mtc-experimental-landmark' and r['baseline']=='pq' and r['metric']=='handshake_wall_ms']
 lines += ['12. **MTC landmark timing vs X.509:** '+ '; '.join(f'N={r["tree_size"]}: paired {fmt(r["median_campaign_paired_difference"])} ms, 95% CI [{fmt(r["bootstrap95_low"])}, {fmt(r["bootstrap95_high"])}], {r["stability"]}' for r in selected)+'. Server CPU and full-process latency must be judged separately; lower timed wall does not automatically imply lower CPU.','', '13. **Measurements versus models:** serialized sizes, TLS traffic, setup and handshake timers are measurements. log2(N), 32·ceil(log2(N)), serialized-size fits and TLS+trust/H are reference calculations/descriptive analytical models. No exact unevaluated crossover, persistent reuse, CPU complexity proof or protocol-equivalent security saving is claimed.','', '## Architectural interpretation','', 'Compact warm vs MTC landmark compares different designs. MTC retains DER TBSCertificate, richer X.509 fields/leaf validation, log entries, checkpoints and a CA plus local cosigner model. Compact binds SPKI, DNS and validity through its smaller credential and root. MTC landmark depends on authenticated out-of-band checkpoints/subtrees. MTC here is experimental draft-05, uses a private exact-ID TLS extension and limited direct-CA/leaf PKIX validation; there is no public transparency log or independent cosigner deployment. Smaller encoding alone does not establish superiority.','', '**Compact cold vs MTC standalone is an architectural comparison, not security-equivalent savings.** MTC standalone carries CA and cosigner subtree signatures. X.509 baseline has no SCTs. Their byte and timing differences cannot be attributed solely to Merkle algorithms.','', '## Timing stability and limitations','']
 for metric in TIMING:
  g=[r for r in effects if r['scenario'].startswith('pq') and r['metric']==metric];supported=sum(r['stability']=='direction supported in these campaigns' for r in g);lines += [f'- {metric}: {supported}/{len(g)} PQ contrasts have directionally supported campaign intervals; {len(g)-supported} are uncertain/unstable. Full details retain signs and ranges.']
 lines += ['', 'All outliers remain in every summary. Host scheduling, process launch, CPU frequency and fixed N execution order limit attribution of timing trends. Five campaigns are a modest replication count. The unmeasured isolated MTC proof CPU prevents a complete answer to the requested two-scheme CPU-complexity comparison. Do not claim that part is validated.','', '## Figures and machine-readable data','', 'plots/ contains five requested publication figures in PDF, SVG and PNG, plus proof-size and Compact proof-CPU figures. Timing figures show the five campaign medians as observations plus their median, without bootstrap error bars or fitted trend claims. MTC proof-only CPU is explicitly unavailable. Figure 2 uses TLS bytes minus RPK TLS bytes, not raw credential DER subtraction. All values come from saved CSV files.','', 'Required tables: tls-bytes-table.csv, byte-overhead.csv, timing-table.csv. Reproducibility: metadata.json, environment.json, images-before.json, fixture inventories, generation.log, tests.log, tests-after.log, source snapshot and campaign endpoint logs. Private keys remain solely in protected fixture storage; result/source snapshots contain hashes, not private key contents.','']
 lines += ['## PQ warm trust and measured setup','',table(['N','Compact root B','MTC landmark file B','Compact setup wall ms','MTC setup wall ms','Compact setup CPU ms','MTC setup CPU ms'],[[n,next(r['compact_signed_root_bytes'] for r in structural if r['crypto_family']=='pq' and int(r['tree_size'])==n),next(r['mtc_predistributed_landmark_bytes'] for r in structural if r['crypto_family']=='pq' and int(r['tree_size'])==n),fmt(val(n,'pq-compact-warm','setup_wall_ms')),fmt(val(n,'pq-mtc-experimental-landmark','setup_wall_ms')),fmt(val(n,'pq-compact-warm','setup_cpu_ms')),fmt(val(n,'pq-mtc-experimental-landmark','setup_cpu_ms'))] for n in SIZES]),'', 'Setup is outside the handshake window. Warm root/checkpoint validation is nested within it and repeated per process. Architectural paired setup effects and intervals are in bootstrap-comparisons.csv. root-signature-setup.csv also retains the original root signature wall/CPU diagnostics.','', '## Analytical PQ amortization — stored trust model','']
 amort_rows=read(root/'amortization.csv')
 lines += [table(['N','Scheme','H=1','H=10','H=100','H=1,000','H=10,000'],[[n,s,*[fmt(next(r['amortized_total_per_connection'] for r in amort_rows if int(r['tree_size'])==n and r['scenario']==s and int(r['H'])==h)) for h in [1,10,100,1000,10000]]] for n in [16,256,1024] for s in ['pq-compact-warm','pq-mtc-experimental-landmark']]),'', 'All entries are bytes per connection from the analytical formula. The incremental model excluding MTC authority bytes is retained alongside this model in amortization.csv. No timing amortization is inferred.','', '## Serialized fixed/tree decomposition','', 'fixed-and-tree-components.csv subtracts the actual sibling-hash payload from each actual serialized object. The remainder includes fixed fields, signatures and framing; it may change at DER boundaries or with ECDSA signature lengths. It is not assumed constant. size-increments.csv separately records raw-proof, complete-object and observed TLS increments for every N step.','']
 diagnostics=[]
 for r in read(root/'campaign-summary.csv'):
  if r['mode']!='primary' or r['scenario'] not in ['classic','pq','classic-rpk','pq-rpk']:continue
  n=int(r['tree_size']);s=r['scenario']
  diagnostics.append({'tree_size':n,'campaign_id':r['campaign_id'],'scenario':s,**{m:float(r[m+'_median']) for m in TIMING},**{m+'_ratio_to_same_n_campaign_median':float(r[m+'_median'])/val(n,s,m) for m in TIMING}})
 write(root/'baseline-diagnostics.csv',diagnostics)
 flagged=[r for r in diagnostics if r['scenario']=='pq-rpk' and (r['handshake_wall_ms_ratio_to_same_n_campaign_median']>2 or r['handshake_client_cpu_ms_ratio_to_same_n_campaign_median']>2)]
 lines += ['## Post-hoc fixed-baseline timing diagnostic','', f'The diagnostic identified {len(flagged)} markedly slower primary campaigns. This diagnostic retains every observation and is not an exclusion rule. The unchanged RPK baseline also slows, which is evidence of a campaign/environment effect rather than an N-dependent Merkle cost. The cause was not instrumented; both wall and CPU rise, so this must not be attributed only to scheduling waits.','',table(['Campaign','PQ RPK wall ms','PQ RPK client CPU ms','Wall / same-N median','Client CPU / same-N median'],[[r['campaign_id'],fmt(r['handshake_wall_ms']),fmt(r['handshake_client_cpu_ms']),fmt(r['handshake_wall_ms_ratio_to_same_n_campaign_median']),fmt(r['handshake_client_cpu_ms_ratio_to_same_n_campaign_median'])] for r in flagged]),'', 'baseline-diagnostics.csv contains all fixed-baseline campaign values, not just these observations (>2× same-N campaign median, a post-hoc descriptive flag). Paired effects and their campaign intervals remain reported with these campaigns included. Absolute handshake/CPU scaling curves are provisional for causal interpretation and should not support an algorithmic speedup or complexity claim in the study. Serialized-size and traffic findings are unaffected by this timing variation.','', 'At N=1024, the difference of scenario wall medians for MTC landmark versus X.509 is positive while the median round-paired campaign effect is negative with an interval crossing zero. They are different estimators; no directional improvement is established there.','']
 if (root/'tests-after-status.json').exists() and (root/'preservation-after.json').exists():
  if json.loads((root/'tests-after-status.json').read_text())['passed'] and json.loads((root/'preservation-after.json').read_text())['passed']:
   lines += ['## Final gates','', 'The complete positive/negative/regression gate passed both before and after all campaigns. All recorded previous source/input/result hashes and new fixture hashes match. Authentication/control validation passed for every campaign; no campaigns were excluded. These gates validate execution and preservation, not the absent MTC proof-only CPU metric or the environmental attribution of noisy timing campaigns.','']
   lines=[line.replace('Do not treat this report as released until those gates pass.','Both gates passed; see the final-gates section.') for line in lines]
 (root/'report.md').write_text('\n'.join(lines))
def refresh_report(root):
 def numeric(rows):
  for r in rows:
   for k,v in list(r.items()):
    if v=='':r[k]=None;continue
    try:r[k]=int(v) if k in ['tree_size','campaigns','resamples','negative_campaigns','positive_campaigns'] else float(v)
    except ValueError:pass
  return rows
 report(root,numeric(read(root/'scaling-summary.csv')),numeric(read(root/'bootstrap-comparisons.csv')),numeric(read(root/'component-scaling.csv')),read(root/'structural-sizes.csv'))
if __name__=='__main__':
 root=Path(sys.argv[1])
 if '--report-only' in sys.argv:refresh_report(root)
 else:analyze(root)
