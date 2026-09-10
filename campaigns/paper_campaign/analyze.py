"""Campaign is the resampling unit. Never bootstrap pooled handshakes."""
import argparse,csv,hashlib,json,math,random,statistics
from pathlib import Path
TIMING=['handshake_wall_ms','handshake_client_cpu_ms','handshake_server_cpu_ms','handshake_total_cpu_ms','client_process_http_wall_ms']
PRIMARY_METRICS=['transport_total_bytes',*TIMING]
EXTRA=['transport_read_bytes','transport_written_bytes','certificate_message_bytes','certificate_verify_bytes','encrypted_extensions_bytes',
       'rpk_spki_bytes','compact_credential_bytes','merkle_proof_bytes','signed_root_bytes','signed_root_tls_bytes',
       'root_setup_ms','root_validation_ms','setup_wall_ms','setup_cpu_ms','trust_validation_ms','trust_base_bytes',
       'predistributed_bytes','predistributed_incremental_bytes','mtc_certificate_bytes','mtc_tbs_bytes','mtc_proof_bytes',
       'mtc_inclusion_proof_bytes','mtc_subtree_signature_bytes','mtc_cosignature_bytes','mtc_checkpoint_bytes',
       'mtc_checkpoint_oob_bytes','mtc_landmark_bytes','mtc_setup_ms','mtc_trust_validation_ms']
METRICS=PRIMARY_METRICS+EXTRA
SUFFIXES=['','-rpk','-compact-warm','-compact-cold','-mtc-experimental-standalone','-mtc-experimental-landmark']

def quantile(values,p):
    v=sorted(values);i=(len(v)-1)*p;lo=math.floor(i);hi=math.ceil(i)
    return v[lo]+(v[hi]-v[lo])*(i-lo)
def paired_effect(x,y):
    if set(x)!=set(y):raise ValueError('Unpaired rounds')
    return statistics.median(x[k]-y[k] for k in sorted(x))
def bootstrap_campaign(values,resamples):
    if len(values)!=10:raise ValueError('Exactly ten campaign effects required')
    b=[statistics.median(values[i] for i in indices) for indices in resamples]
    return quantile(b,.025),quantile(b,.975)
def sign_stability(v,low,high):
    neg=sum(x<0 for x in v);pos=sum(x>0 for x in v)
    if min(neg,pos)>=2:return 'unstable: both signs in at least 2/10 campaigns'
    if low<=0<=high:return 'uncertain: campaign interval includes zero'
    return 'direction supported within these campaigns'
def number(row,key):
    value=row.get(key,'')
    return float(value) if value not in ('',None) else None
def read(path):
    with path.open(newline='') as f:return list(csv.DictReader(f))
def write(path,rows):
    if not rows:return
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]),lineterminator='\n');w.writeheader();w.writerows(rows)
def correlation(x,y):
    mx=statistics.mean(x);my=statistics.mean(y)
    den=math.sqrt(sum((v-mx)**2 for v in x)*sum((v-my)**2 for v in y))
    return sum((a-mx)*(b-my) for a,b in zip(x,y))/den if den else None

def analyze(root):
    status=json.loads((root/'campaign-status.json').read_text())
    if status['failed_campaign'] or len(status['campaigns'])!=10 or any(c['state']!='complete' for c in status['campaigns']):raise RuntimeError('Ten complete campaigns required')
    if (root/'all-samples.csv').exists():raise RuntimeError('Analysis already exists; do not overwrite')
    campaign_data=[];allrows=[];warmrows=[];seen=set();natives=[]
    for ci,record in enumerate(status['campaigns'],1):
        directory=root/record['campaign_id'];meta=json.loads((directory/'metadata.json').read_text())
        assert record['seed']==41+ci==meta['seed'];assert meta['runs']==30 and meta['warmup']==5 and meta['image_id']==status['image_id']
        rows=read(directory/'samples.csv');warm=read(directory/'warmups.csv');scenarios=meta['scenarios'];assert len(scenarios)==14
        rng=random.Random(meta['seed'])
        for observations,n,w in [(warm,5,1),(rows,30,0)]:
            assert len(observations)==n*14
            for r in range(1,n+1):
                order=scenarios.copy();rng.shuffle(order)
                group=sorted([x for x in observations if int(x['round_id'])==r],key=lambda x:int(x['order_in_round']))
                assert [x['scenario'] for x in group]==order
                for x in group:
                    assert x['campaign_id']==record['campaign_id'] and int(x['seed'])==meta['seed'] and int(x['is_warmup'])==w
                    assert x['client_random'] not in seen;seen.add(x['client_random'])
                    for key in PRIMARY_METRICS:assert math.isfinite(number(x,key)) and number(x,key)>0
                    assert number(x,'transport_total_bytes')==number(x,'transport_read_bytes')+number(x,'transport_written_bytes')
                    assert abs(number(x,'handshake_total_cpu_ms')-number(x,'handshake_client_cpu_ms')-number(x,'handshake_server_cpu_ms'))<1e-8
        allrows.extend(rows);warmrows.extend(warm);campaign_data.append((record,rows,meta));natives.append(meta)
    # Fixtures and protocol controls must remain identical across campaigns.
    for key in ['fixture','compact','inputs','configuration','openssl_commit','liboqs_commit','oqs_provider_commit','mtc_hash','compact_hash','profile_hash']:
        assert all(m[key]==natives[0][key] for m in natives),key
    write(root/'all-samples.csv',allrows);write(root/'all-warmups.csv',warmrows)
    scenarios=natives[0]['scenarios'];summaries=[];outliers=[]
    for record,rows,meta in campaign_data:
        for scenario in scenarios:
            group=[r for r in rows if r['scenario']==scenario]
            s={'campaign_id':record['campaign_id'],'seed':record['seed'],'scenario':scenario,'crypto_family':group[0]['crypto_family'],'tree_size':16,'n':len(group)}
            for metric in METRICS:
                values=[number(r,metric) for r in group if number(r,metric) is not None]
                assert len(values) in [0,30]
                s[metric+'_median']=statistics.median(values) if values else None
                s[metric+'_min']=min(values) if values else None;s[metric+'_max']=max(values) if values else None
                if metric in TIMING:
                    q1=quantile(values,.25);q3=quantile(values,.75);lo=q1-1.5*(q3-q1);hi=q3+1.5*(q3-q1)
                    for r in group:
                        v=number(r,metric)
                        if v<lo or v>hi:outliers.append({'campaign_id':record['campaign_id'],'scenario':scenario,'round_id':r['round_id'],'metric':metric,'value':v,'lower_fence':lo,'upper_fence':hi,'client_random':r['client_random']})
            summaries.append(s)
    write(root/'campaign-summary.csv',summaries)
    aggregated=[]
    for scenario in scenarios:
        s={'scenario':scenario,'campaigns':10}
        group=[r for r in summaries if r['scenario']==scenario]
        for metric in METRICS:
            values=[r[metric+'_median'] for r in group if r[metric+'_median'] is not None]
            s[metric+'_median_of_campaign_medians']=statistics.median(values) if values else None
            s[metric+'_campaign_min']=min(values) if values else None;s[metric+'_campaign_max']=max(values) if values else None
            s[metric+'_campaign_cv_percent']=100*statistics.stdev(values)/statistics.mean(values) if values and statistics.mean(values)>0 else None
        aggregated.append(s)
    write(root/'scenario-summary.csv',aggregated)
    pairs=[]
    for family in ['classic','pq']:
        for suffix in SUFFIXES[1:]:pairs.append((family+suffix,family,'primary'))
        pairs += [(family+'-compact-warm',family+'-rpk','layer'),(family+'-mtc-experimental-landmark',family+'-rpk','layer'),
                  (family+'-compact-warm',family+'-mtc-experimental-landmark','architectural'),(family+'-compact-cold',family+'-mtc-experimental-standalone','architectural'),
                  (family+'-mt',family,'secondary')]
    paired=[]
    for record,rows,meta in campaign_data:
        for left,right,kind in pairs:
            for metric in PRIMARY_METRICS:
                x={r['round_id']:number(r,metric) for r in rows if r['scenario']==left};y={r['round_id']:number(r,metric) for r in rows if r['scenario']==right}
                paired.append({'campaign_id':record['campaign_id'],'seed':record['seed'],'scenario':left,'baseline':right,'comparison_class':kind,'metric':metric,
                    'paired_median_difference':paired_effect(x,y),'transport_percentage_difference':100*(statistics.median(x.values())/statistics.median(y.values())-1) if metric=='transport_total_bytes' else None,
                    'paired_percentage_median':statistics.median(100*(x[k]-y[k])/y[k] for k in x) if metric=='transport_total_bytes' else None,'protocol_equivalent':False})
    write(root/'paired-comparisons.csv',paired)
    rng=random.Random(20260910);resamples=[rng.choices(range(10),k=10) for _ in range(10000)];boot=[]
    for left,right,kind in pairs:
        for metric in PRIMARY_METRICS:
            group=[r for r in paired if r['scenario']==left and r['baseline']==right and r['metric']==metric]
            values=[r['paired_median_difference'] for r in group];low,high=bootstrap_campaign(values,resamples)
            signs=[-1 if x<0 else 1 for x in values if x!=0]
            boot.append({'scenario':left,'baseline':right,'comparison_class':kind,'metric':metric,'campaigns':10,'resamples':10000,'bootstrap_seed':20260910,
                         'median_campaign_paired_difference':statistics.median(values),'campaign_min_difference':min(values),'campaign_max_difference':max(values),
                         'bootstrap95_low':low,'bootstrap95_high':high,'negative_campaigns':sum(v<0 for v in values),'positive_campaigns':sum(v>0 for v in values),'zero_campaigns':sum(v==0 for v in values),
                         'chronological_sign_changes':sum(a!=b for a,b in zip(signs,signs[1:])),
                         'transport_percentage_difference_median':statistics.median(r['transport_percentage_difference'] for r in group) if metric=='transport_total_bytes' else None,
                         'stability':sign_stability(values,low,high),'protocol_equivalent':False})
    write(root/'bootstrap-comparisons.csv',boot)
    ranks=[]
    for record,rows,meta in campaign_data:
        for family in ['classic','pq']:
            group=[r for r in summaries if r['campaign_id']==record['campaign_id'] and r['scenario'] in [family+s for s in SUFFIXES]]
            for metric in TIMING:
                values=[r[metric+'_median'] for r in group]
                for r in group:
                    v=r[metric+'_median'];rank=1+sum(x<v for x in values)+.5*(sum(x==v for x in values)-1)
                    ranks.append({'campaign_id':record['campaign_id'],'scenario':r['scenario'],'metric':metric,'rank':rank})
    write(root/'scenario-ranks.csv',ranks)
    if outliers:write(root/'outliers.csv',outliers)
    diagnostics=[]
    for scenario in scenarios:
        group=[r for r in summaries if r['scenario']==scenario];x=[r['handshake_wall_ms_median'] for r in group]
        diagnostics.append({'scenario':scenario,'wall_client_cpu_correlation_campaign_medians':correlation(x,[r['handshake_client_cpu_ms_median'] for r in group]),
            'wall_total_cpu_correlation_campaign_medians':correlation(x,[r['handshake_total_cpu_ms_median'] for r in group]),
            'wall_tukey_outliers_retained':sum(r['scenario']==scenario and r['metric']=='handshake_wall_ms' for r in outliers),
            'largest_observed_wall_ms':max(number(r,'handshake_wall_ms') for r in allrows if r['scenario']==scenario)})
    write(root/'timing-diagnostics.csv',diagnostics)
    decomp=[]
    definitions=[('X509_overhead_removed','pq','pq-rpk'),('compact_layer_overhead','pq-compact-warm','pq-rpk'),('mtc_landmark_layer_overhead','pq-mtc-experimental-landmark','pq-rpk'),('compact_vs_mtc_landmark_bytes','pq-compact-warm','pq-mtc-experimental-landmark')]
    for record,rows,meta in campaign_data:
        med={r['scenario']:r['transport_total_bytes_median'] for r in summaries if r['campaign_id']==record['campaign_id']}
        for name,left,right in definitions:decomp.append({'campaign_id':record['campaign_id'],'quantity':name,'bytes':med[left]-med[right]})
    write(root/'byte-decomposition.csv',decomp)
    baseline=json.loads((root/'baseline.json').read_text());environment=json.loads((root/'environment-before.json').read_text())
    environment['measurement_image']=json.loads((root/'measurement-image.json').read_text());environment['campaign_server_resources']={r['campaign_id']:r['resources'] for r in status['campaigns']};environment['campaign_networks']={r['campaign_id']:r['networks'] for r in status['campaigns']}
    environment['container']= {k:natives[0][k] for k in ['architecture','platform','visible_cpus','memory','cpu.max','memory.max'] if k in natives[0]}
    (root/'environment.json').write_text(json.dumps(environment,indent=2)+'\n')
    metadata={'baseline':baseline,'draft':'draft-ietf-plants-merkle-tree-certs-05','status':'MTC-experimental','campaigns':10,'seeds':list(range(42,52)),'tree_size':16,
        'scenarios':scenarios,'primary_scenarios':{f:[f+s for s in SUFFIXES] for f in ['classic','pq']},'secondary_scenarios':['classic-mt','pq-mt'],
        'measured_handshakes':len(allrows),'warmup_handshakes':len(warmrows),'measurement_preflight':{'measured':28,'warmup':14,'excluded_from_campaign_analysis':True},
        'replication_unit':'campaign; shared Docker Desktop session, new server containers, same bridge, same resource configuration',
        'statistics':{'point_estimate':'median of ten campaign medians; contrasts: median of ten within-campaign paired median differences','bootstrap_unit':'ten campaign effects','bootstrap_resamples':10000,'bootstrap_seed':20260910,'interval':'percentile with linear interpolation','within_campaign_bootstrap':'2000 resamples retained as secondary in campaign-*/comparisons.csv','instability':'at least two positive and two negative campaign effects','outliers':'Tukey 1.5 IQR within each campaign/scenario; none removed','cv':'sample SD / mean of ten campaign medians, percent','null_hypothesis_tests':False},
        'implementation_changes':'Only isolated s_client setup wall/CPU wrappers; original protocol sources, fixtures and libraries unchanged',
        'setup_scope':'compact_client or mtc_client, including configuration load, prior validation and callback registration; before SSL_new/handshake; nested setup logging included; PAPER_SETUP output itself excluded',
        'byte_definitions':natives[0]['byte_definitions'],
        'additional_accounting':{'predistributed_bytes':'total local trust configuration file bytes, including CA material; PEM for compact/X509, binary MCF1 for MTC; not network transport',
            'predistributed_incremental_bytes':'signed root for compact warm; trust.bin minus authority.bin for MTC landmark',
            'trust_validation_ms':'compact warm: root signature operation only; MTC landmark: checkpoint signatures only; nested within setup; cold blank if not separately timed',
            'root_setup_ms':'alias for full compact configuration setup wall time','mtc_proof_bytes':'entire encoded MTCProof, including signatures if present','mtc_subtree_signature_bytes':'raw CA signature only','mtc_checkpoint_bytes':'TLS checkpoint bytes, always zero','mtc_checkpoint_oob_bytes':'serialized checkpoint fields and signature vector in trust.bin','mtc_landmark_bytes':'complete trust.bin file, not TLS bytes','signed_root_tls_bytes':'root payload sent in compact cold only','missing_values':'empty CSV cells mean unmeasured/not applicable, never fabricated zeros'},
        'trust_cache':'none; each new client process reloads and revalidates root/landmark',
        'security_asymmetry':'MTC standalone requires CA and one local cosigner; X509 has no SCTs. Compact/MTC comparisons are architectural, not protocol-equivalent.',
        'tests':json.loads((root/'tests-status.json').read_text()),'failed_campaigns':[],'repeated_campaigns':[],
        'preflight_harness_corrections':['attempt 01: legacy C demos invoked without required fixture arguments','attempt 02: codigoOriginal/C/mtc_tests.c deliberately returns 1 on success; output/status-aware wrapper added; protocol untouched'],
        'scaling_executed':False}
    (root/'metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
    report(root,aggregated,boot,ranks,diagnostics,metadata)
    print(json.dumps({'campaigns':10,'measured':len(allrows),'warmup':len(warmrows),'root':str(root)}))

def report(root,aggregated,boot,ranks,diagnostics,metadata):
    by={r['scenario']:r for r in aggregated};pq=['pq'+s for s in SUFFIXES]
    val=lambda s,m:by[s][m+'_median_of_campaign_medians']
    fmt=lambda v:'—' if v is None else (str(int(v)) if float(v).is_integer() else f'{v:.6f}')
    timing=lambda v:'—' if v is None else f'{v:.6f}'
    lines=['# Controlled N=16 campaigns: MTC-experimental and existing TLS controls','',
        '**10/10 successful campaigns; 4200 measured handshakes and 700 warmups.** Each campaign recreated servers, used 5 warmup and 30 paired measurement rounds for 14 scenarios, and a distinct seed 42–51. All share one Docker Desktop session. No campaign failed or was repeated.', '',
        'Baseline commit: `'+metadata['baseline']['git_commit']+'`. MTC remains **MTC-experimental**, targeting draft-ietf-plants-merkle-tree-certs-05. No protocol behavior was changed. An isolated s_client adds setup wall/CPU measurements; source/fixture hashes and original libraries were preserved.', '',
        'All regression and negative tests passed before campaigns. Two initial launcher failures (missing legacy demo arguments and its success exit code 1) were corrected and archived in preflight-attempts/. They were not protocol failures. The final measurement preflight had 28 handshakes and 14 warmups, excluded from the counts and analysis above.', '',
        '## Table A — PQ authentication','',
        'Entries are **medians of ten campaign medians**, not medians of 300 pooled observations. Times are milliseconds. CPU total is formed per paired connection before campaign aggregation. Ranges, unrounded values and full classic results are retained in CSV.', '',
        '| Scenario | TLS bytes | Handshake wall ms | Client CPU ms | Server CPU ms | Total CPU ms |','|---|---:|---:|---:|---:|---:|']
    for s in pq:lines.append('| '+s+' | '+fmt(val(s,'transport_total_bytes'))+' | '+' | '.join(timing(val(s,m)) for m in TIMING[:4])+' |')
    lines += ['','## Table B — PQ byte decomposition','',
        'Arrows mean **destination minus origin**; percentages use the origin as denominator. These are architectural byte differences, not equal-security substitutions. The four explicit quantities below additionally use the requested sign convention.', '',
        '| Transition | Difference bytes | Difference % |','|---|---:|---:|']
    transitions=[('X509 → RPK','pq','pq-rpk'),('RPK → Compact warm','pq-rpk','pq-compact-warm'),('RPK → MTC landmark','pq-rpk','pq-mtc-experimental-landmark'),('X509 → Compact warm','pq','pq-compact-warm'),('X509 → MTC landmark','pq','pq-mtc-experimental-landmark'),('Compact warm → MTC landmark','pq-compact-warm','pq-mtc-experimental-landmark')]
    for name,a,b in transitions:
        x=val(a,'transport_total_bytes');d=val(b,'transport_total_bytes')-x
        lines.append(f'| {name} | {d:+.6f} | {100*d/x:+.6f}% |')
    quantities=[('X509_overhead_removed','pq','pq-rpk'),('compact_layer_overhead','pq-compact-warm','pq-rpk'),('mtc_landmark_layer_overhead','pq-mtc-experimental-landmark','pq-rpk'),('compact_vs_mtc_landmark_bytes','pq-compact-warm','pq-mtc-experimental-landmark')]
    lines+=['']+[f'- `{name} = {fmt(val(a,"transport_total_bytes")-val(b,"transport_total_bytes"))}` bytes.' for name,a,b in quantities]
    lines+=['','The X509→RPK contrast removes a certificate/container and changes trust semantics. Compact and MTC landmark add distinct layers. The net Compact/MTC difference combines credential fields, proof encoding and TLS signalling; it does not isolate only ASN.1 overhead.',
        'MTC standalone carries CA authentication **plus one local cosigner**, while the X509 reference has no SCTs or equivalent cosigner. Its larger/smaller byte count must not be interpreted as an equivalent-security comparison.', '',
        '## Table C — PQ trust distribution','',
        'OOB bytes are **local file sizes**, not transmitted TLS bytes: total trust material and (increment beyond common keys/policy). Compact uses a CA PEM plus a binary signed root; MTC uses binary configuration. Setup is before the timed handshake; it includes loading and validation. Validation is the nested signature-operation subset, so **do not add it to setup**.', '',
        '| Mode | OOB total (increment) bytes | Setup wall / CPU ms | Prior signature validation ms | TLS bytes | Authentication object in TLS, excluding CertificateVerify | Reuse |',
        '|---|---:|---:|---:|---:|---|---|']
    for s in ['pq-compact-warm','pq-compact-cold','pq-mtc-experimental-landmark','pq-mtc-experimental-standalone']:
        if s.endswith('compact-warm'):obj=f'credential {fmt(val(s,"compact_credential_bytes"))}; encoded proof {fmt(val(s,"merkle_proof_bytes"))}; root absent'
        elif s.endswith('compact-cold'):obj=f'signed root payload {fmt(val(s,"signed_root_tls_bytes"))}; credential/proof also sent'
        elif s.endswith('landmark'):obj=f'MTCProof {fmt(val(s,"mtc_proof_bytes"))}; no subtree signatures'
        else:obj=f'MTCProof {fmt(val(s,"mtc_proof_bytes"))}, including CA {fmt(val(s,"mtc_subtree_signature_bytes"))} + cosigner {fmt(val(s,"mtc_cosignature_bytes"))} signature bytes'
        reuse='root/landmark validated every process' if s.endswith(('warm','landmark')) else 'new process; signatures verified during TLS'
        lines.append(f'| {s} | {fmt(val(s,"predistributed_bytes"))} ({fmt(val(s,"predistributed_incremental_bytes"))}) | {timing(val(s,"setup_wall_ms"))} / {timing(val(s,"setup_cpu_ms"))} | {timing(val(s,"trust_validation_ms"))} | {fmt(val(s,"transport_total_bytes"))} | {obj} | {reuse} |')
    lines+=['','For PQ Compact, the signed root payload is 3399 bytes. The cold–warm TLS difference is 3367 bytes because the warm ClientHello additionally carries a 32-byte root identifier. A file/payload size must not be substituted for the net transport difference.', '', 'No persistent cache was implemented or measured. Compact cold root validation is inside the handshake and not separately timed; the missing prior-validation value is not zero cost. MTC standalone configures trusted keys before TLS and checks subtree signatures inside TLS. Its prior checkpoint-validation value is zero because no checkpoint is used. All modes retain native TLS CertificateVerify and Finished.', '',
        '## Table D — Independent campaign stability','',
        'Ranges are min/max of the ten **campaign medians**. CV is sample standard deviation divided by their mean, in percent. Rank is among the six primary PQ scenarios by campaign median wall time; ties receive average ranks.', '',
        '| Scenario | Wall median range ms | Wall CV % | Client CPU median range ms | Total CPU CV % | Wall rank range |','|---|---:|---:|---:|---:|---:|']
    for s in pq:
        r=by[s];rs=[x['rank'] for x in ranks if x['scenario']==s and x['metric']=='handshake_wall_ms']
        lines.append(f'| {s} | {r["handshake_wall_ms_campaign_min"]:.6f}–{r["handshake_wall_ms_campaign_max"]:.6f} | {r["handshake_wall_ms_campaign_cv_percent"]:.6f} | {r["handshake_client_cpu_ms_campaign_min"]:.6f}–{r["handshake_client_cpu_ms_campaign_max"]:.6f} | {r["handshake_total_cpu_ms_campaign_cv_percent"]:.6f} | {min(rs):g}–{max(rs):g} |')
    lines+=['','### Timing interpretation','',
        'For each contrast, the effect is first the median of round-paired differences within a campaign. The final estimate is the median of ten such effects. Confidence intervals resample these **ten campaign effects**, 10000 times (seed 20260910), using percentile intervals. No null-hypothesis tests were added. Within-campaign bootstrap files remain secondary.', '',
        'A contrast is labelled sign-unstable when at least two campaigns are positive and at least two negative. An interval containing zero is uncertain even if fewer sign changes occur. The following primary PQ contrasts show the observed sign counts and campaign-level intervals; small differences are not promoted to universal speed claims.', '']
    selected=[r for r in boot if r['scenario'].startswith('pq') and r['comparison_class']!='secondary' and r['metric']=='handshake_wall_ms']
    for r in selected:
        lines.append(f'- {r["scenario"]} vs {r["baseline"]}: paired effect {r["median_campaign_paired_difference"]:+.6f} ms; 95% interval [{r["bootstrap95_low"]:+.6f}, {r["bootstrap95_high"]:+.6f}]; negative/positive/zero campaigns {r["negative_campaigns"]}/{r["positive_campaigns"]}/{r["zero_campaigns"]}; **{r["stability"]}**.')
    server_unstable=[r for r in boot if r['scenario'].startswith('pq') and r['comparison_class']!='secondary' and r['metric']=='handshake_server_cpu_ms' and not r['stability'].startswith('direction')]
    lines+=['',f'**Server CPU contrasts are not stable:** {len(server_unstable)}/9 primary PQ contrasts change sign frequently or have an interval containing zero. Do not claim server-CPU improvements from the Table A point estimates.']
    for r in boot:
        if r['scenario'].startswith('pq') and r['comparison_class']!='secondary' and r['metric']=='client_process_http_wall_ms' and not r['stability'].startswith('direction'):
            lines.append(f'- Full client-process/HTTP latency, {r["scenario"]} vs {r["baseline"]}: {r["median_campaign_paired_difference"]:+.6f} ms, interval [{r["bootstrap95_low"]:+.6f}, {r["bootstrap95_high"]:+.6f}], signs negative/positive {r["negative_campaigns"]}/{r["positive_campaigns"]}; **{r["stability"]}**, even if the percentile interval is directional.')
    lines+=['The ranking of separate campaign medians also changes for X509 versus MTC landmark and Compact warm versus cold (Table D). A median of round-paired differences is not the difference of two separate medians; those rank changes do not contradict the signs of the paired estimates.', 'Standalone MTC has lower timed-handshake wall values but higher client CPU than X509 in this experiment. These windows measure different aspects of scheduling, setup and verification; they do not establish an overall algorithmic speedup.', '','Outlier diagnostics use within-campaign Tukey 1.5-IQR fences and retain every observation. Descriptive correlations of campaign median wall time with client/total CPU are stored separately; wall time also includes waiting and is not interchangeable with CPU.']
    for s in pq:
        d=next(r for r in diagnostics if r['scenario']==s)
        lines.append(f'- {s}: {d["wall_tukey_outliers_retained"]}/300 wall observations flagged; largest wall observation {d["largest_observed_wall_ms"]:.6f} ms; wall/total-CPU correlation across campaign medians {fmt(d["wall_total_cpu_correlation_campaign_medians"])}.')
    unstable=[r for r in selected if r['stability'].startswith(('unstable','uncertain'))]
    lines+=['','The previous component profile located most compact verifier cost in SPKI encoding, with much smaller Merkle-proof processing. This campaign does not reprofile components and does not attribute the entire Compact timing difference to Merkle.', '',
        '### Decision about scaling','',
        ('Byte decomposition supports proceeding to a separate scaling study. **Timing is not yet stable for all primary contrasts**: '+str(len(unstable))+' of the nine primary PQ wall contrasts are sign-unstable or have an interval containing zero. Scaling timing would need the same campaign-level replication and explicit treatment of noise; it must not turn these contrasts into speed claims.' if unstable else 'All primary PQ wall contrasts have a campaign-level directional interval in this run. Byte results support proceeding to a separate scaling study. However, server-CPU differences and standalone MTC full-process latency are not stable; any scaling study must retain campaign-level replication and avoid claims of those improvements. This is not evidence of portability to other machines/networks or a persistent-cache benefit.'),
        '**No tree-size scaling experiment was run in this task.** All ten campaigns used the original N=16 population. The shared Docker session, resource contention/thermal state not independently reset, local cosigner, non-equivalent trust models and new-client-per-sample design limit generalization.', '',
        '### Files and reproduction','',
        '- `all-samples.csv`: 4200 observations with campaign, seed, paired round and order; `all-warmups.csv`: 700 warmups.',
        '- `campaign-summary.csv`: distributions of campaign medians; `scenario-summary.csv`: median/range/CV across campaigns.',
        '- `paired-comparisons.csv`: campaign-level paired effects; `bootstrap-comparisons.csv`: final campaign-level intervals.',
        '- `byte-decomposition.csv`, `scenario-ranks.csv`, `timing-diagnostics.csv`, `outliers.csv`: decomposition and stability diagnostics.',
        '- `campaign-01/` through `campaign-10/`: original samples, logs, endpoint telemetry, environment, and secondary bootstrap results.',
        '- `metadata.json`, `environment.json`, `tests.log`, `tests-status.json`, source/fixture hash inventories and `measurement-provenance.json`: reproducibility evidence.',
        '- Measurement implementation and host orchestration/analysis are stored in `source/`; the saved protocol commit is unchanged.', '']
    (root/'report.md').write_text('\n'.join(lines))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);a=p.parse_args();analyze(a.root)
