"""Campaign-level bandwidth analysis with analytical serialization kept separate."""
import csv,json,math,random,statistics as st,sys
from pathlib import Path
RTTS=[10,50,100];RATES=[100,20,10,5,1]
SCENARIOS=['pq','pq-rpk','pq-compact-warm','pq-compact-cold','pq-mtc-experimental-landmark','pq-mtc-experimental-standalone']
PAIRS=[('pq-compact-warm','pq'),('pq-mtc-experimental-landmark','pq'),('pq-compact-warm','pq-mtc-experimental-landmark'),('pq-compact-cold','pq'),('pq-mtc-experimental-standalone','pq'),('pq-compact-cold','pq-mtc-experimental-standalone')]
TIMING=['handshake_wall_ms','handshake_client_cpu_ms','handshake_server_cpu_ms','handshake_total_cpu_ms','client_process_http_wall_ms']
EXTRA=['transport_total_bytes','setup_wall_ms','setup_cpu_ms','trust_validation_ms','predistributed_incremental_bytes']
def read(p):
    with p.open() as f:return list(csv.DictReader(f))
def write(p,rows):
    if not rows:return
    fields=list(dict.fromkeys(k for r in rows for k in r))
    with p.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
def val(r,k):return float(r[k]) if r.get(k) not in ['',None] else None
def q(v,p):
    v=sorted(v);i=(len(v)-1)*p;a=math.floor(i);b=math.ceil(i);return v[a]+(v[b]-v[a])*(i-a)
def boot(v):
    rng=random.Random(20260910);x=[st.median(rng.choices(v,k=5)) for _ in range(10000)];return q(x,.025),q(x,.975)
def fit(rows,scenario):
    selected=[r for r in rows if r['scenario']==scenario];x=[[1,float(r['rtt_measured_ms']),1/float(r['bandwidth_measured_mbps'])] for r in selected];y=[float(r['handshake_wall_ms_median']) for r in selected]
    # Transparent three-parameter least squares, solved without external dependencies.
    a=[[sum(u[i]*u[j] for u in x) for j in range(3)]+[sum(u[i]*v for u,v in zip(x,y))] for i in range(3)]
    for i in range(3):
        pivot=max(range(i,3),key=lambda k:abs(a[k][i]));a[i],a[pivot]=a[pivot],a[i];d=a[i][i];a[i]=[v/d for v in a[i]]
        for k in range(3):
            if k!=i:
                d=a[k][i];a[k]=[u-d*v for u,v in zip(a[k],a[i])]
    beta=[a[i][3] for i in range(3)];res=[v-sum(b*u for b,u in zip(beta,row)) for row,v in zip(x,y)];mean=st.mean(y);ss=sum((v-mean)**2 for v in y)
    return {'scenario':scenario,'intercept_ms':beta[0],'rtt_coefficient_ms_per_ms':beta[1],'inverse_bandwidth_coefficient_ms_mbps':beta[2],'r_squared':1-sum(v*v for v in res)/ss if ss else None,'residual_min_ms':min(res),'residual_max_ms':max(res),'residuals':json.dumps(res),'interpretation':'descriptive T=a+b1*measured_RTT+b2*(1/measured_Mbps); 1/BW represents serialization scaling, not causal decomposition'}
def main(root):
    status=json.loads((root/'campaign-status.json').read_text());assert status['passed'] and len(status['campaigns'])==75 and not status['failed_campaign'];assert not (root/'all-samples.csv').exists()
    samples=[];warmups=[];campaign=[];paired=[];network=[];outliers=[];qconfig=[];qstats=[]
    for rec in status['campaigns']:
        d=root/'campaigns'/rec['campaign_id'];rows=read(d/'samples.csv');warm=read(d/'warmups.csv');assert len(rows)==180 and len(warm)==30;samples+=rows;warmups+=warm
        network.append({k:rec[k] for k in ['campaign_id','rtt_target_ms','bandwidth_target_mbps','measured_rtt_min_ms','measured_rtt_median_ms','measured_rtt_max_ms','bandwidth_forward_mbps','bandwidth_reverse_mbps','bandwidth_measured_mbps','ping_loss_percent','iperf_retransmits_forward','iperf_retransmits_reverse','qdisc_drops']})
        qconfig.append(f'## {rec["campaign_id"]}\n{(d/"server-qdisc-before.txt").read_text()}\n{(d/"network-validation.log").read_text()}');qstats.append(f'## {rec["campaign_id"]}\nserver:\n{(d/"server-qdisc-after.txt").read_text()}\nclient:\n{(d/"client-qdisc-after.txt").read_text()}')
        for scenario in SCENARIOS:
            group=[r for r in rows if r['scenario']==scenario];s={'rtt_target_ms':rec['rtt_target_ms'],'rtt_measured_ms':rec['measured_rtt_median_ms'],'bandwidth_target_mbps':rec['bandwidth_target_mbps'],'bandwidth_measured_mbps':rec['bandwidth_measured_mbps'],'campaign_id':rec['campaign_id'],'seed':rec['seed'],'scenario':scenario,'n':30}
            for metric in TIMING+EXTRA:
                v=[val(r,metric) for r in group if val(r,metric) is not None];s[metric+'_median']=st.median(v) if v else None;s[metric+'_min']=min(v) if v else None;s[metric+'_max']=max(v) if v else None
                if metric in TIMING:
                    lo=q(v,.25)-1.5*(q(v,.75)-q(v,.25));hi=q(v,.75)+1.5*(q(v,.75)-q(v,.25));outliers += [{'campaign_id':rec['campaign_id'],'rtt_target_ms':rec['rtt_target_ms'],'bandwidth_target_mbps':rec['bandwidth_target_mbps'],'scenario':scenario,'round_id':r['round_id'],'metric':metric,'value':val(r,metric),'lower_fence':lo,'upper_fence':hi,'retained':True} for r in group if val(r,metric)<lo or val(r,metric)>hi]
            campaign.append(s)
        for left,right in PAIRS:
            for metric in TIMING+['transport_total_bytes']:
                x={int(r['round_id']):val(r,metric) for r in rows if r['scenario']==left};y={int(r['round_id']):val(r,metric) for r in rows if r['scenario']==right};assert set(x)==set(y)
                paired.append({'rtt_target_ms':rec['rtt_target_ms'],'rtt_measured_ms':rec['measured_rtt_median_ms'],'bandwidth_target_mbps':rec['bandwidth_target_mbps'],'bandwidth_measured_mbps':rec['bandwidth_measured_mbps'],'campaign_id':rec['campaign_id'],'scenario':left,'baseline':right,'metric':metric,'paired_median_difference':st.median(x[k]-y[k] for k in x)})
    for name,rows in [('all-samples.csv',samples),('all-warmups.csv',warmups),('campaign-summary.csv',campaign),('paired-comparisons.csv',paired),('network-validation.csv',network),('outliers.csv',outliers)]:write(root/name,rows)
    (root/'qdisc-config.txt').write_text('\n\n'.join(qconfig)+'\n');(root/'qdisc-statistics.txt').write_text('\n\n'.join(qstats)+'\n')
    summary=[];effects=[]
    for rtt in RTTS:
        for rate in RATES:
            for scenario in SCENARIOS:
                group=[r for r in campaign if r['rtt_target_ms']==rtt and r['bandwidth_target_mbps']==rate and r['scenario']==scenario];assert len(group)==5
                row={'rtt_target_ms':rtt,'rtt_measured_ms':st.median(r['rtt_measured_ms'] for r in group),'bandwidth_target_mbps':rate,'bandwidth_measured_mbps':st.median(r['bandwidth_measured_mbps'] for r in group),'scenario':scenario,'campaigns':5}
                for metric in TIMING+EXTRA:
                    values=[r[metric+'_median'] for r in group if r[metric+'_median'] is not None];row[metric+'_median']=st.median(values) if values else None;row[metric+'_campaign_min']=min(values) if values else None;row[metric+'_campaign_max']=max(values) if values else None
                row['theoretical_serialization_ms']=row['transport_total_bytes_median']*8/(row['bandwidth_measured_mbps']*1000);summary.append(row)
            for left,right in PAIRS:
                for metric in TIMING+['transport_total_bytes']:
                    group=[r for r in paired if r['rtt_target_ms']==rtt and r['bandwidth_target_mbps']==rate and r['scenario']==left and r['baseline']==right and r['metric']==metric];values=[r['paired_median_difference'] for r in group];assert len(values)==5;lo,hi=boot(values) if metric!='transport_total_bytes' else (None,None)
                    effects.append({'rtt_target_ms':rtt,'bandwidth_target_mbps':rate,'scenario':left,'baseline':right,'metric':metric,'median_campaign_effect':st.median(values),'campaign_min':min(values),'campaign_max':max(values),'bootstrap95_low':lo,'bootstrap95_high':hi,'negative_campaigns':sum(v<0 for v in values),'positive_campaigns':sum(v>0 for v in values),'stability':'uncertain' if lo is not None and lo<=0<=hi else 'direction supported','resamples':10000 if lo is not None else 0})
    write(root/'bandwidth-summary.csv',summary);write(root/'bootstrap-comparisons.csv',effects)
    serialization=[]
    for row in summary:serialization.append({'rtt_target_ms':row['rtt_target_ms'],'bandwidth_target_mbps':row['bandwidth_target_mbps'],'bandwidth_measured_mbps':row['bandwidth_measured_mbps'],'scenario':row['scenario'],'tls_bytes':row['transport_total_bytes_median'],'theoretical_serialization_ms':row['theoretical_serialization_ms'],'measured_handshake_wall_ms':row['handshake_wall_ms_median'],'analytical_only':True})
    write(root/'serialization-reference.csv',serialization)
    breaks=[]
    for rtt in RTTS:
        for scenario in ['pq-compact-warm','pq-mtc-experimental-landmark']:
            points=[]
            for rate in RATES:
                e=next(r for r in effects if r['rtt_target_ms']==rtt and r['bandwidth_target_mbps']==rate and r['scenario']==scenario and r['baseline']=='pq' and r['metric']=='handshake_wall_ms');points.append((rate,e['median_campaign_effect'],e['bootstrap95_low'],e['bootstrap95_high']))
            faster=[x for x in points if x[1]<0];cross=[]
            ordered=sorted(points)
            for a,b in zip(ordered,ordered[1:]):
                if a[1]*b[1]<0:cross.append(f'{a[0]}-{b[0]} Mbps')
            breaks.append({'rtt_target_ms':rtt,'scenario':scenario,'observed_faster_bandwidths_mbps':json.dumps([x[0] for x in faster]),'observed_neighboring_crossover_intervals':json.dumps(cross),'exact_break_even_not_inferred':True,'all_points':json.dumps(points)})
    write(root/'break-even-analysis.csv',breaks)
    amort=[]
    for row in summary:
        if row['scenario'] not in ['pq-compact-warm','pq-mtc-experimental-landmark']:continue
        incremental=row['predistributed_incremental_bytes_median']
        for h in [1,10,100,1000,10000]:amort.append({'rtt_target_ms':row['rtt_target_ms'],'bandwidth_target_mbps':row['bandwidth_target_mbps'],'scenario':row['scenario'],'H':h,'tls_bytes':row['transport_total_bytes_median'],'incremental_predistributed_bytes':incremental,'effective_bytes':row['transport_total_bytes_median']+incremental/h,'analytical_only_not_measured_distribution':True})
    write(root/'amortization.csv',amort);models=[fit(summary,s) for s in SCENARIOS];write(root/'interaction-models.csv',models)
    report(root,summary,effects,network,breaks,models,outliers);(root/'analysis-status.json').write_text(json.dumps({'passed':True,'campaigns':75,'measured_handshakes':13500,'warmups':2250,'bootstrap_unit':'campaign at fixed RTT and bandwidth','resamples':10000,'all_outliers_retained':len(outliers)},indent=2)+'\n')
def report(root,summary,effects,network,breaks,models,outliers):
    def get(rtt,rate,s):return next(r for r in summary if r['rtt_target_ms']==rtt and r['bandwidth_target_mbps']==rate and r['scenario']==s)
    def eff(rtt,rate,s,b='pq'):return next(r for r in effects if r['rtt_target_ms']==rtt and r['bandwidth_target_mbps']==rate and r['scenario']==s and r['baseline']==b and r['metric']=='handshake_wall_ms')
    lines=['# Controlled bandwidth-limited TLS experiment','','Seventy-five campaigns: five per 3 RTT × 5 per-direction rate conditions. Each contains five warmup and thirty measured paired rounds over six PQ scenarios: 13,500 measured handshakes and 2,250 warmups. Smoke data are separate. This report is generated only after all throughput, RTT, retransmission and qdisc-drop gates pass.','','TBF rate is configured independently on client and server egress, with rate-dependent burst and a 1000 ms queue latency bound. A child netem adds RTT/2 deterministic delay in each direction. No loss or jitter option is configured. Validation uses twenty pings and four-second forward/reverse iperf3 runs before each campaign. Both throughput directions must be within ±15%; any retransmit or qdisc drop invalidates and stops the campaign.','','| RTT | rate | measured Mbps | X.509 wall ms | Compact warm wall ms | MTC landmark wall ms | Compact−X.509 paired ms | MTC−X.509 paired ms |','|---:|---:|---:|---:|---:|---:|---:|---:|']
    for rtt in RTTS:
        for rate in RATES:
            x=get(rtt,rate,'pq');c=get(rtt,rate,'pq-compact-warm');m=get(rtt,rate,'pq-mtc-experimental-landmark');ce=eff(rtt,rate,'pq-compact-warm');me=eff(rtt,rate,'pq-mtc-experimental-landmark');lines.append(f'| {rtt} | {rate} | {x["bandwidth_measured_mbps"]:.3f} | {x["handshake_wall_ms_median"]:.3f} | {c["handshake_wall_ms_median"]:.3f} | {m["handshake_wall_ms_median"]:.3f} | {ce["median_campaign_effect"]:.3f} [{ce["bootstrap95_low"]:.3f}, {ce["bootstrap95_high"]:.3f}] | {me["median_campaign_effect"]:.3f} [{me["bootstrap95_low"]:.3f}, {me["bootstrap95_high"]:.3f}] |')
    lines += ['','## Break-even observations','']
    for row in breaks:lines.append(f'- RTT {row["rtt_target_ms"]} ms, {row["scenario"]}: observed faster points {row["observed_faster_bandwidths_mbps"]}; neighboring sign-change intervals {row["observed_neighboring_crossover_intervals"]}. No exact break-even is inferred.')
    lines += ['','## Descriptive RTT + inverse-bandwidth models','','The `1/BW` term is used because simple serialization delay is proportional to bytes divided by rate. These fits are descriptive diagnostics, not causal decompositions.','','| scenario | RTT coefficient | 1/BW coefficient | R² | residual range ms |','|---|---:|---:|---:|---:|']
    for r in models:lines.append(f'| {r["scenario"]} | {r["rtt_coefficient_ms_per_ms"]:.5f} | {r["inverse_bandwidth_coefficient_ms_mbps"]:.3f} | {r["r_squared"]:.5f} | {r["residual_min_ms"]:.3f}…{r["residual_max_ms"]:.3f} |')
    max_rtt=max(abs(float(r['measured_rtt_median_ms'])-float(r['rtt_target_ms'])) for r in network);max_bw=max(max(abs(float(r[k])-float(r['bandwidth_target_mbps']))/float(r['bandwidth_target_mbps']) for k in ['bandwidth_forward_mbps','bandwidth_reverse_mbps']) for r in network)*100
    lines += ['','## Interpretation','','Theoretical serialization values are retained separately in serialization-reference.csv. They are not equated with measured handshake time: TLS flights, framing, TCP segmentation, queueing and process scheduling remain. The measured-difference versus theoretical-difference plot is diagnostic only.','','Warm Compact and MTC landmark move trust material out of the handshake. amortization.csv reports TLS bytes + incremental predistributed bytes/H for H=1,10,100,1000,10000. It is an analytical byte model, excludes a distribution protocol and persistent-cache behavior, and is never mixed into measured wall time.','','Cold Compact and standalone MTC transmit more authentication material. Their comparison remains architectural; standalone MTC includes CA/cosigner semantics absent from Compact cold and ordinary X.509. Local setup CPU, client CPU, server CPU and total CPU remain separate from serialization.','','Validation summary: maximum RTT target error '+f'{max_rtt:.3f} ms; maximum directional throughput error {max_bw:.2f}%; zero accepted ping loss, iperf retransmissions and qdisc drops. '+f'All {len(outliers)} Tukey diagnostic rows are retained. Five campaigns per condition and one Docker host limit generalization.','','Machine-readable outputs include bandwidth-summary.csv, bootstrap-comparisons.csv, serialization-reference.csv, break-even-analysis.csv, amortization.csv, interaction-models.csv and network-validation.csv. Plots are under plots/.','','Experiment commit: PENDING_COMMIT']
    (root/'report.md').write_text('\n'.join(lines)+'\n')
if __name__=='__main__':main(Path(sys.argv[1]))
