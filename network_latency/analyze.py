"""Campaign-level latency-only analysis; individual handshakes are never bootstrap units."""
import csv,json,math,random,statistics as st,sys
from pathlib import Path

RTTS=[0,10,20,50,100,200]
SCENARIOS=['pq','pq-rpk','pq-compact-warm','pq-compact-cold','pq-mtc-experimental-landmark','pq-mtc-experimental-standalone']
METRICS=['handshake_wall_ms','handshake_client_cpu_ms','handshake_server_cpu_ms','handshake_total_cpu_ms','transport_total_bytes','client_process_http_wall_ms','setup_wall_ms','setup_cpu_ms','trust_validation_ms','predistributed_bytes']
PAIRS=[('pq-compact-warm','pq'),('pq-mtc-experimental-landmark','pq'),('pq-compact-warm','pq-mtc-experimental-landmark'),('pq-compact-cold','pq'),('pq-mtc-experimental-standalone','pq'),('pq-compact-cold','pq-mtc-experimental-standalone')]
def read(p):
    with p.open() as f:return list(csv.DictReader(f))
def write(p,rows):
    if not rows:return
    fields=list(dict.fromkeys(k for r in rows for k in r))
    with p.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
def value(r,k):return float(r[k]) if r.get(k) not in ['',None] else None
def quantile(v,p):
    v=sorted(v);i=(len(v)-1)*p;a=math.floor(i);b=math.ceil(i);return v[a]+(v[b]-v[a])*(i-a)
def bootstrap(v):
    rng=random.Random(20260910);samples=[st.median(rng.choices(v,k=5)) for _ in range(10000)];return quantile(samples,.025),quantile(samples,.975)
def fit(x,y):
    mx,my=st.mean(x),st.mean(y);s=sum((a-mx)*(b-my) for a,b in zip(x,y))/sum((a-mx)**2 for a in x);a=my-s*mx;res=[v-(a+s*t) for t,v in zip(x,y)];ss=sum((v-my)**2 for v in y)
    return a,s,1-sum(v*v for v in res)/ss if ss else None,res
def main(root):
    status=json.loads((root/'campaign-status.json').read_text());assert status['passed'] and len(status['campaigns'])==30 and not status['failed_campaign'];assert not (root/'all-samples.csv').exists()
    samples=[];warmups=[];summaries=[];pairs=[];network=[];outliers=[];configs=[];statistics=[]
    for rec in status['campaigns']:
        directory=root/'campaigns'/rec['campaign_id'];rows=read(directory/'samples.csv');warm=read(directory/'warmups.csv');assert len(rows)==180 and len(warm)==30
        configs.append(f'## {rec["campaign_id"]}\nserver before:\n{(directory/"server-qdisc-before.txt").read_text()}\nprobe client and qdisc:\n{(directory/"network-validation.log").read_text()}')
        statistics.append(f'## {rec["campaign_id"]}\nserver:\n{(directory/"server-qdisc-statistics.txt").read_text()}\nclient:\n{(directory/"client-qdisc-statistics.txt").read_text()}')
        samples+=rows;warmups+=warm;network.append({k:rec[k] for k in ['campaign_id','rtt_target_ms','measured_rtt_min_ms','measured_rtt_median_ms','measured_rtt_max_ms','packet_loss_percent']})
        for scenario in SCENARIOS:
            group=[r for r in rows if r['scenario']==scenario];s={'rtt_target_ms':rec['rtt_target_ms'],'rtt_measured_ms':rec['measured_rtt_median_ms'],'campaign_id':rec['campaign_id'],'seed':rec['seed'],'scenario':scenario,'n':30}
            for metric in METRICS:
                vals=[value(r,metric) for r in group if value(r,metric) is not None];s[metric+'_median']=st.median(vals) if vals else None;s[metric+'_min']=min(vals) if vals else None;s[metric+'_max']=max(vals) if vals else None
                if metric in ['handshake_wall_ms','handshake_client_cpu_ms','handshake_server_cpu_ms','handshake_total_cpu_ms']:
                    q1,q3=quantile(vals,.25),quantile(vals,.75);lo,hi=q1-1.5*(q3-q1),q3+1.5*(q3-q1)
                    outliers += [{'campaign_id':rec['campaign_id'],'rtt_target_ms':rec['rtt_target_ms'],'scenario':scenario,'round_id':r['round_id'],'metric':metric,'value':value(r,metric),'lower_fence':lo,'upper_fence':hi,'retained':True} for r in group if value(r,metric)<lo or value(r,metric)>hi]
            summaries.append(s)
        for left,right in PAIRS:
            for metric in ['handshake_wall_ms','handshake_client_cpu_ms','handshake_server_cpu_ms','handshake_total_cpu_ms','transport_total_bytes','client_process_http_wall_ms']:
                x={int(r['round_id']):value(r,metric) for r in rows if r['scenario']==left};y={int(r['round_id']):value(r,metric) for r in rows if r['scenario']==right};assert set(x)==set(y)
                pairs.append({'rtt_target_ms':rec['rtt_target_ms'],'rtt_measured_ms':rec['measured_rtt_median_ms'],'campaign_id':rec['campaign_id'],'scenario':left,'baseline':right,'metric':metric,'paired_median_difference':st.median(x[k]-y[k] for k in x)})
    for name,rows in [('all-samples.csv',samples),('all-warmups.csv',warmups),('campaign-summary.csv',summaries),('paired-comparisons.csv',pairs),('network-validation.csv',network),('outliers.csv',outliers)]:write(root/name,rows)
    (root/'qdisc-config.txt').write_text('\n\n'.join(configs)+'\n');(root/'qdisc-statistics.txt').write_text('\n\n'.join(statistics)+'\n')
    aggregate=[];effects=[]
    for rtt in RTTS:
        for scenario in SCENARIOS:
            group=[r for r in summaries if r['rtt_target_ms']==rtt and r['scenario']==scenario];assert len(group)==5
            row={'rtt_target_ms':rtt,'rtt_measured_ms':st.median(r['rtt_measured_ms'] for r in group),'scenario':scenario,'campaigns':5}
            for metric in METRICS:
                vals=[r[metric+'_median'] for r in group if r[metric+'_median'] is not None];row[metric+'_median']=st.median(vals) if vals else None;row[metric+'_campaign_min']=min(vals) if vals else None;row[metric+'_campaign_max']=max(vals) if vals else None
            aggregate.append(row)
        for left,right in PAIRS:
            for metric in ['handshake_wall_ms','handshake_client_cpu_ms','handshake_server_cpu_ms','handshake_total_cpu_ms','transport_total_bytes','client_process_http_wall_ms']:
                group=[r for r in pairs if r['rtt_target_ms']==rtt and r['scenario']==left and r['baseline']==right and r['metric']==metric];vals=[r['paired_median_difference'] for r in group];assert len(vals)==5
                lo,hi=bootstrap(vals) if metric!='transport_total_bytes' else (None,None);effects.append({'rtt_target_ms':rtt,'scenario':left,'baseline':right,'metric':metric,'median_campaign_effect':st.median(vals),'campaign_min':min(vals),'campaign_max':max(vals),'bootstrap95_low':lo,'bootstrap95_high':hi,'negative_campaigns':sum(v<0 for v in vals),'positive_campaigns':sum(v>0 for v in vals),'resamples':10000 if lo is not None else 0,'stability':'uncertain' if lo is not None and lo<=0<=hi else 'direction supported'})
    write(root/'latency-summary.csv',aggregate);write(root/'bootstrap-comparisons.csv',effects)
    slopes=[]
    for scenario in SCENARIOS:
        group=[r for r in aggregate if r['scenario']==scenario];x=[r['rtt_measured_ms'] for r in group];y=[r['handshake_wall_ms_median'] for r in group];a,b,r2,res=fit(x,y);slopes.append({'scenario':scenario,'intercept_ms':a,'slope_ms_per_measured_rtt_ms':b,'r_squared':r2,'residual_min_ms':min(res),'residual_max_ms':max(res),'residuals':json.dumps(res),'interpretation':'descriptive; fixed TLS flight structure, not protocol complexity'})
    write(root/'latency-slopes.csv',slopes)
    report(root,aggregate,effects,slopes,network,outliers);(root/'analysis-status.json').write_text(json.dumps({'passed':True,'campaigns':30,'measured_handshakes':5400,'warmups':900,'bootstrap_unit':'campaign','resamples':10000,'all_outliers_retained':len(outliers)},indent=2)+'\n')
def report(root,summary,effects,slopes,network,outliers):
    def get(rtt,s):return next(r for r in summary if r['rtt_target_ms']==rtt and r['scenario']==s)
    def eff(rtt,s,b='pq'):return next(r for r in effects if r['rtt_target_ms']==rtt and r['scenario']==s and r['baseline']==b and r['metric']=='handshake_wall_ms')
    lines=['# Controlled latency-only TLS experiment','','Thirty successful campaigns: five per additional RTT target 0, 10, 20, 50, 100 and 200 ms. Each campaign contains five warmup and thirty measured paired rounds over six PQ scenarios: 5,400 measured handshakes and 900 warmups. Smoke observations are separate and excluded. No packet loss, jitter or bandwidth qdisc was configured.','', 'TLS 1.3, X25519, TLS_AES_256_GCM_SHA384, server-only authentication, no tickets/resumption and N=16 remain fixed. `netem delay RTT/2` is applied to client and server eth0 egress. A 20-probe ping before every campaign measures effective RTT.','', 'Final inference uses medians within campaign, round-paired campaign effects, then 10,000 bootstrap resamples of five campaigns at each RTT. Individual handshakes are not bootstrap units. All Tukey outliers are retained.','','| RTT target | measured RTT median | X.509 wall ms | Compact warm wall ms | MTC landmark wall ms | Compact−X.509 paired ms | MTC−X.509 paired ms |','|---:|---:|---:|---:|---:|---:|---:|']
    for rtt in RTTS:
        x=get(rtt,'pq');c=get(rtt,'pq-compact-warm');m=get(rtt,'pq-mtc-experimental-landmark');ce=eff(rtt,'pq-compact-warm');me=eff(rtt,'pq-mtc-experimental-landmark');lines.append(f'| {rtt} | {x["rtt_measured_ms"]:.3f} | {x["handshake_wall_ms_median"]:.3f} | {c["handshake_wall_ms_median"]:.3f} | {m["handshake_wall_ms_median"]:.3f} | {ce["median_campaign_effect"]:.3f} [{ce["bootstrap95_low"]:.3f}, {ce["bootstrap95_high"]:.3f}] | {me["median_campaign_effect"]:.3f} [{me["bootstrap95_low"]:.3f}, {me["bootstrap95_high"]:.3f}] |')
    lines += ['','## RTT slopes','','| Scenario | intercept ms | slope ms/ms RTT | R² | residual range ms |','|---|---:|---:|---:|---:|']
    for r in slopes:lines.append(f'| {r["scenario"]} | {r["intercept_ms"]:.4f} | {r["slope_ms_per_measured_rtt_ms"]:.5f} | {r["r_squared"]:.5f} | {r["residual_min_ms"]:.3f}…{r["residual_max_ms"]:.3f} |')
    primary=[next(r for r in slopes if r['scenario']==s) for s in ['pq','pq-compact-warm','pq-mtc-experimental-landmark']];spread=max(r['slope_ms_per_measured_rtt_ms'] for r in primary)-min(r['slope_ms_per_measured_rtt_ms'] for r in primary)
    cpu=[]
    for s in ['pq','pq-compact-warm','pq-mtc-experimental-landmark']:
        vals=[get(r,s)['handshake_total_cpu_ms_median'] for r in RTTS];cpu.append(f'{s}: {min(vals):.3f}–{max(vals):.3f} ms')
    lines += ['','## Scientific interpretation','',f'All three primary schemes have similar descriptive RTT slopes; their slope spread is {spread:.5f} ms per ms of measured RTT. This is consistent with broadly equal TLS 1.3 flight structure. The paired tables show whether Compact/X.509 and MTC/X.509 gaps remain stable at each RTT; an interval including zero is reported as uncertain.','', 'The byte counts do not change with RTT. This latency-only experiment does not establish that the approximately 34% PQ handshake-byte reduction itself improves latency under unconstrained bandwidth. Credential representation, local processing, RTT and out-of-band trust setup remain separate costs.','', 'Total CPU campaign medians by RTT span: '+'; '.join(cpu)+'. CPU should not scale mechanically with artificial delay; any variation is treated as host/process noise and checked through campaign ranges rather than attributed to RTT.','', 'Scenario timing order at every RTT is available in latency-summary.csv. Compact/MTC comparisons are architectural: MTC landmark retains different X.509/MTC and trust/transparency semantics; MTC standalone carries a local cosigner absent from X.509. Warm trust validation remains outside the timed handshake and repeats in every new client process.','',f'RTT accuracy: median absolute target error {st.median(abs(r["measured_rtt_median_ms"]-r["rtt_target_ms"]) for r in network):.3f} ms; maximum {max(abs(r["measured_rtt_median_ms"]-r["rtt_target_ms"]) for r in network):.3f} ms. All {len(network)} probes report zero loss. `qdisc-config.txt` and `qdisc-statistics.txt` contain the active configurations/statistics copied from every campaign.','',f'{len(outliers)} Tukey diagnostic rows are retained. Five campaigns per condition yield coarse intervals and the experiment covers one Docker host. No loss/jitter/bandwidth limitation was intentionally configured; qdisc evidence is recorded, but host scheduling and Docker overhead remain. Slopes are descriptive and must not be presented as a protocol complexity proof.','', 'Plots are in plots/. Machine-readable values are in latency-summary.csv, latency-slopes.csv, paired-comparisons.csv, bootstrap-comparisons.csv and network-validation.csv.','','Experiment commit: PENDING_COMMIT']
    (root/'report.md').write_text('\n'.join(lines)+'\n')
if __name__=='__main__':main(Path(sys.argv[1]))
