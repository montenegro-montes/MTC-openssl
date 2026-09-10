"""Failure-aware campaign analysis; bootstrap unit is the campaign."""
import csv,json,math,random,statistics as st,sys
from pathlib import Path
from config import LOSSES,SCENARIOS,PAIRS
TIMING=['handshake_wall_ms','handshake_client_cpu_ms','handshake_server_cpu_ms','handshake_total_cpu_ms','client_process_http_wall_ms']
EXTRA=['transport_total_bytes','setup_wall_ms','setup_cpu_ms','trust_validation_ms','predistributed_bytes']
def read(path):
    with path.open() as f:return list(csv.DictReader(f))
def write(path,rows):
    if not rows:return
    fields=list(dict.fromkeys(k for r in rows for k in r))
    with path.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
def val(row,key):return float(row[key]) if row.get(key) not in ['',None] else None
def q(values,p):
    values=sorted(values);x=(len(values)-1)*p;a=math.floor(x);b=math.ceil(x);return values[a]+(values[b]-values[a])*(x-a)
def bootstrap(values):
    rng=random.Random(20260910);samples=[st.median(rng.choices(values,k=len(values))) for _ in range(10000)];return q(samples,.025),q(samples,.975)
def main(root):
    status=json.loads((root/'campaign-status.json').read_text());assert status['passed'] and len(status['campaigns'])==30 and not status['failed_campaign'];assert not (root/'all-samples.csv').exists()
    samples=[];warmups=[];failures=[];campaign=[];paired=[];network=[];retrans=[];outliers=[];qconfig=[];qstats=[]
    for rec in status['campaigns']:
        d=root/'campaigns'/rec['campaign_id'];good=read(d/'samples.csv') if (d/'samples.csv').exists() else [];warm=read(d/'warmups.csv') if (d/'warmups.csv').exists() else [];bad=read(d/'failures.csv');measured_bad=[r for r in bad if r['is_warmup']=='0'];warm_bad=[r for r in bad if r['is_warmup']=='1'];assert len(good)+len(measured_bad)==180 and len(warm)+len(warm_bad)==30
        samples+=good;warmups+=warm;failures+=bad;validation=json.loads((d/'validation.json').read_text());network.append({k:validation[k] for k in ['configured_rtt_ms','measured_rtt_min_ms','measured_rtt_median_ms','measured_rtt_max_ms','loss_target_percent','loss_measured_percent','probe_packets_sent','probe_packets_received','client_qdisc','server_qdisc','unexpected_bandwidth_limiter','qdisc_dropped_packets']}|{'campaign_id':rec['campaign_id']})
        tcp=json.loads((d/'tcp-counters.json').read_text())
        for side,data in tcp.items():retrans.append({'loss_target_percent':rec['loss_target_percent'],'campaign_id':rec['campaign_id'],'side':side,**data})
        qconfig.append(f'## {rec["campaign_id"]}\n{(d/"server-qdisc-before.txt").read_text()}\n{(d/"network-validation.log").read_text()}');qstats.append(f'## {rec["campaign_id"]}\nserver:\n{(d/"server-qdisc-after.txt").read_text()}\nclient:\n{(d/"client-qdisc-after.txt").read_text()}')
        for scenario in SCENARIOS:
            group=[r for r in good if r['scenario']==scenario];failed=[r for r in measured_bad if r['scenario']==scenario];assert len(group)+len(failed)==30;s={'loss_target_percent':rec['loss_target_percent'],'loss_measured_percent':rec['loss_measured_percent'],'campaign_id':rec['campaign_id'],'seed':rec['seed'],'scenario':scenario,'successful_handshakes':len(group),'failed_handshakes':len(failed),'failure_rate':len(failed)/30}
            for metric in TIMING+EXTRA:
                values=[val(r,metric) for r in group if val(r,metric) is not None];s[metric+'_median']=st.median(values) if values else None;s[metric+'_min']=min(values) if values else None;s[metric+'_max']=max(values) if values else None
                if metric in TIMING and len(values)>=4:
                    lo=q(values,.25)-1.5*(q(values,.75)-q(values,.25));hi=q(values,.75)+1.5*(q(values,.75)-q(values,.25));outliers += [{'loss_target_percent':rec['loss_target_percent'],'campaign_id':rec['campaign_id'],'scenario':scenario,'round_id':r['round_id'],'metric':metric,'value':val(r,metric),'lower_fence':lo,'upper_fence':hi,'retained':True} for r in group if val(r,metric)<lo or val(r,metric)>hi]
            campaign.append(s)
        for left,right in PAIRS:
            for metric in TIMING+['transport_total_bytes']:
                x={int(r['round_id']):val(r,metric) for r in good if r['scenario']==left};y={int(r['round_id']):val(r,metric) for r in good if r['scenario']==right};common=sorted(set(x)&set(y))
                paired.append({'loss_target_percent':rec['loss_target_percent'],'campaign_id':rec['campaign_id'],'scenario':left,'baseline':right,'metric':metric,'paired_successful_rounds':len(common),'paired_median_difference':st.median(x[k]-y[k] for k in common) if common else None})
    for name,rows in [('all-samples.csv',samples),('all-warmups.csv',warmups),('failures.csv',failures),('campaign-summary.csv',campaign),('paired-comparisons.csv',paired),('network-validation.csv',network),('retransmissions.csv',retrans),('outliers.csv',outliers)]:write(root/name,rows)
    (root/'qdisc-config.txt').write_text('\n\n'.join(qconfig)+'\n');(root/'qdisc-statistics.txt').write_text('\n\n'.join(qstats)+'\n')
    summary=[];effects=[]
    for loss in LOSSES:
        for scenario in SCENARIOS:
            group=[r for r in campaign if r['loss_target_percent']==loss and r['scenario']==scenario];assert len(group)==5;row={'loss_target_percent':loss,'scenario':scenario,'campaigns':5,'successful_handshakes':sum(r['successful_handshakes'] for r in group),'failed_handshakes':sum(r['failed_handshakes'] for r in group),'failure_rate':sum(r['failed_handshakes'] for r in group)/150}
            for metric in TIMING+EXTRA:
                values=[r[metric+'_median'] for r in group if r[metric+'_median'] is not None];row[metric+'_median_of_campaign_medians']=st.median(values) if values else None;row[metric+'_campaign_min']=min(values) if values else None;row[metric+'_campaign_max']=max(values) if values else None
            summary.append(row)
        for left,right in PAIRS:
            for metric in TIMING+['transport_total_bytes']:
                group=[r for r in paired if r['loss_target_percent']==loss and r['scenario']==left and r['baseline']==right and r['metric']==metric];values=[r['paired_median_difference'] for r in group if r['paired_median_difference'] is not None];lo,hi=bootstrap(values) if metric!='transport_total_bytes' and values else (None,None)
                effects.append({'loss_target_percent':loss,'scenario':left,'baseline':right,'metric':metric,'campaign_effects_available':len(values),'paired_rounds_total':sum(r['paired_successful_rounds'] for r in group),'median_campaign_effect':st.median(values) if values else None,'campaign_min':min(values) if values else None,'campaign_max':max(values) if values else None,'bootstrap95_low':lo,'bootstrap95_high':hi,'negative_campaigns':sum(v<0 for v in values),'positive_campaigns':sum(v>0 for v in values),'resamples':10000 if lo is not None else 0,'stability':'unavailable' if not values else ('uncertain' if lo is not None and lo<=0<=hi else 'direction supported')})
    write(root/'scenario-summary.csv',summary);write(root/'bootstrap-comparisons.csv',effects)
    report(root,summary,effects,retrans,network,outliers);(root/'analysis-status.json').write_text(json.dumps({'passed':True,'measured_attempts':5400,'warmup_attempts':900,'successful_measured':len(samples),'failed_measured':sum(r['is_warmup']=='0' for r in failures),'bootstrap_unit':'campaign','resamples':10000,'per_connection_retransmission_attribution':False,'all_outliers_retained':len(outliers)},indent=2)+'\n')
def report(root,summary,effects,retrans,network,outliers):
    lines=['# Controlled packet-loss TLS experiment','','Six symmetric per-egress netem loss settings at a fixed additional 50 ms RTT. Thirty campaigns contain 5,400 measured attempts plus 900 warmups. Successful-handshake latency and failure rate are reported together. Failed connections are retained in reliability accounting.','','Loss is independently applied to client and server egress; the target percentage is not an end-to-end connection loss probability. The qdisc value is authoritative, especially for 0.1% where finite probes may observe zero events. No bandwidth, jitter, reordering, duplication or corruption is configured.','','| Loss % | scenario | TLS bytes | wall median ms | client CPU ms | server CPU ms | total CPU ms | failures / 150 | failure rate |','|---:|---|---:|---:|---:|---:|---:|---:|---:|']
    for row in summary:
        def f(k):return 'NA' if row[k] is None else f'{row[k]:.3f}'
        lines.append(f'| {row["loss_target_percent"]} | {row["scenario"]} | {f("transport_total_bytes_median_of_campaign_medians")} | {f("handshake_wall_ms_median_of_campaign_medians")} | {f("handshake_client_cpu_ms_median_of_campaign_medians")} | {f("handshake_server_cpu_ms_median_of_campaign_medians")} | {f("handshake_total_cpu_ms_median_of_campaign_medians")} | {row["failed_handshakes"]} | {row["failure_rate"]:.4f} |')
    lines += ['','Primary paper table is available as `scenario-summary.csv`; filter scenarios `pq`, `pq-compact-warm`, and `pq-mtc-experimental-landmark`. Paired effects and campaign bootstrap intervals are in `bootstrap-comparisons.csv`. If loss prevents a paired round or an entire campaign effect, counts are explicit and unavailable values are not invented.','','TCP counters are campaign/container-namespace deltas. They include probes only where stated by the runner and cannot be attributed reliably to individual handshakes or scenarios. Retransmitted bytes are unavailable. Therefore the default figures include campaign retransmission counts versus configured loss, but do not generate handshake latency versus per-connection retransmissions. TLS BIO bytes are not wire bytes.','','Compact and MTC do not modify TCP. Any difference is associated with their transmitted authentication representation under this Docker/TCP configuration; it does not establish inherent packet-loss resilience. Credential size, TCP segments, random loss events, retransmission behavior, local processing and trust setup remain distinct. Compact/MTC comparisons are architectural and MTC standalone includes a local cosigner.','','All failures, timeouts and TLS errors are in `failures.csv`. All Tukey outliers remain included. No linear loss model is forced. Five campaigns per condition, finite low-loss probes, campaign-level retransmission attribution and one Docker host limit interpretation.','','Plots are under `plots/`. Network/qdisc evidence is in `network-validation.csv`, `qdisc-config.txt`, and `qdisc-statistics.txt`.','','Experiment commit: PENDING_COMMIT']
    (root/'report.md').write_text('\n'.join(lines)+'\n')
if __name__=='__main__':main(Path(sys.argv[1]))
