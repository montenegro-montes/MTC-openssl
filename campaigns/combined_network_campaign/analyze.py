"""Failure-aware summaries; campaigns, rather than handshakes, are bootstrap units."""
import argparse,csv,json,math,random,statistics as st
from pathlib import Path
from config import PAIRS,PROFILES,SCENARIOS
TIMING=['handshake_wall_ms','handshake_client_cpu_ms','handshake_server_cpu_ms','handshake_total_cpu_ms']
METRICS=TIMING+['transport_total_bytes','setup_wall_ms','setup_cpu_ms','trust_validation_ms','predistributed_bytes']
FAILURE_FIELDS=['experiment','network_profile','configured_loss_percent','campaign_id','round_id','seed','scenario','order_in_round','is_warmup','success','failure_reason','timeout','TLS_error','returncode']
def read(p):
 with p.open() as f:return list(csv.DictReader(f))
def write(p,data,fields=None):
 if not data and fields is None:return
 fields=fields or list(dict.fromkeys(k for r in data for k in r))
 with p.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(data)
def value(r,k):return float(r[k]) if r.get(k) not in ('',None) else None
def quantile(v,p):
 v=sorted(v);x=(len(v)-1)*p;a=math.floor(x);b=math.ceil(x);return v[a]+(v[b]-v[a])*(x-a)
def bootstrap(v):
 rng=random.Random(20260910);samples=[st.median(rng.choices(v,k=len(v))) for _ in range(10000)];return quantile(samples,.025),quantile(samples,.975)
def optional_isolated(out, paths):
 rows=[]
 for kind,path in paths:
  if not path:continue
  for r in read(path):rows.append({'isolated_experiment':kind,'source_file':str(path),'source_condition':json.dumps(r,sort_keys=True),'use':'descriptive comparison only; effects are never added or composed'})
 write(out/'isolated-comparison.csv',rows)
def main(a):
 root=a.root;status=json.loads((root/'campaign-status.json').read_text());assert status['passed'] and len(status['campaigns'])==20
 samples=[];warmups=[];failures=[];campaign=[];paired=[];network=[];tcp=[]
 for rec in status['campaigns']:
  d=root/'campaigns'/rec['campaign_id'];good=read(d/'samples.csv');warm=read(d/'warmups.csv');bad=read(d/'failures.csv');assert len(good)+sum(r['is_warmup']=='0' for r in bad)==180;assert len(warm)+sum(r['is_warmup']=='1' for r in bad)==30;samples+=good;warmups+=warm;failures+=bad
  validation=json.loads((d/'validation.json').read_text());network.append({'campaign_id':rec['campaign_id'],**validation});tcp.append({'campaign_id':rec['campaign_id'],'profile':rec['profile'],**json.loads((d/'tcp-counters.json').read_text())})
  for scenario in SCENARIOS:
   group=[r for r in good if r['scenario']==scenario];failed=[r for r in bad if r['is_warmup']=='0' and r['scenario']==scenario];row={'profile':rec['profile'],'campaign_id':rec['campaign_id'],'scenario':scenario,'successful_handshakes':len(group),'failed_handshakes':len(failed),'failure_rate':len(failed)/30}
   for metric in METRICS:
    vals=[value(r,metric) for r in group if value(r,metric) is not None];row[metric+'_median']=st.median(vals) if vals else None;row[metric+'_min']=min(vals) if vals else None;row[metric+'_max']=max(vals) if vals else None
   campaign.append(row)
  for left,right in PAIRS:
   for metric in TIMING+['transport_total_bytes']:
    x={r['round_id']:value(r,metric) for r in good if r['scenario']==left};y={r['round_id']:value(r,metric) for r in good if r['scenario']==right};common=set(x)&set(y);paired.append({'profile':rec['profile'],'campaign_id':rec['campaign_id'],'scenario':left,'baseline':right,'metric':metric,'paired_successful_rounds':len(common),'paired_median_difference':st.median(x[k]-y[k] for k in common) if common else None})
 for name,data in [('all-samples.csv',samples),('all-warmups.csv',warmups),('campaign-summary.csv',campaign),('paired-comparisons.csv',paired),('network-telemetry.csv',network),('campaign-tcp-counters.csv',tcp)]:write(root/name,data)
 write(root/'failures.csv',failures,FAILURE_FIELDS)
 summary=[];effects=[]
 for profile in PROFILES:
  for scenario in SCENARIOS:
   group=[r for r in campaign if r['profile']==profile and r['scenario']==scenario];assert len(group)==5;row={'profile':profile,**PROFILES[profile],'scenario':scenario,'campaigns':5,'successful_handshakes':sum(r['successful_handshakes'] for r in group),'failed_handshakes':sum(r['failed_handshakes'] for r in group),'failure_rate':sum(r['failed_handshakes'] for r in group)/150}
   for metric in METRICS:
    vals=[r[metric+'_median'] for r in group if r[metric+'_median'] is not None];row[metric+'_median_of_campaign_medians']=st.median(vals) if vals else None
   summary.append(row)
  for left,right in PAIRS:
   for metric in TIMING+['transport_total_bytes']:
    group=[r for r in paired if r['profile']==profile and r['scenario']==left and r['baseline']==right and r['metric']==metric];vals=[r['paired_median_difference'] for r in group if r['paired_median_difference'] is not None];lo,hi=bootstrap(vals) if vals and metric!='transport_total_bytes' else (None,None);effects.append({'profile':profile,'scenario':left,'baseline':right,'metric':metric,'campaign_effects_available':len(vals),'paired_rounds_total':sum(r['paired_successful_rounds'] for r in group),'median_campaign_effect':st.median(vals) if vals else None,'bootstrap95_low':lo,'bootstrap95_high':hi,'resamples':10000 if lo is not None else 0})
 write(root/'scenario-summary.csv',summary);write(root/'paired-table.csv',effects);main_rows=[r for r in summary if r['scenario'] in ['pq','pq-compact-warm','pq-mtc-experimental-landmark']];write(root/'main-table.csv',main_rows);optional_isolated(root,[('latency',a.isolated_latency),('bandwidth',a.isolated_bandwidth),('packet-loss',a.isolated_loss)])
 report=['# Representative combined-network TLS experiment','','Results cover controlled Docker profiles and are not estimates of every real network. RTT, bandwidth and loss effects interact; isolated-experiment effects must never be summed. MTC remains `MTC-experimental` targeting `draft-ietf-plants-merkle-tree-certs-05`.','','Primary results: `main-table.csv`. All scenarios: `scenario-summary.csv`. Paired common-success-round effects and 10,000-resample campaign bootstrap intervals: `paired-table.csv`. Failures remain in `failures.csv`. TCP retransmissions are campaign-level only and are not attributed to individual TLS connections. TLS BIO bytes are not wire bytes.','','Experiment commit: PENDING_COMMIT'];(root/'report.md').write_text('\n'.join(report)+'\n');save={'passed':True,'measured_attempts':3600,'warmup_attempts':600,'successful_measured':len(samples),'failed_measured':sum(r['is_warmup']=='0' for r in failures),'bootstrap_unit':'campaign','resamples':10000,'isolated_effects_summed':False};(root/'analysis-status.json').write_text(json.dumps(save,indent=2)+'\n')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('--isolated-latency',type=Path);p.add_argument('--isolated-bandwidth',type=Path);p.add_argument('--isolated-loss',type=Path);main(p.parse_args())
