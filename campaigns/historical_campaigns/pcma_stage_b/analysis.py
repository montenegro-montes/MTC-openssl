"""Campaign-level paired inference and data-dependent publication outputs."""
import csv
import importlib.util
import json
from pathlib import Path
import random
import statistics as stats
from collections import defaultdict

from design import ROOT,digest,save
from audit import audit,read_rows

spec=importlib.util.spec_from_file_location('pcma_b_frozen_stats',ROOT/'campaigns/historical_campaigns/controlled_n16_campaign/analyze.py')
previous=importlib.util.module_from_spec(spec);spec.loader.exec_module(previous)
METRICS=['tls_total_bytes','handshake_total_bytes','server_authentication_bytes','clienthello_bytes',
         'advertisement_bytes','proof_bytes','net_authentication_bytes','net_authentication_saving',
         'wall_ms','cpu_ms','server_cpu_ms','encode_ms','server_advertisement_parse_ms','server_range_lookup_ms',
         'server_partial_construction_ms','cache_lookup_ms','reconstruction_ms','verification_ms','credential_verify_ms',
         'cache_nodes','cache_bytes','reused_hashes','transmitted_hashes']
IDENTITY=['N','workload','network_profile','scenario','cache_budget','cache_policy']

def csv_write(p,rows):
    if not rows:raise ValueError('no rows for table')
    fields=list(dict.fromkeys(k for row in rows for k in row))
    with p.open('x',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)

def bootstrap(values,count,seed):
    # Adapt the existing campaign bootstrap to configurable campaign counts.
    if len(values)<2:return None,None
    rng=random.Random(seed)
    medians=[stats.median(rng.choices(values,k=len(values))) for _ in range(count)]
    return previous.quantile(medians,.025),previous.quantile(medians,.975)

def compute(rows,config):
    measured=[r for r in rows if not int(r['is_warmup'])]
    campaigns=defaultdict(list)
    for r in measured:campaigns[(r['campaign_id'],)+tuple(r[k] for k in IDENTITY)].append(r)
    medians=[]
    for key,rs in campaigns.items():
        row=dict(zip(['campaign_id']+IDENTITY,key))
        for metric in METRICS:
            values=[float(r[metric]) for r in rs if r.get(metric) not in ('',None)]
            row[metric]=stats.median(values) if values else None
        medians.append(row)
    pooled=defaultdict(list)
    for row in medians:pooled[tuple(row[k] for k in IDENTITY)].append(row)
    summary=[]
    for key,rs in pooled.items():
        row=dict(zip(IDENTITY,key),campaigns=len(rs))
        for metric in METRICS:
            values=[r[metric] for r in rs if r[metric] is not None]
            row[metric]=stats.median(values) if values else None
        summary.append(row)
    references={(r['campaign_id'],r['sequence_position'],r['scenario']):r for r in measured if r['scenario'] in ('pq','pq-compact-warm')}
    effects=defaultdict(list)
    for (cid,*arm),rs in campaigns.items():
        if rs[0]['scenario']=='pq':continue
        baselines=['pq-compact-warm'] if rs[0]['scenario']=='pq-compact-pcma' else ['pq']
        for baseline in baselines:
            if (cid,rs[0]['sequence_position'],baseline) not in references:continue
            for metric in ('tls_total_bytes','handshake_total_bytes','server_authentication_bytes','wall_ms','cpu_ms','server_cpu_ms'):
                left={r['sequence_position']:float(r[metric]) for r in rs}
                right={r['sequence_position']:float(references[(cid,r['sequence_position'],baseline)][metric]) for r in rs}
                value=previous.paired_effect(left,right)
                effects[tuple(arm)+(baseline,metric)].append((cid,value))
    paired=[];campaign_effects=[]
    for key,values in effects.items():
        lows,highs=bootstrap([v for _,v in values],config['bootstrap_resamples'],config['bootstrap_seed'])
        row=dict(zip(IDENTITY+['baseline','metric'],key),campaigns=len(values),median_paired_difference=stats.median(v for _,v in values),ci95_low=lows,ci95_high=highs)
        paired.append(row)
        campaign_effects.extend(dict(zip(IDENTITY+['baseline','metric'],key),campaign_id=cid,paired_difference=v) for cid,v in values)
    return medians,summary,campaign_effects,paired

def analyze(directory,output):
    report=audit(directory)
    config=json.loads((directory/'manifest.json').read_text())['config']
    medians,summary,effects,paired=compute(read_rows(directory/'observations.csv'),config)
    output.mkdir(parents=True,exist_ok=False)
    for name,rows in [('campaign-medians',medians),('summary',summary),('campaign-paired-effects',effects),('paired-comparisons',paired)]:
        if rows:csv_write(output/(name+'.csv'),rows)
    outcomes=[]
    for row in paired:
        if row['scenario']!='pq-compact-pcma' or row['metric']!='wall_ms':continue
        byte=next(r for r in paired if all(r[k]==row[k] for k in IDENTITY+['baseline']) and r['metric']=='tls_total_bytes')
        if byte['median_paired_difference']>=0:outcome='D: record framing/state overhead removes communication advantage'
        elif row['ci95_low'] is None:outcome='UNRESOLVED: insufficient independent campaigns for timing CI'
        elif row['ci95_high']<0:outcome='A: bytes and latency reduced'
        elif row['ci95_low']>0:outcome='C: fewer bytes, increased latency; inspect component overhead'
        else:outcome='B: fewer bytes; timing interval includes zero (not proof of equivalence)'
        outcomes.append(dict(row,outcome=outcome))
    save(output/'analysis.json',dict(audit=report,outcomes=outcomes,unit='campaign',effect='median of access-paired differences within campaign, then median across campaigns',bootstrap_count=config['bootstrap_resamples'],bootstrap_seed=config['bootstrap_seed'],hashes={p.name:digest(p) for p in output.glob('*.csv')}))

def tables(directory,output):
    audit(directory);m=json.loads((directory/'manifest.json').read_text())
    _,summary,_,paired=compute(read_rows(directory/'observations.csv'),m['config'])
    output.mkdir(parents=True,exist_ok=False)
    for name,rows in [('primary',summary),('paired',paired)]:
        if not rows:continue
        csv_write(output/(name+'.csv'),rows)
        # Long-form fragments avoid an unreadably wide 30-column publication table.
        fields=IDENTITY+(['metric','median_paired_difference','ci95_low','ci95_high'] if name=='paired' else ['metric','value'])
        flat=rows if name=='paired' else [dict(r,metric=k,value=r[k]) for r in rows for k in METRICS if r[k] is not None]
        def esc(value):return str(value).replace('_',r'\_').replace('%',r'\%')
        text=[r'\begin{tabular}{'+'l'*len(fields)+'}', ' & '.join(map(esc,fields))+r' \\ \hline']
        for r in flat:text.append(' & '.join(esc(f'{r[k]:.6f}' if isinstance(r[k],float) else (r[k] if r[k] is not None else '--')) for k in fields)+r' \\')
        text.append(r'\end{tabular}')
        with (output/(name+'.tex')).open('x') as f:f.write('\n'.join(text)+'\n')
    save(output/'manifest.json',dict(source_sha256=digest(directory/'observations.csv'),hashes={p.name:digest(p) for p in output.iterdir()}))

def plots(directory,output):
    audit(directory)
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    data=read_rows(directory/'observations.csv');config=json.loads((directory/'manifest.json').read_text())['config']
    _,summary,_,_=compute(data,config)
    output.mkdir(parents=True,exist_ok=False)
    def emit(fig,name):fig.tight_layout();fig.savefig(output/(name+'.png'),dpi=180);fig.savefig(output/(name+'.pdf'));plt.close(fig)
    # Per-workload/profile comparison panels retain arms and budgets explicitly.
    for workload,profile in sorted({(r['workload'],r['network_profile']) for r in summary}):
        subset=[r for r in summary if (r['workload'],r['network_profile'])==(workload,profile)]
        for metric in ('tls_total_bytes','handshake_total_bytes','server_authentication_bytes','wall_ms','cpu_ms','server_cpu_ms','net_authentication_bytes'):
            fig,ax=plt.subplots(figsize=(8,5))
            for scenario,budget in sorted({(r['scenario'],r['cache_budget']) for r in subset}):
                points=sorted([r for r in subset if r['scenario']==scenario and r['cache_budget']==budget and r[metric] is not None],key=lambda r:int(r['N']))
                if points:ax.plot([int(r['N']) for r in points],[r[metric] for r in points],marker='o',label=f'{scenario} / {budget} B')
            ax.set(xlabel='N',ylabel=metric,title=f'{workload} / {profile}');ax.legend(fontsize=7);emit(fig,f'{metric}-{workload}-{profile}')
    grouped=defaultdict(list)
    for r in data:
        if r['scenario']=='pq-compact-pcma':grouped[(r['N'],r['workload'],r['network_profile'],r['cache_budget'])].append(r)
    for key,rows in grouped.items():
        for metric in ('net_authentication_saving','cache_bytes','cache_nodes','reused_hashes','transmitted_hashes','advertisement_bytes','proof_bytes'):
            series=defaultdict(list)
            for r in rows:series[int(r['sequence_position'])].append(float(r[metric]))
            fig,ax=plt.subplots(figsize=(8,5));positions=sorted(series);ax.plot(positions,[stats.median(series[t]) for t in positions])
            ax.set(xlabel='sequence position (including warmup)',ylabel=metric,title=' / '.join(key));emit(fig,metric+'-'+'-'.join(key))
        fig,ax=plt.subplots(figsize=(8,5));positions=sorted({int(r['sequence_position']) for r in rows})
        for metric in ('advertisement_bytes','proof_bytes'):
            ax.plot(positions,[stats.median(float(r[metric]) for r in rows if int(r['sequence_position'])==t) for t in positions],label=metric)
        ax.legend();ax.set(xlabel='sequence position',ylabel='serialized bytes',title=' / '.join(key));emit(fig,'decomposition-'+'-'.join(key))
    # Component overhead by arm for all workload/N/budget/network combinations.
    component=['encode_ms','server_advertisement_parse_ms','server_range_lookup_ms','server_partial_construction_ms','cache_lookup_ms','reconstruction_ms','verification_ms','credential_verify_ms']
    for r in summary:
        if r['scenario']!='pq-compact-pcma':continue
        fig,ax=plt.subplots(figsize=(10,5));ax.bar(component,[r[k] or 0 for k in component]);ax.tick_params(axis='x',rotation=65);ax.set(ylabel='diagnostic component milliseconds',title=' / '.join(r[k] for k in IDENTITY));emit(fig,'components-'+'-'.join(r[k] for k in IDENTITY))
    save(output/'manifest.json',dict(source_sha256=digest(directory/'observations.csv'),hashes={p.name:digest(p) for p in output.iterdir()}))
