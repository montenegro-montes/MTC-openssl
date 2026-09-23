"""Publication figures from saved CSVs only; no fitted timing curves or data edits."""
import csv,json,math,os,sys
from pathlib import Path
os.environ.setdefault('MPLCONFIGDIR','/tmp/mt-scaling-matplotlib')
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np
SIZES=[1,4,16,64,256,1024];X=[math.log2(n) for n in SIZES]
LABELS={'pq':'X.509','pq-rpk':'RPK','pq-compact-warm':'Compact warm','pq-compact-cold':'Compact cold','pq-mtc-experimental-landmark':'MTC landmark','pq-mtc-experimental-standalone':'MTC standalone'}
COLORS=dict(zip(LABELS,['#333333','#777777','#0072B2','#56B4E9','#D55E00','#CC79A7']))
MARKERS=dict(zip(LABELS,['o','s','^','v','D','P']))
def read(p):
 with p.open() as f:return list(csv.DictReader(f))
def main(root):
 out=root/'plots';out.mkdir(exist_ok=True);summary=read(root/'scaling-summary.csv');campaigns=read(root/'campaign-summary.csv');amort=read(root/'amortization.csv');structural=read(root/'structural-sizes.csv');comps=read(root/'component-campaign-summary.csv')
 plt.rcParams.update({'font.size':9,'axes.titlesize':11,'axes.labelsize':10,'legend.fontsize':8,'pdf.fonttype':42,'ps.fonttype':42,'svg.fonttype':'none','axes.spines.top':False,'axes.spines.right':False})
 def get(s,n,k):return float(next(r for r in summary if r['mode']=='primary' and r['scenario']==s and int(r['tree_size'])==n)[k+'_median'])
 def setup(ax,y):
  ax.set_xticks(X,[str(n) for n in SIZES]);ax.set_xlabel('Tree population N (log₂ spacing)');ax.set_ylabel(y);ax.grid(axis='y',alpha=.2)
 def save(fig,name):
  for ext in ['pdf','svg','png']:fig.savefig(out/(name+'.'+ext),dpi=220,bbox_inches='tight')
  plt.close(fig)
 fig,ax=plt.subplots(figsize=(7.1,4.3),layout='constrained')
 for s,label in LABELS.items():ax.plot(X,[get(s,n,'transport_total_bytes') for n in SIZES],label=label,color=COLORS[s],marker=MARKERS[s],lw=1.5)
 setup(ax,'TLS handshake bytes');ax.set_title('PQ authentication: handshake traffic');ax.legend(ncol=2,loc='center',bbox_to_anchor=(.5,.72));save(fig,'figure-1-tls-bytes')
 fig,ax=plt.subplots(figsize=(7.1,4.3),layout='constrained')
 for s in ['pq-compact-warm','pq-mtc-experimental-landmark']:ax.plot(X,[get(s,n,'transport_total_bytes')-get('pq-rpk',n,'transport_total_bytes') for n in SIZES],label=LABELS[s],color=COLORS[s],marker=MARKERS[s])
 setup(ax,'TLS bytes above RPK');ax.set_title('PQ credential and TLS framing overhead');ax.legend();save(fig,'figure-2-over-rpk')
 for metric,name,title,ylabel in [('handshake_wall_ms','figure-3-handshake-wall','PQ handshake wall time','Wall time (ms)'),('handshake_total_cpu_ms','figure-4-total-cpu','PQ combined endpoint CPU','Client + server CPU (ms)')]:
  fig,ax=plt.subplots(figsize=(7.1,4.5),layout='constrained')
  for si,(s,label) in enumerate(LABELS.items()):
   vals=[get(s,n,metric) for n in SIZES];ax.plot(X,vals,label=label,color=COLORS[s],marker=MARKERS[s],lw=1.3)
   for n,x in zip(SIZES,X):
    v=[float(r[metric+'_median']) for r in campaigns if r['mode']=='primary' and r['scenario']==s and int(r['tree_size'])==n];assert len(v)==5
    ax.scatter([x]*5,v,s=13,color=COLORS[s],alpha=.35,linewidth=0)
  setup(ax,ylabel);ax.set_title(title+'\nLines: median of 5 campaigns; dots: campaign medians',fontsize=10);ax.legend(ncol=2);save(fig,name)
 fig,axes=plt.subplots(1,3,figsize=(10,3.6),sharey=True,layout='constrained')
 for ax,n in zip(axes,[16,256,1024]):
  for s in ['pq-compact-warm','pq-mtc-experimental-landmark']:
   g=sorted([r for r in amort if r['scenario']==s and int(r['tree_size'])==n],key=lambda r:int(r['H']));ax.plot([int(r['H']) for r in g],[float(r['amortized_total_per_connection']) for r in g],label=LABELS[s],color=COLORS[s],marker=MARKERS[s]);ax.axhline(get(s,n,'transport_total_bytes'),color=COLORS[s],ls=':',lw=.8)
  ax.set_xscale('log');ax.set_xticks([1,10,100,1000,10000],['1','10','100','1k','10k']);ax.set_title(f'N = {n}');ax.set_xlabel('Analytical connections H');ax.grid(axis='y',alpha=.2)
 axes[0].set_ylabel('Amortized bytes / connection');axes[0].legend();fig.suptitle('PQ TLS + stored trust / H (no measured persistent reuse)',fontsize=11);save(fig,'figure-5-amortization')
 fig,ax=plt.subplots(figsize=(7.1,4.3),layout='constrained');g=[r for r in structural if r['crypto_family']=='pq']
 for field,label,color,ls in [('compact_proof_bytes','Compact MTP1 (encoded)','#0072B2','-'),('mtc_landmark_proof_bytes','MTCProof landmark (encoded)','#D55E00','-'),('compact_inclusion_hash_bytes','Compact sibling hashes','#0072B2','--'),('mtc_landmark_inclusion_bytes','MTC sibling hashes','#D55E00','--')]:ax.plot(X,[float(r[field]) for r in g],label=label,color=color,ls=ls,marker='o',ms=4)
 setup(ax,'Serialized proof bytes');ax.set_title('Encoded proofs and sibling-hash payloads');ax.legend();save(fig,'figure-6-proof-bytes')
 fig,axes=plt.subplots(1,2,figsize=(9,3.7),layout='constrained')
 for ax,component,title in zip(axes,['merkle_proof','spki_encode'],['Compact proof verification','Compact SPKI encoding']):
  for s in ['pq-compact-warm','pq-compact-cold']:
   med=[]
   for n,x in zip(SIZES,X):
    v=[float(r['cpu_ms_median'])*1000 for r in comps if r['side']=='client' and r['scenario']==s and r['component']==component and int(r['tree_size'])==n];assert len(v)==5;med.append(float(np.median(v)));ax.scatter([x]*5,v,color=COLORS[s],alpha=.4,s=13)
   ax.plot(X,med,label=LABELS[s],color=COLORS[s],marker=MARKERS[s])
  setup(ax,'Client CPU (µs)');ax.set_title(title);ax.legend()
 fig.suptitle('Separate existing detail timers: campaign medians, no regression\nMTC proof-only CPU is not instrumented',fontsize=10);save(fig,'figure-7-proof-cpu')
 (out/'metadata.json').write_text(json.dumps({'matplotlib':matplotlib.__version__,'numpy':np.__version__,'data_sources':['scaling-summary.csv','campaign-summary.csv','amortization.csv','structural-sizes.csv','component-campaign-summary.csv'],'timing_uncertainty':'individual campaign medians shown; no CI bars or regression','formats':['pdf','svg','png']},indent=2))
 print('Seven figures in PDF/SVG/PNG:',out)
if __name__=='__main__':main(Path(sys.argv[1]))
