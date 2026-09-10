import csv,math,os,sys
from pathlib import Path
os.environ.setdefault('MPLCONFIGDIR','/tmp/mt-network-plots')
import matplotlib;matplotlib.use('Agg')
import matplotlib.pyplot as plt
def read(p):
    with p.open() as f:return list(csv.DictReader(f))
def main(root):
    out=root/'plots';out.mkdir();summary=read(root/'latency-summary.csv');effects=read(root/'bootstrap-comparisons.csv');campaigns=read(root/'campaign-summary.csv')
    plt.rcParams.update({'font.size':9,'axes.spines.top':False,'axes.spines.right':False,'pdf.fonttype':42,'svg.fonttype':'none'})
    colors={'pq':'#333333','pq-compact-warm':'#0072B2','pq-mtc-experimental-landmark':'#D55E00'};labels={'pq':'X.509','pq-compact-warm':'Compact warm','pq-mtc-experimental-landmark':'MTC landmark'}
    def save(fig,name):
        for ext in ['pdf','svg','png']:fig.savefig(out/f'{name}.{ext}',dpi=220,bbox_inches='tight')
        plt.close(fig)
    fig,ax=plt.subplots(figsize=(7,4.3),layout='constrained')
    for s in colors:
        g=sorted([r for r in summary if r['scenario']==s],key=lambda r:float(r['rtt_measured_ms']));x=[float(r['rtt_measured_ms']) for r in g];y=[float(r['handshake_wall_ms_median']) for r in g];ax.plot(x,y,marker='o',label=labels[s],color=colors[s])
        for r in g:
            vals=[float(c['handshake_wall_ms_median']) for c in campaigns if c['scenario']==s and c['rtt_target_ms']==r['rtt_target_ms']];ax.scatter([float(r['rtt_measured_ms'])]*5,vals,color=colors[s],alpha=.35,s=14)
    ax.set(xlabel='Measured RTT (ms)',ylabel='Handshake wall time (ms)',title='Latency only: PQ TLS handshake');ax.grid(axis='y',alpha=.2);ax.legend();save(fig,'latency-handshake-vs-rtt')
    fig,ax=plt.subplots(figsize=(7,4.3),layout='constrained')
    pairs=[('pq-compact-warm','pq','Compact warm − X.509','#0072B2'),('pq-mtc-experimental-landmark','pq','MTC landmark − X.509','#D55E00'),('pq-compact-warm','pq-mtc-experimental-landmark','Compact warm − MTC landmark','#009E73')]
    for s,b,label,color in pairs:
        g=sorted([r for r in effects if r['scenario']==s and r['baseline']==b and r['metric']=='handshake_wall_ms'],key=lambda r:float(r['rtt_target_ms']));x=[float(r['rtt_target_ms']) for r in g];y=[float(r['median_campaign_effect']) for r in g];lo=[v-float(r['bootstrap95_low']) for v,r in zip(y,g)];hi=[float(r['bootstrap95_high'])-v for v,r in zip(y,g)];ax.errorbar(x,y,yerr=[lo,hi],marker='o',capsize=3,label=label,color=color)
    ax.axhline(0,color='#555',lw=.8);ax.set(xlabel='Additional RTT target (ms)',ylabel='Paired wall-time difference (ms)',title='Latency-only paired effects (campaign bootstrap 95% CI)');ax.grid(axis='y',alpha=.2);ax.legend();save(fig,'latency-paired-differences')
if __name__=='__main__':main(Path(sys.argv[1]))
