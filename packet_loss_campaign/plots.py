"""Paper figures from analyzed CSVs; skips unsupported per-connection retransmission plot."""
import csv,os,sys
from pathlib import Path
os.environ.setdefault('MPLCONFIGDIR','/tmp/mt-network-plots')
import matplotlib;matplotlib.use('Agg')
import matplotlib.pyplot as plt
def read(path):
    with path.open() as f:return list(csv.DictReader(f))
def number(value):return float(value) if value not in ['',None,'NA'] else None
def main(root):
    out=root/'plots';out.mkdir();summary=read(root/'scenario-summary.csv');effects=read(root/'bootstrap-comparisons.csv');retrans=read(root/'retransmissions.csv');colors={'pq':'#333333','pq-compact-warm':'#0072B2','pq-mtc-experimental-landmark':'#D55E00'};labels={'pq':'X.509','pq-compact-warm':'Compact warm','pq-mtc-experimental-landmark':'MTC landmark'};plt.rcParams.update({'font.size':9,'axes.spines.top':False,'axes.spines.right':False,'pdf.fonttype':42,'svg.fonttype':'none'})
    def save(fig,name):
        for ext in ['pdf','svg','png']:fig.savefig(out/f'{name}.{ext}',dpi=220,bbox_inches='tight')
        plt.close(fig)
    fig,ax=plt.subplots(figsize=(7,4.3),layout='constrained')
    for scenario in colors:
        g=[r for r in summary if r['scenario']==scenario];x=[float(r['loss_target_percent']) for r in g];y=[number(r['handshake_wall_ms_median_of_campaign_medians']) for r in g];ax.plot(x,y,marker='o',color=colors[scenario],label=labels[scenario])
    ax.set(xlabel='Configured loss per egress direction (%)',ylabel='Successful handshake wall time (ms)',title='Packet loss: TLS handshake latency');ax.grid(axis='y',alpha=.2);ax.legend();save(fig,'figure-1-handshake-wall-vs-loss')
    fig,ax=plt.subplots(figsize=(7,4.3),layout='constrained')
    for scenario,base,label,color in [('pq-compact-warm','pq','Compact warm − X.509','#0072B2'),('pq-mtc-experimental-landmark','pq','MTC landmark − X.509','#D55E00'),('pq-compact-warm','pq-mtc-experimental-landmark','Compact warm − MTC','#009E73')]:
        g=[r for r in effects if r['scenario']==scenario and r['baseline']==base and r['metric']=='handshake_wall_ms' and r['median_campaign_effect']!=''];x=[float(r['loss_target_percent']) for r in g];y=[float(r['median_campaign_effect']) for r in g];lo=[v-float(r['bootstrap95_low']) for v,r in zip(y,g)];hi=[float(r['bootstrap95_high'])-v for v,r in zip(y,g)];ax.errorbar(x,y,yerr=[lo,hi],marker='o',capsize=3,color=color,label=label)
    ax.axhline(0,color='#555',lw=.8);ax.set(xlabel='Configured loss per egress direction (%)',ylabel='Paired wall-time difference (ms)',title='Packet-loss paired effects');ax.grid(axis='y',alpha=.2);ax.legend();save(fig,'figure-2-paired-difference-vs-loss')
    fig,ax=plt.subplots(figsize=(7,4.3),layout='constrained')
    for scenario in colors:
        g=[r for r in summary if r['scenario']==scenario];ax.plot([float(r['loss_target_percent']) for r in g],[100*float(r['failure_rate']) for r in g],marker='o',color=colors[scenario],label=labels[scenario])
    ax.set(xlabel='Configured loss per egress direction (%)',ylabel='Handshake failure rate (%)',title='Handshake reliability under packet loss');ax.grid(axis='y',alpha=.2);ax.legend();save(fig,'figure-3-failure-rate-vs-loss')
    fig,ax=plt.subplots(figsize=(7,4.3),layout='constrained')
    for side,color in [('client','#0072B2'),('server','#D55E00')]:
        points=[]
        for loss in ['0','0.1','0.5','1','2','5']:
            values=[float(r['tcp_retransmitted_segments']) for r in retrans if r['side']==side and r['loss_target_percent']==loss];points.append((float(loss),sum(values)/len(values)))
        ax.plot([p[0] for p in points],[p[1] for p in points],marker='o',color=color,label=side.title())
    ax.set(xlabel='Configured loss per egress direction (%)',ylabel='Campaign TCP retransmitted segments',title='Campaign-level retransmission activity');ax.grid(axis='y',alpha=.2);ax.legend();save(fig,'figure-4-retransmissions-vs-loss')
    (out/'README.txt').write_text('Figure 5 (latency vs retransmission count) is intentionally absent: retransmission counters are campaign/container-level and cannot be attributed reliably to individual handshakes or scenarios.\n')
if __name__=='__main__':main(Path(sys.argv[1]))
