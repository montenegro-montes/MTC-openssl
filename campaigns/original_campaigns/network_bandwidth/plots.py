import csv,os,sys
from pathlib import Path
os.environ.setdefault('MPLCONFIGDIR','/tmp/mt-network-plots')
import matplotlib;matplotlib.use('Agg')
import matplotlib.pyplot as plt
def read(p):
    with p.open() as f:return list(csv.DictReader(f))
def main(root):
    out=root/'plots';out.mkdir();summary=read(root/'bandwidth-summary.csv');effects=read(root/'bootstrap-comparisons.csv');serialization=read(root/'serialization-reference.csv');plt.rcParams.update({'font.size':9,'axes.spines.top':False,'axes.spines.right':False,'pdf.fonttype':42,'svg.fonttype':'none'})
    colors={'pq':'#333333','pq-rpk':'#777777','pq-compact-warm':'#0072B2','pq-compact-cold':'#56B4E9','pq-mtc-experimental-landmark':'#D55E00','pq-mtc-experimental-standalone':'#CC79A7'}
    labels={s:s.removeprefix('pq-').replace('mtc-experimental-','MTC ').replace('compact-','Compact ').replace('pq','X.509').replace('rpk','RPK').title() for s in colors}
    def save(fig,name):
        for ext in ['pdf','svg','png']:fig.savefig(out/f'{name}.{ext}',dpi=220,bbox_inches='tight')
        plt.close(fig)
    for rtt in [10,50,100]:
        fig,ax=plt.subplots(figsize=(7,4.3),layout='constrained')
        for s in colors:
            g=sorted([r for r in summary if int(r['rtt_target_ms'])==rtt and r['scenario']==s],key=lambda r:float(r['bandwidth_measured_mbps']));ax.plot([float(r['bandwidth_measured_mbps']) for r in g],[float(r['handshake_wall_ms_median']) for r in g],marker='o',label=labels[s],color=colors[s])
        ax.set_xscale('log');ax.invert_xaxis();ax.set(xlabel='Measured rate per direction (Mbps)',ylabel='Handshake wall time (ms)',title=f'Bandwidth limited, RTT target {rtt} ms');ax.grid(axis='y',alpha=.2);ax.legend(ncol=2);save(fig,f'bandwidth-handshake-rtt-{rtt}')
        fig,ax=plt.subplots(figsize=(7,4.3),layout='constrained')
        for s,b,label,color in [('pq-compact-warm','pq','Compact warm − X.509','#0072B2'),('pq-mtc-experimental-landmark','pq','MTC landmark − X.509','#D55E00'),('pq-compact-warm','pq-mtc-experimental-landmark','Compact warm − MTC','#009E73')]:
            g=sorted([r for r in effects if int(r['rtt_target_ms'])==rtt and r['scenario']==s and r['baseline']==b and r['metric']=='handshake_wall_ms'],key=lambda r:float(r['bandwidth_target_mbps']));x=[float(r['bandwidth_target_mbps']) for r in g];y=[float(r['median_campaign_effect']) for r in g];lo=[v-float(r['bootstrap95_low']) for v,r in zip(y,g)];hi=[float(r['bootstrap95_high'])-v for v,r in zip(y,g)];ax.errorbar(x,y,yerr=[lo,hi],marker='o',capsize=3,label=label,color=color)
        ax.set_xscale('log');ax.invert_xaxis();ax.axhline(0,color='#555',lw=.8);ax.set(xlabel='Target rate per direction (Mbps)',ylabel='Paired wall-time difference (ms)',title=f'Paired bandwidth effects, RTT {rtt} ms');ax.grid(axis='y',alpha=.2);ax.legend();save(fig,f'bandwidth-paired-rtt-{rtt}')
    fig,ax=plt.subplots(figsize=(6,5),layout='constrained')
    for s,b,label,color in [('pq-compact-warm','pq','Compact warm − X.509','#0072B2'),('pq-mtc-experimental-landmark','pq','MTC landmark − X.509','#D55E00')]:
        points=[]
        for e in effects:
            if e['scenario']==s and e['baseline']==b and e['metric']=='handshake_wall_ms':
                left=next(r for r in serialization if r['scenario']==s and r['rtt_target_ms']==e['rtt_target_ms'] and r['bandwidth_target_mbps']==e['bandwidth_target_mbps']);right=next(r for r in serialization if r['scenario']==b and r['rtt_target_ms']==e['rtt_target_ms'] and r['bandwidth_target_mbps']==e['bandwidth_target_mbps']);points.append((float(left['theoretical_serialization_ms'])-float(right['theoretical_serialization_ms']),float(e['median_campaign_effect'])))
        ax.scatter([p[0] for p in points],[p[1] for p in points],label=label,color=color)
    ax.axhline(0,color='#555',lw=.8);ax.set(xlabel='Theoretical serialization difference (ms)',ylabel='Measured paired wall-time difference (ms)',title='Serialization reference vs measured effect');ax.grid(alpha=.2);ax.legend();save(fig,'bandwidth-measured-vs-serialization')
if __name__=='__main__':main(Path(sys.argv[1]))
