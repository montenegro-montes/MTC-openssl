import csv,sys
from pathlib import Path
import matplotlib.pyplot as plt
root=Path(sys.argv[1]);plots=root/'plots';plots.mkdir(exist_ok=True)
with (root/'scenario-summary.csv').open() as f:rows=list(csv.DictReader(f))
primary=['pq','pq-compact-warm','pq-mtc-experimental-landmark'];profiles=['baseline','wan','constrained','adverse']
def plot(metric,title,name):
 fig,ax=plt.subplots(figsize=(8,4.8));x=range(len(profiles))
 for scenario in primary:
  vals=[float(next(r[metric] for r in rows if r['profile']==p and r['scenario']==scenario)) for p in profiles];ax.plot(x,vals,marker='o',label=scenario)
 ax.set_xticks(list(x),profiles);ax.set_ylabel(title);ax.grid(alpha=.25);ax.legend();fig.tight_layout();fig.savefig(plots/name,dpi=180);plt.close(fig)
plot('handshake_wall_ms_median_of_campaign_medians','Handshake wall time (ms)','wall-time.png')
plot('handshake_total_cpu_ms_median_of_campaign_medians','Total handshake CPU (ms)','cpu-time.png')
plot('transport_total_bytes_median_of_campaign_medians','TLS BIO bytes','tls-bytes.png')
plot('failure_rate','Failure rate','failure-rate.png')
