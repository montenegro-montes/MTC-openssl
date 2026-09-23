#!/usr/bin/env python3
"""Generate descriptive handshake-time plots from network-summary.csv."""
import argparse,csv
from pathlib import Path
def main():
 p=argparse.ArgumentParser();p.add_argument('root',type=Path);a=p.parse_args();import matplotlib.pyplot as plt
 with (a.root/'network-summary.csv').open(newline='') as f:rows=list(csv.DictReader(f))
 out=a.root/'plots';out.mkdir(exist_ok=False);labels=[f"{r['scenario']}\n{i+1}" for i,r in enumerate(rows)];values=[float(r['handshake_wall_ms_median']) for r in rows];fig,ax=plt.subplots(figsize=(max(8,len(rows)*.35),5));ax.bar(labels,values);ax.set_ylabel('Handshake wall time median (ms)');ax.tick_params(axis='x',rotation=90);fig.tight_layout();fig.savefig(out/'handshake-time.png',dpi=150);fig.savefig(out/'handshake-time.pdf');plt.close(fig);print(out)
if __name__=='__main__':main()
