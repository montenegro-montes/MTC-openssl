#!/usr/bin/env python3
"""Produce descriptive network-campaign summaries without a reference winner."""
import argparse,csv,statistics
from pathlib import Path
CONDITIONS=('profile','authentication','rtt_target_ms','rate_target_mbit','loss_target_percent','network_profile','configured_rtt_ms','configured_bandwidth_mbit','configured_loss_percent')
def read(path):
 with path.open(newline='') as f:return list(csv.DictReader(f))
def main():
 p=argparse.ArgumentParser();p.add_argument('root',type=Path);a=p.parse_args();rows=[]
 for path in a.root.rglob('samples.csv'):rows.extend(read(path))
 if not rows:raise SystemExit('no measured samples found')
 groups={}
 for row in rows:
  key=(row['scenario'],)+tuple(row.get(k,'') for k in CONDITIONS);groups.setdefault(key,[]).append(row)
 out=[]
 for key,data in sorted(groups.items()):
  times=[float(r['handshake_wall_ms']) for r in data];sizes=[int(float(r['transport_total_bytes'])) for r in data]
  item={'scenario':key[0],**dict(zip(CONDITIONS,key[1:])),'samples':len(data),'handshake_wall_ms_mean':statistics.mean(times),'handshake_wall_ms_median':statistics.median(times),'handshake_wall_ms_stdev':statistics.stdev(times) if len(times)>1 else 0,'transport_total_bytes_median':statistics.median(sizes)};out.append(item)
 fields=list(out[0]);target=a.root/'network-summary.csv'
 with target.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(out)
 print(target)
if __name__=='__main__':main()
