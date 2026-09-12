#!/usr/bin/env python3
import argparse,csv,random,statistics
from pathlib import Path
def main():
 p=argparse.ArgumentParser();p.add_argument("root",type=Path);a=p.parse_args();files=list(a.root.glob("*/data/observations.csv"));rows=[]
 for file in files:
  with file.open() as f:rows.extend(csv.DictReader(f))
 if not rows:raise SystemExit("No observations found")
 metrics=["handshake_wall_ms","client_cpu_ms","server_cpu_ms","authentication_processing_wall_ms","authentication_processing_cpu_ms","certificate_message_bytes","certificate_verify_message_bytes","tls_bio_read_bytes","tls_bio_written_bytes"]
 output=[]
 for scenario in sorted({r["scenario"] for r in rows}):
  group=[r for r in rows if r["scenario"]==scenario];entry={"scenario":scenario,"n":len(group),"campaigns":len({r["campaign"] for r in group})}
  for metric in metrics:
   values=[statistics.median(float(r[metric]) for r in group if r["campaign"]==c) for c in sorted({r["campaign"] for r in group})];entry[metric+"_median_of_campaign_medians"]=statistics.median(values)
   if len(values)>=2:
    rng=random.Random(73001);boot=sorted(statistics.median(rng.choices(values,k=len(values))) for _ in range(2000));entry[metric+"_bootstrap95_low"]=boot[49];entry[metric+"_bootstrap95_high"]=boot[1949]
   else:entry[metric+"_bootstrap95_low"]="";entry[metric+"_bootstrap95_high"]=""
  output.append(entry)
 with (a.root/"summary.csv").open("w",newline="") as f:w=csv.DictWriter(f,fieldnames=list(output[0]));w.writeheader();w.writerows(output)
 print(a.root/"summary.csv")
if __name__=="__main__":main()
