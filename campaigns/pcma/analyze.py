"""Aggregate completed PCMA observations into summaries and Pareto data."""
import argparse,csv,json,statistics
from collections import defaultdict
from pathlib import Path

METRICS=["normal_proof_bytes","pcma_proof_bytes","state_advertisement_bytes","net_authentication_bytes","net_bytes_saved","saving_percentage","transmitted_hashes","reused_hashes","cached_nodes","cache_bytes","proof_construction_ns","verification_reconstruction_ns"]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("root",type=Path);a=p.parse_args();source=a.root/"observations.csv"
    if not source.is_file():p.error(f"{source} does not exist; execute a diagnostic or Stage-A matrix first")
    rows=list(csv.DictReader(source.open()));groups=defaultdict(list)
    for row in rows:groups[(row["tree_size"],row["workload"],row["cache_policy"],row["cache_budget_bytes"])].append(row)
    summary=[]
    for key,items in sorted(groups.items(),key=lambda x:(int(x[0][0]),x[0][1],x[0][2],x[0][3])):
        record=dict(zip(["tree_size","workload","cache_policy","cache_budget_bytes"],key));record["observations"]=len(items)
        for metric in METRICS:
            values=[float(x[metric]) for x in items];record[metric+"_mean"]=statistics.fmean(values);record[metric+"_median"]=statistics.median(values)
        summary.append(record)
    with (a.root/"summary.csv").open("w",newline="") as f:w=csv.DictWriter(f,fieldnames=list(summary[0]));w.writeheader();w.writerows(summary)
    pareto=[{"tree_size":r["tree_size"],"workload":r["workload"],"cache_policy":r["cache_policy"],"cache_budget_bytes":r["cache_budget_bytes"],"client_storage_bytes":r["cache_bytes_mean"],"authentication_communication_bytes":r["net_authentication_bytes_mean"]} for r in summary]
    with (a.root/"pareto.csv").open("w",newline="") as f:w=csv.DictWriter(f,fieldnames=list(pareto[0]));w.writeheader();w.writerows(pareto)
    (a.root/"analysis.json").write_text(json.dumps({"passed":True,"input_rows":len(rows),"groups":len(summary),"outputs":["summary.csv","pareto.csv"]},indent=2)+"\n");print(a.root/"summary.csv")


if __name__=="__main__":main()
