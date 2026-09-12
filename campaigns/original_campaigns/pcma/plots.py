"""Generate PCMA Stage-A figures from observations.csv and summary.csv."""
import argparse,csv
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("root",type=Path);a=p.parse_args()
    try:import matplotlib.pyplot as plt
    except ImportError:p.error("matplotlib is required; install requirements-plots.txt in a separate environment")
    raw=a.root/"observations.csv";summary_file=a.root/"summary.csv"
    if not raw.is_file() or not summary_file.is_file():p.error("run the experiment and analyze.py before plots.py")
    rows=list(csv.DictReader(raw.open()));summary=list(csv.DictReader(summary_file.open()));out=a.root/"plots"
    if out.exists():p.error(f"{out} already exists; plots are not overwritten")
    out.mkdir()
    def save(name):plt.tight_layout();plt.savefig(out/(name+".png"),dpi=180);plt.savefig(out/(name+".pdf"));plt.close()
    selected=[r for r in rows if r["tree_size"]=="256" and r["workload"]=="clustered" and r["cache_policy"]=="full"]
    plt.plot([int(r["sequence_position"]) for r in selected],[float(r["net_authentication_bytes"]) for r in selected],label="net authentication bytes")
    plt.plot([int(r["sequence_position"]) for r in selected],[32*int(r["transmitted_hashes"]) for r in selected],label="transmitted hash bytes");plt.xlabel("access t");plt.ylabel("bytes");plt.legend();save("bytes-vs-access")
    bounded=[r for r in summary if r["workload"]=="clustered" and r["cache_policy"]=="lru" and r["cache_budget_bytes"]!="unbounded"]
    for n in [16,64,256,1024]:
        part=[r for r in bounded if int(r["tree_size"])==n];plt.plot([int(r["cache_budget_bytes"]) for r in part],[float(r["net_authentication_bytes_mean"]) for r in part],marker="o",label=f"N={n}")
    plt.xlabel("cache budget bytes");plt.ylabel("mean authentication bytes");plt.legend();save("budget-and-tree-size")
    for workload in ["uniform","zipf","clustered"]:
        part=[r for r in summary if r["tree_size"]=="256" and r["workload"]==workload and r["cache_policy"]=="lru" and r["cache_budget_bytes"]!="unbounded"]
        plt.plot([int(r["cache_budget_bytes"]) for r in part],[float(r["net_bytes_saved_mean"]) for r in part],marker="o",label=workload)
    plt.xlabel("cache budget bytes");plt.ylabel("mean net bytes saved");plt.legend();save("workloads")
    for policy in ["lru","upper-level"]:
        part=[r for r in summary if r["tree_size"]=="256" and r["workload"]=="clustered" and r["cache_policy"]==policy]
        plt.plot([int(r["cache_budget_bytes"]) for r in part],[float(r["net_authentication_bytes_mean"]) for r in part],marker="o",label=policy)
    plt.xlabel("cache budget bytes");plt.ylabel("mean authentication bytes");plt.legend();save("cache-policies")
    plt.scatter([float(r["cache_bytes_mean"]) for r in summary],[float(r["net_authentication_bytes_mean"]) for r in summary],s=12);plt.xlabel("mean client storage bytes");plt.ylabel("mean authentication bytes");save("storage-communication-pareto")
    print(out)


if __name__=="__main__":main()
