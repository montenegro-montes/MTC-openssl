"""Run the explicit default Stage-A matrix; never overwrites an output."""
import argparse, csv, datetime, hashlib, json
from pathlib import Path
from run import FIELDS, simulate

SIZES=[16,64,256,1024];WORKLOADS=["uniform","zipf","clustered"];BUDGETS=[0,1,2,4,8,16];POLICIES=["lru","upper-level"]


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--fixtures",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--accesses",type=int,default=1000);p.add_argument("--seed",type=int,default=20260911);p.add_argument("--include-full-cache",action=argparse.BooleanOptionalAction,default=True);a=p.parse_args()
    if a.output.exists():p.error("output exists; choose a new directory")
    a.output.mkdir(parents=True);rows=[];configs=[];ordinal=0
    for n in SIZES:
      for workload in WORKLOADS:
       variants=[(policy,kb) for policy in POLICIES for kb in BUDGETS]+([("full",None)] if a.include_full_cache else [])
       for policy,kb in variants:
        ordinal+=1;seed=a.seed+ordinal;budget=0 if kb is None else kb*1024
        rows.extend(simulate(a.fixtures.resolve(),n,workload,a.accesses,seed,policy,budget));configs.append({"tree_size":n,"workload":workload,"policy":policy,"cache_kb":kb,"seed":seed})
    with (a.output/"observations.csv").open("w",newline="") as f:w=csv.DictWriter(f,fieldnames=FIELDS);w.writeheader();w.writerows(rows)
    manifest={"format":"pcma-stage-a-matrix-v1","created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"fixtures":str(a.fixtures.resolve()),"base_seed":a.seed,"accesses_per_run":a.accesses,"runs":len(configs),"observations":len(rows),"configurations":configs,"observations_sha256":hashlib.sha256((a.output/"observations.csv").read_bytes()).hexdigest()}
    (a.output/"manifest.json").write_text(json.dumps(manifest,indent=2)+"\n");print(a.output,len(configs),"runs",len(rows),"observations")


if __name__=="__main__":main()
