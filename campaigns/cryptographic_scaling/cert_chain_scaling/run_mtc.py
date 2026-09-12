#!/usr/bin/env python3
"""Filtered manual MTC runner over preserved scaling fixtures."""
import argparse,json,os,subprocess
from pathlib import Path
from config import IMAGE,MTC_PROFILE_MAP,TREE_SIZES
REPO=Path(__file__).resolve().parents[3];ARTIFACTS=REPO/"artifacts";COMPOSE=["docker","compose","-f",str(REPO/"docker/original_campaigns/compose.scaling.yaml")]
def main():
 p=argparse.ArgumentParser();p.add_argument("--fixtures",type=Path,required=True,help="Scaling root containing batchN directories");p.add_argument("--output",type=Path,required=True);p.add_argument("--profile",choices=MTC_PROFILE_MAP,default="mldsa65");p.add_argument("--scenario",choices=["landmark","standalone"],default="landmark");p.add_argument("--tree-size",type=int,choices=TREE_SIZES,required=True);p.add_argument("--campaigns",type=int,default=1);p.add_argument("--repetitions",type=int,default=30);p.add_argument("--warmups",type=int,default=5);p.add_argument("--seed",type=int,default=51000);p.add_argument("--image",default=IMAGE);p.add_argument("--execute",action="store_true");a=p.parse_args()
 fixtures=a.fixtures.resolve();output=a.output.resolve()
 try:fixture_container="/work/"+str(fixtures.relative_to(ARTIFACTS.resolve()));result_container="/work/results/"+str(output.relative_to((ARTIFACTS/"results").resolve()))
 except ValueError:p.error("fixtures must be under artifacts/ and output under artifacts/results/")
 family=MTC_PROFILE_MAP[a.profile];scenario=f"{family}-mtc-experimental-{a.scenario}";plan={"schema":1,"status":"MTC-experimental","profile":a.profile,"scenario":scenario,"tree_size":a.tree_size,"campaigns":a.campaigns,"repetitions":a.repetitions,"warmups":a.warmups,"output":str(output)}
 if output.exists():p.error("Output exists; results are immutable")
 if not a.execute:print(json.dumps(plan,indent=2));return
 output.mkdir(parents=True);(output/"manifest.json").write_text(json.dumps(plan,indent=2)+"\n");image_id=json.loads(subprocess.check_output(["docker","image","inspect",a.image],text=True))[0]["Id"]
 for index in range(1,a.campaigns+1):
  cid=f"{scenario}-n{a.tree_size}-c{index}";seed=a.seed+index+a.tree_size;env=os.environ.copy();env.update(SCALING_IMAGE=image_id,SCALING_FIXTURES=fixture_container,TREE_SIZE=str(a.tree_size),SCALING_DETAIL="1",MEASUREMENT_RUN_ROOT=result_container,MEASUREMENT_CAMPAIGN_ID=cid,MEASUREMENT_SEED=str(seed))
  try:
   subprocess.run(COMPOSE+["up","-d","--force-recreate","--wait","server"],env=env,check=True)
   subprocess.run(COMPOSE+["run","--rm","client","python3","/opt/measurement/measure.py","--runs",str(a.repetitions),"--warmup",str(a.warmups),"--seed",str(seed),"--image-id",image_id,"--scenarios",scenario],env=env,check=True)
  finally:subprocess.run(COMPOSE+["down"],env=env,check=False)
if __name__=="__main__":main()
