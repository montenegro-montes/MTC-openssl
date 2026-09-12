#!/usr/bin/env python3
"""Host-side immutable fixture generator using the pinned measurement image."""
import argparse, json, subprocess
from pathlib import Path
from config import DEPTHS, IMAGE, PROFILES
REPO=Path(__file__).resolve().parents[3]
def main():
 p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);p.add_argument("--profile",action="append",choices=PROFILES);p.add_argument("--depth",action="append",type=int,choices=DEPTHS);p.add_argument("--image",default=IMAGE);p.add_argument("--plan",action="store_true");a=p.parse_args();out=a.output.resolve()
 if out.exists():p.error("Output exists; choose a new immutable fixture root")
 profiles=a.profile or list(PROFILES);depths=a.depth or list(DEPTHS);commands=[]
 for profile in profiles:
  for depth in depths:commands.append(["docker","run","--rm","-v",f"{REPO}:/repo:ro","-v",f"{out.parent}:/output",a.image,"python3","/repo/campaigns/cryptographic_scaling/cert_chain_scaling/fixture_builder.py","--output",f"/output/{out.name}/{profile}/depth-{depth}","--profile",profile,"--depth",str(depth)])
 if a.plan:
  print(json.dumps({"output":str(out),"commands":commands},indent=2));return
 out.parent.mkdir(parents=True,exist_ok=True)
 for command in commands:subprocess.run(command,check=True)
 print(out)
if __name__=="__main__":main()
