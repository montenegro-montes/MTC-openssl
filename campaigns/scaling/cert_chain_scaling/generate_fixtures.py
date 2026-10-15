#!/usr/bin/env python3
"""Host-side immutable fixture generator using the pinned measurement image."""
import argparse, json, os, subprocess
from pathlib import Path
from config import DEPTHS, IMAGE, PROFILES
REPO=Path(__file__).resolve().parents[3]
def main():
 p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);p.add_argument("--profile",action="append",choices=PROFILES);p.add_argument("--depth",action="append",type=int,choices=DEPTHS);p.add_argument("--image",default=IMAGE);p.add_argument("--role",choices=("server","client"),default="server");p.add_argument("--plan",action="store_true");a=p.parse_args();out=a.output.resolve()
 if out.exists():p.error("Output exists; choose a new immutable fixture root")
 profiles=a.profile or list(PROFILES);depths=a.depth or list(DEPTHS);commands=[]
 for profile in profiles:
  for depth in depths:commands.append(["docker","run","--rm","--user",f"{os.getuid()}:{os.getgid()}","-v",f"{REPO}:/repo:ro","-v",f"{out.parent}:/output",a.image,"python3","/repo/campaigns/scaling/cert_chain_scaling/fixture_builder.py","--output",f"/output/{out.name}/{profile}/depth-{depth}","--profile",profile,"--depth",str(depth),"--role",a.role])
 if a.plan:
  print(json.dumps({"output":str(out),"commands":commands},indent=2));return
 out.parent.mkdir(parents=True,exist_ok=True)
 image_id=json.loads(subprocess.check_output(["docker","image","inspect",a.image],text=True))[0]["Id"]
 commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=REPO,text=True).strip()
 for index,command in enumerate(commands,1):
  print(f"  [{index}/{len(commands)}] {command[command.index('--profile')+1]} D={command[command.index('--depth')+1]} {a.role} generating...",flush=True)
  command[command.index(a.image)]=image_id
  command[3:3]=["-e","FIXTURE_IMAGE_ID="+image_id,"-e","FIXTURE_SOURCE_COMMIT="+commit]
  subprocess.run(command,check=True)
 for profile in profiles:
  for depth in depths:
   manifest=out/profile/f"depth-{depth}"/"manifest.json"
   try:manifest.read_bytes()
   except OSError as error:raise SystemExit(f"ERROR: generated fixture manifest is not host-readable: {manifest}: {error}")
 print(out)
if __name__=="__main__":main()
