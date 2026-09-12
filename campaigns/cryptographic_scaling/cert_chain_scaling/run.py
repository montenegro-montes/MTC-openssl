#!/usr/bin/env python3
"""Filtered manual X.509 runner; full matrices require --full-matrix explicitly."""
import argparse,hashlib,json,os,platform,subprocess
from pathlib import Path
from config import DEPTHS,IMAGE,PROFILES
REPO=Path(__file__).resolve().parents[3];COMPOSE=["docker","compose","-f",str(REPO/"docker/cryptographic_scaling/compose.cert-chain-scaling.yaml")]
def main():
 p=argparse.ArgumentParser();p.add_argument("--fixtures",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--profile",action="append",choices=PROFILES);p.add_argument("--family",choices=["ECDSA","ML-DSA","SLH-DSA"]);p.add_argument("--security-level",type=int,choices=[1,3,5]);p.add_argument("--depth",action="append",type=int,choices=DEPTHS);p.add_argument("--campaigns",type=int,default=1);p.add_argument("--repetitions",type=int,default=30);p.add_argument("--warmups",type=int,default=5);p.add_argument("--seed",type=int,default=41000);p.add_argument("--image",default=IMAGE);p.add_argument("--execute",action="store_true");p.add_argument("--full-matrix",action="store_true");a=p.parse_args()
 profiles=a.profile or list(PROFILES);profiles=[x for x in profiles if (not a.family or PROFILES[x]["family"]==a.family) and (not a.security_level or PROFILES[x]["level"]==a.security_level)];depths=a.depth or list(DEPTHS)
 cells=[(profile,depth,c) for profile in profiles for depth in depths for c in range(1,a.campaigns+1)]
 if len(profiles)==len(PROFILES) and len(depths)==len(DEPTHS) and not a.full_matrix:p.error("complete matrix requires --full-matrix (WARNING: expensive)")
 if a.output.exists():p.error("Output exists; results are immutable")
 plan={"schema":1,"profiles":profiles,"depths":depths,"campaigns":a.campaigns,"repetitions":a.repetitions,"warmups":a.warmups,"seed":a.seed,"cells":[{"profile":x,"depth":d,"campaign":c} for x,d,c in cells]}
 if not a.execute:print(json.dumps(plan,indent=2));return
 commit=subprocess.check_output(["git","rev-parse","HEAD"],cwd=REPO,text=True).strip();status=subprocess.check_output(["git","status","--porcelain"],cwd=REPO,text=True);image=json.loads(subprocess.check_output(["docker","image","inspect",a.image],text=True))[0]
 plan.update(git_commit=commit,git_status=status,image_id=image["Id"],platform=platform.platform(),tls={"version":"TLSv1.3","group":"X25519","cipher":"TLS_AES_256_GCM_SHA384","tickets":False,"resumption":False},network="Docker bridge; no NET_ADMIN and no qdisc configuration")
 a.output.mkdir(parents=True);(a.output/"manifest.json").write_text(json.dumps(plan,indent=2)+"\n");(a.output/"environment.json").write_text(json.dumps({"image":image,"platform":platform.platform()},indent=2)+"\n")
 fixture_hashes={str(x.relative_to(a.fixtures)):hashlib.sha256(x.read_bytes()).hexdigest() for x in a.fixtures.glob("*/depth-*/manifest.json")};(a.output/"fixture_hashes.json").write_text(json.dumps(fixture_hashes,indent=2)+"\n")
 for profile,depth,index in cells:
  campaign=f"{profile}-d{depth}-c{index}";fixture=a.fixtures/profile/f"depth-{depth}";fixture_hash=hashlib.sha256((fixture/"manifest.json").read_bytes()).hexdigest();env=os.environ.copy();env.update(CERT_CHAIN_IMAGE=a.image,CERT_CHAIN_FIXTURES=str(a.fixtures.resolve()),CERT_CHAIN_RESULTS=str(a.output.resolve()),CERT_PROFILE=profile,CERT_DEPTH=str(depth),CERT_CAMPAIGN=campaign,FIXTURE_SHA256=fixture_hash,SOURCE_COMMIT=commit,IMAGE_ID=image["Id"]);seed=a.seed+index+depth*100+list(PROFILES).index(profile)*1000
  try:
   subprocess.run(COMPOSE+["up","-d","--force-recreate","--wait","server"],env=env,check=True)
   subprocess.run(COMPOSE+["run","--rm","client","python3","/repo/campaigns/cryptographic_scaling/cert_chain_scaling/measure.py","--runs",str(a.repetitions),"--warmups",str(a.warmups),"--scenario",profile+f"-d{depth}","--campaign",campaign,"--seed",str(seed)],env=env,check=True)
  finally:subprocess.run(COMPOSE+["down"],env=env,check=False)
if __name__=="__main__":main()
