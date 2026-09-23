#!/usr/bin/env python3
"""Validate immutable chains and optional static-analysis outputs."""
import argparse,hashlib,json,subprocess
from pathlib import Path
from config import IMAGE,PROFILES
REPO=Path(__file__).resolve().parents[3]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument("fixtures",type=Path);p.add_argument("--analysis",type=Path);p.add_argument("--output",type=Path,required=True);p.add_argument("--image",default=IMAGE);a=p.parse_args()
 if a.output.exists():p.error("output exists")
 checks=[];failures=[];manifests=list(a.fixtures.glob("*/depth-*/manifest.json"))
 expected=len(PROFILES)*4
 if len(manifests)!=expected:failures.append(f"expected {expected} fixture manifests, found {len(manifests)}")
 for path in manifests:
  d=path.parent;m=json.loads(path.read_text());depth=m["depth_including_root"]
  required=["root.pem","root.key","server.pem","server.key","server-chain.pem","intermediates.pem"]+[f"{x}.der" for x in ["root","server"]+[f"intermediate-{i}" for i in range(1,depth-1)]]
  for name in required:
   if not (d/name).is_file():failures.append(str(d/name)+" missing")
  for name,digest in m["files_sha256"].items():
   if not (d/name).is_file() or sha(d/name)!=digest:failures.append(str(d/name)+" hash mismatch")
  pem=(d/"server-chain.pem").read_text();count=pem.count("-----BEGIN CERTIFICATE-----")
  if count!=depth-1:failures.append(f"{d}: transmitted chain count {count}, expected {depth-1}")
  if (d/"root.pem").read_text() in pem:failures.append(f"{d}: root included in transmitted chain")
  observed=[]
  for name,item in m.get("certificate_checks",{}).items():
   if not item.get("key_matches_certificate"):failures.append(f"{d}/{name}: private/public key mismatch")
   if not item.get("signature_algorithms"):failures.append(f"{d}/{name}: missing signature algorithm evidence")
   else:observed.append(item["signature_algorithms"][-1].lower().replace("-","").replace("_",""))
  if len(set(observed))>1:failures.append(f"{d}: mixed certificate signature algorithms: {observed}")
  cmd=["docker","run","--rm","-v",f"{d.resolve()}:/fixture:ro","--entrypoint","/opt/openssl/bin/openssl",a.image,"verify","-CAfile","/fixture/root.pem","-verify_hostname","server"]
  if depth>2:cmd += ["-untrusted","/fixture/intermediates.pem"]
  cmd += ["/fixture/server.pem"];r=subprocess.run(cmd,capture_output=True,text=True)
  if r.returncode:failures.append(f"{d}: chain verification failed: {r.stderr.strip()}")
  checks.append({"fixture":str(d),"profile":m["profile"],"depth":depth,"transmitted_certificates":count,"root_transmitted":False,"hashes_checked":len(m["files_sha256"]),"chain_valid":r.returncode==0})
 if a.analysis:
  for name in ["key_sizes.csv","certificate_sizes.csv","chain_sizes.csv","mtc_sizes.csv","crossover.csv","analysis.json","manifest.json"]:
   if not (a.analysis/name).is_file():failures.append(str(a.analysis/name)+" missing")
 report={"passed":not failures,"fixture_count":len(manifests),"checks":checks,"failures":failures,"limitations":["TLS negotiation gates are enforced by the measurement parser after a manually launched functional run","MTC proof validation remains in the preserved scaling campaign structural validator"]};a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2)+"\n");print("PASS" if not failures else "FAIL",a.output)
 if failures:raise SystemExit(1)
if __name__=="__main__":main()
