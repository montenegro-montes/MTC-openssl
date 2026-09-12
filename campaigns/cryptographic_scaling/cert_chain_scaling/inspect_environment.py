#!/usr/bin/env python3
import argparse,json,subprocess
from config import IMAGE,PROFILES
def command(image,*args):return subprocess.check_output(["docker","run","--rm","--entrypoint","/opt/openssl/bin/openssl",image,*args],text=True)
def image_file(image,path):return subprocess.check_output(["docker","run","--rm","--entrypoint","cat",image,path],text=True).strip()
def main():
 p=argparse.ArgumentParser();p.add_argument("--output",required=True);p.add_argument("--image",default=IMAGE);a=p.parse_args();algorithms=command(a.image,"list","-signature-algorithms");providers=command(a.image,"list","-providers");missing=[v["algorithm"] for v in PROFILES.values() if v["algorithm"] not in algorithms and v["algorithm"]!="EC"]
 data={"image":json.loads(subprocess.check_output(["docker","image","inspect",a.image],text=True))[0],"openssl":command(a.image,"version","-a"),"versions":{"openssl":"3.5.8","liboqs":"0.14.0","oqs_provider":"0.10.0"},"source_commits":{"openssl":image_file(a.image,"/opt/openssl/SOURCE_COMMIT"),"liboqs":image_file(a.image,"/opt/oqs/SOURCE_COMMIT"),"oqs_provider":image_file(a.image,"/opt/oqs/PROVIDER_COMMIT")},"providers":providers,"signature_algorithms":algorithms,"configured_profiles":PROFILES,"missing_algorithms":missing}
 from pathlib import Path
 out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True)
 if out.exists():p.error("output exists")
 out.write_text(json.dumps(data,indent=2)+"\n");print(out)
 if missing:raise SystemExit("Missing required algorithms: "+", ".join(missing))
if __name__=="__main__":main()
