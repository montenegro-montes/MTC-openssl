#!/usr/bin/env python3
"""Immutable preparation gate shared by current network campaigns."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
REPO=Path(__file__).resolve().parents[3]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def fixture_roots():
 profile=os.environ['NETWORK_PROFILE'];mode=os.environ['NETWORK_AUTH_MODE']
 if mode=='single':
  root=REPO/os.environ['NETWORK_SINGLE_ROOT'];return [root/'population'/profile,root/'batch16/mtc'/profile]
 if mode=='mutual':
  root=REPO/os.environ['NETWORK_MUTUAL_ROOT'];server=REPO/os.environ['NETWORK_MUTUAL_SERVER_X509'];return [server/profile/'ca-server',root/'client-x509'/profile/'ca-server',root/'server-mtc-source'/profile,root/'server-mtc'/'batch16'/profile,root/'client-mtc'/'batch16'/profile]
 raise SystemExit('NETWORK_AUTH_MODE must be single or mutual')
def inputs():
 roots=fixture_roots();missing=[str(p) for p in roots if not p.is_dir()]
 if missing:raise SystemExit('missing network fixture input: '+missing[0])
 return sorted(p for root in roots for p in root.rglob('*') if p.is_file())
def main():
 p=argparse.ArgumentParser();p.add_argument('action',choices=['init','tests','audit']);p.add_argument('root',type=Path);p.add_argument('--experiment',required=True);a=p.parse_args();root=a.root.resolve()
 if not root.is_relative_to(REPO/'artifacts/results'):raise SystemExit('root must be below artifacts/results')
 if a.action=='init':
  if root.exists():raise SystemExit('output exists')
  root.mkdir(parents=True);files=inputs();sources=[p for base in (REPO/'campaigns/network',REPO/'docker/network',REPO/'bin/network') for p in base.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'];save(root/'fixture-sha256.json',{str(f):sha(f) for f in files});save(root/'baseline-source-sha256.json',{str(f.relative_to(REPO)):sha(f) for f in sorted(sources)});save(root/'metadata.json',{'experiment':a.experiment,'profile':os.environ['NETWORK_PROFILE'],'authentication':os.environ['NETWORK_AUTH_MODE'],'key_establishment':os.environ.get('MTC_KEM_LABEL','X25519'),'openssl_group':os.environ.get('MTC_TLS_GROUP','X25519'),'scenarios':['x509','mtc-landmark','mtc-standalone'],'status':'PREPARED_NOT_EXECUTED'});print(root);return
 for name in ('fixture-sha256.json','baseline-source-sha256.json'):
  for path,digest in json.loads((root/name).read_text()).items():
   file=Path(path) if Path(path).is_absolute() else REPO/path
   if not file.is_file() or sha(file)!=digest:raise SystemExit('preservation mismatch: '+path)
 if a.action=='tests':
  image=json.loads(subprocess.check_output(['docker','image','inspect','mt-tls-network:local'],text=True))[0]['Id'];save(root/'tests-status.json',{'passed':True,'key_establishment':os.environ.get('MTC_KEM_LABEL','X25519'),'openssl_group':os.environ.get('MTC_TLS_GROUP','X25519'),'scope':'fixture/source preservation and image availability; no TLS executed','image_id':image});print(root/'tests-status.json')
 else:print('PASS',root)
if __name__=='__main__':main()
