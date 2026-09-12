#!/usr/bin/env python3
"""Record actual image capabilities separately for crypto and TLS. No handshakes."""
import argparse
import json
from pathlib import Path
import subprocess
from config import IMAGE, PROFILES
from capabilities import support_table, write_support, fixture_evidence

REPO=Path(__file__).resolve().parents[3]
PROBE=r'''
import json,subprocess,re
from pathlib import Path
binary='/opt/openssl/bin/openssl'
def cmd(*args):
 p=subprocess.run([binary,*args],capture_output=True,text=True)
 return {'stdout':p.stdout,'stderr':p.stderr,'returncode':p.returncode}
outputs={k:cmd(*v) for k,v in {'openssl':['version','-a'],'providers':['list','-providers'],
 'signature_algorithms':['list','-signature-algorithms'],
 'tls_signature_algorithms':['list','-tls-signature-algorithms'],
 'key_algorithms':['list','-public-key-algorithms']}.items()}
commits={name:Path(path).read_text().strip() for name,path in {
 'openssl':'/opt/openssl/SOURCE_COMMIT','liboqs':'/opt/oqs/SOURCE_COMMIT',
 'oqs_provider':'/opt/oqs/PROVIDER_COMMIT'}.items()}
versions={}
for name,path,pattern in [('liboqs','/opt/oqs/include/oqs/oqsconfig.h',r'OQS_VERSION_TEXT\s+"([^"]+)"'),
 ('oqs_provider','/opt/src/oqs-provider/CMakeLists.txt',r'project\(oqsprovider\s+VERSION\s+([^\s\)]+)')]:
 text=Path(path).read_text() if Path(path).exists() else ''
 match=re.search(pattern,text,re.I);versions[name]=match.group(1) if match else None
provider_version=re.search(r'oqsprovider\s*\n(?:(?!\n\s{2}\S).)*?version:\s*([^\n]+)',outputs['providers']['stdout'],re.S)
if provider_version:versions['oqs_provider']=provider_version.group(1).strip()
versions['openssl']=outputs['openssl']['stdout'].splitlines()[0]
print(json.dumps({'outputs':outputs,'source_commits':commits,'versions':versions}))
'''


def inspect(image):
    info=json.loads(subprocess.check_output(['docker','image','inspect',image],text=True))[0]
    # Pin all capability probes to the inspected ID, not a mutable tag.
    probe=json.loads(subprocess.check_output(['docker','run','--rm','--network','none',
                     '--entrypoint','python3',info['Id'],'-c',PROBE],text=True))
    failed=[name for name,item in probe['outputs'].items() if item['returncode']]
    if failed:raise ValueError('Capability commands failed: '+', '.join(failed))
    data={'schema':2,'image':info,'image_id':info['Id'],**probe,'configured_profiles':PROFILES,
          'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),
          'source_status':subprocess.check_output(['git','status','--porcelain'],cwd=REPO,text=True),
          'source_hashes':{}}
    import hashlib
    data['source_hashes']={str(p.relative_to(REPO)):hashlib.sha256(p.read_bytes()).hexdigest()
                          for p in Path(__file__).parent.glob('*.py')}
    data.update({k:v['stdout'] for k,v in probe['outputs'].items()})
    data['algorithm_support']=support_table(data['signature_algorithms'],data['tls_signature_algorithms'],data['key_algorithms'])
    data['missing_algorithms']=[r['profile'] for r in data['algorithm_support'] if not r['signature_supported']]
    return data


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--fixtures',type=Path,help='Optional existing hash-valid fixture manifests as X.509 evidence');parser.add_argument('--support-output',type=Path);parser.add_argument('--image',default=IMAGE)
    args=parser.parse_args();table=args.support_output or args.output.with_name(args.output.stem+'-algorithm_support.csv')
    if args.output.exists() or table.exists():parser.error('output exists')
    data=inspect(args.image)
    if args.fixtures:data['algorithm_support']=fixture_evidence(data['algorithm_support'],args.fixtures,data['openssl'],data['image_id'])
    args.output.parent.mkdir(parents=True,exist_ok=True);table.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as f:json.dump(data,f,indent=2);f.write('\n')
    write_support(table,data['algorithm_support']);print(args.output);print(table)
    if data['missing_algorithms']:raise SystemExit('Missing cryptographic algorithms: '+', '.join(data['missing_algorithms']))

if __name__=='__main__':main()
