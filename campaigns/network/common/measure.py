#!/usr/bin/env python3
"""Paired X.509/MTC measurements for one profile and authentication mode."""
import argparse,csv,json,os,random,re,subprocess
from pathlib import Path
SINGLE=['x509-simple','mtc-single-landmark','mtc-single-standalone'];MUTUAL=['x509-mutual','mtc-mutual-landmark','mtc-mutual-standalone'];ALL=SINGLE+MUTUAL
PORTS={name:4433+i%3 for i,name in enumerate(ALL)};OPENSSL='/opt/mtc/openssl.sh'
FAILURE_FIELDS=['campaign_id','profile','authentication','round_id','seed','scenario','order_in_round','is_warmup','success','failure_reason','timeout','TLS_error','returncode']
def write(path,data):
 if not data:return
 with path.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(data[0]));w.writeheader();w.writerows(data)
def write_failures(path,data):
 with path.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=FAILURE_FIELDS);w.writeheader();w.writerows(data)
def client_args(host,scenario,profile,mode):
 args=[OPENSSL,'s_client','-connect',f'{host}:{PORTS[scenario]}','-servername','server','-verify_hostname','server','-verify_return_error','-no_ticket','-ign_eof','-tls1_3','-groups',os.environ.get('MTC_TLS_GROUP','X25519'),'-ciphersuites','TLS_AES_256_GCM_SHA384','-lab_metrics']
 variant=scenario.rsplit('-',1)[-1] if scenario.startswith('mtc-') else ''
 if mode=='single':
  root=f"/repo/{os.environ['NETWORK_SINGLE_ROOT']}";pop=f'{root}/population/{profile}';mtc=f'{root}/batch16/mtc/{profile}'
  if scenario.startswith('mtc-'):
   args+=['-mtc_trust',f'{mtc}/{"trust.bin" if variant=="landmark" else "authority.bin"}']
   if variant=='landmark':args+=['-mtc_landmark']
  else:args+=['-CAfile',f'{pop}/ca.pem']
 else:
  base=f"/repo/{os.environ['NETWORK_MUTUAL_ROOT']}";sx=f"/repo/{os.environ['NETWORK_MUTUAL_SERVER_X509']}/{profile}/ca-server";cx=f'{base}/client-x509/{profile}/ca-server';sm=f'{base}/server-mtc/batch16/{profile}';cm=f'{base}/client-mtc/batch16/{profile}'
  if scenario.startswith('mtc-'):
   args+=['-mtc_trust',f'{sm}/{"trust.bin" if variant=="landmark" else "authority.bin"}','-cert',f'{cm}/{variant}-0000.pem','-key',f'{cx}/client-0000.key','-mtc_client_id',os.environ['NETWORK_MTC_ID'] if variant=='landmark' else os.environ['NETWORK_MTC_ID'].rsplit('.',3)[0]]
   if variant=='landmark':args+=['-mtc_landmark']
  else:args+=['-CAfile',f'{sx}/root.pem','-cert',f'{cx}/client-0000.pem','-key',f'{cx}/client-0000.key']
 return args
def main():
 p=argparse.ArgumentParser();p.add_argument('--runs',type=int,required=True);p.add_argument('--warmup',type=int,required=True);p.add_argument('--seed',type=int,required=True);p.add_argument('--image-id',required=True);p.add_argument('--scenarios',nargs='+',choices=ALL,required=True);p.add_argument('--host',default='server');a=p.parse_args()
 profile=os.environ['NETWORK_PROFILE'];mode=os.environ.get('NETWORK_AUTH_MODE','single');expected=SINGLE if mode=='single' else MUTUAL
 if a.scenarios!=expected:raise SystemExit(f'{mode} requires scenarios: {expected}')
 out=Path(os.environ['MEASUREMENT_RUN_ROOT'])/os.environ['MEASUREMENT_CAMPAIGN_ID'];(out/'logs').mkdir(parents=True,exist_ok=True);rng=random.Random(a.seed);measured=[];warmups=[];failures=[];allow_failures=os.environ.get('NETWORK_ALLOW_FAILURES')=='1';write_failures(out/'failures.csv',failures)
 for warm,count in ((1,a.warmup),(0,a.runs)):
  for round_id in range(1,count+1):
   order=a.scenarios.copy();rng.shuffle(order)
   for position,scenario in enumerate(order,1):
    timed_out=False
    try:r=subprocess.run(client_args(a.host,scenario,profile,mode),input='GET / HTTP/1.0\r\n\r\n',text=True,capture_output=True,timeout=float(os.environ.get('HANDSHAKE_TIMEOUT_SECONDS','30')));log=r.stdout+r.stderr
    except subprocess.TimeoutExpired as e:r=None;timed_out=True;log=(e.stdout or '')+(e.stderr or '');log=log.decode(errors='replace') if isinstance(log,bytes) else log
    label='warmup' if warm else 'sample';(out/'logs'/f'{label}-{round_id-1:04d}-{scenario}.log').write_text(log);found=re.findall(r'^PROFILE_METRICS (\{.*\})$',log,re.M)
    valid=r is not None and not r.returncode and len(found)==1 and 'Verify return code: 0 (ok)' in log and (not scenario.startswith('mtc-') or 'MTC verification: OK' in log)
    if not valid:
     reason='timeout' if timed_out else ('missing_native_metrics' if len(found)!=1 else 'tls_verification_failed');failures.append({'campaign_id':os.environ['MEASUREMENT_CAMPAIGN_ID'],'profile':profile,'authentication':mode,'round_id':round_id,'seed':a.seed,'scenario':scenario,'order_in_round':position,'is_warmup':warm,'success':0,'failure_reason':reason,'timeout':int(timed_out),'TLS_error':log[-1000:].replace('\n',' '),'returncode':'' if r is None else r.returncode});write_failures(out/'failures.csv',failures)
     if allow_failures:continue
     raise RuntimeError(f'{scenario}: TLS measurement failed ({reason})')
    m=json.loads(found[0]);components=m.get('components',{});mtc=components.get('peer_auth',{}).get('mtc',{}) if isinstance(components.get('peer_auth'),dict) else {}
    row={'campaign_id':os.environ['MEASUREMENT_CAMPAIGN_ID'],'profile':profile,'authentication':mode,'key_establishment':os.environ.get('MTC_KEM_LABEL','X25519'),'openssl_group':os.environ.get('MTC_TLS_GROUP','X25519'),'round':round_id-1,'round_id':round_id,'order':position-1,'order_in_round':position,'scenario_order':position,'scenario':scenario,'tree_size':16,'seed':a.seed,'is_warmup':warm,'client_random':m['client_random'],'handshake_wall_ms':m['handshake_wall_ms'],'handshake_client_cpu_ms':m['handshake_cpu_ms'],'certificate_message_bytes':m['certificate_message_bytes'],'certificate_verify_bytes':m['certificate_verify_message_bytes'],'transport_read_bytes':m['transport_read_bytes'],'transport_written_bytes':m['transport_written_bytes'],'transport_total_bytes':m['transport_read_bytes']+m['transport_written_bytes'],'mtc_proof_encoded_bytes':mtc.get('proof_encoded_bytes',0),'mtc_signature_bytes':mtc.get('signature_bytes',0),'mtc_inclusion_proof_bytes':mtc.get('inclusion_proof_bytes',0),'image_id':a.image_id,'success':1}
    (warmups if warm else measured).append(row);write(out/('warmups.csv' if warm else 'samples.csv'),warmups if warm else measured)
 print(out)
if __name__=='__main__':main()
