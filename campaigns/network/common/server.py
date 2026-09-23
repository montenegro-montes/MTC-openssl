#!/usr/bin/env python3
"""Persistent X.509 and MTC endpoints for one profile and authentication mode."""
import os,signal,subprocess,time
from pathlib import Path
OPENSSL='/opt/mtc/openssl.sh';PROFILE=os.environ['NETWORK_PROFILE'];MODE=os.environ.get('NETWORK_AUTH_MODE','single');MTC_ID=os.environ['NETWORK_MTC_ID']
metrics=Path(os.environ['MEASUREMENT_RUN_ROOT'])/os.environ['MEASUREMENT_CAMPAIGN_ID']/'server-metrics';metrics.mkdir(parents=True,exist_ok=True)
common=['-tls1_3','-groups',os.environ.get('MTC_TLS_GROUP','X25519'),'-ciphersuites','TLS_AES_256_GCM_SHA384','-num_tickets','0','-www','-lab_metrics']
if MODE=='single':
 root=f"/repo/{os.environ['NETWORK_SINGLE_ROOT']}";pop=f'{root}/population/{PROFILE}';mtc=f'{root}/batch16/mtc/{PROFILE}';key=f'{pop}/0.key';cases=[(4433,f'{pop}/0.pem',key,[]),(4434,f'{mtc}/landmark-0000.pem',key,['-mtc_id',MTC_ID]),(4435,f'{mtc}/standalone-0000.pem',key,['-mtc_id',MTC_ID.rsplit('.',3)[0]])]
elif MODE=='mutual':
 base=f"/repo/{os.environ['NETWORK_MUTUAL_ROOT']}";sx=f"/repo/{os.environ['NETWORK_MUTUAL_SERVER_X509']}/{PROFILE}/ca-server";cx=f'{base}/client-x509/{PROFILE}/ca-server';sm=f'{base}/server-mtc/batch16/{PROFILE}';cm=f'{base}/client-mtc/batch16/{PROFILE}';key=f'{base}/server-mtc-source/{PROFILE}/server-0000.key'
 cases=[(4433,f'{sx}/server.pem',f'{sx}/server.key',['-CAfile',f'{cx}/ca.pem','-Verify','1','-verify_return_error']),(4434,f'{sm}/landmark-0000.pem',key,['-mtc_id',MTC_ID,'-mtc_client_trust',f'{cm}/trust.bin','-mtc_landmark','-Verify','1','-verify_return_error']),(4435,f'{sm}/standalone-0000.pem',key,['-mtc_id',MTC_ID.rsplit('.',3)[0],'-mtc_client_trust',f'{cm}/authority.bin','-Verify','1','-verify_return_error'])]
else:raise SystemExit(f'unsupported NETWORK_AUTH_MODE: {MODE}')
env=os.environ.copy();env['PROFILE_METRICS_DIR']=str(metrics);processes=[subprocess.Popen([OPENSSL,'s_server','-accept',str(port),'-cert',cert,'-key',key,*extra,*common],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.STDOUT) for port,cert,key,extra in cases]
def stop(*_):
 for proc in processes:proc.terminate()
signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop);time.sleep(.5)
if any(p.poll() is not None for p in processes):raise SystemExit('network TLS endpoint failed to start')
Path('/tmp/measurement-ready').touch()
while all(p.poll() is None for p in processes):time.sleep(1)
stop();raise SystemExit('network TLS endpoint stopped unexpectedly')
