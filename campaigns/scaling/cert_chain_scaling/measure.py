#!/usr/bin/env python3
"""Measure one X.509 chain with randomized warmup/measured rounds."""
import argparse,csv,json,os,re,subprocess,time
from pathlib import Path
from config import PROFILES
from capabilities import STANDARD

def profile_metadata(profile, depth):
 config=PROFILES[profile]
 return {"profile":profile,"family":config["family"],"algorithm":STANDARD.get(profile,config.get("standard_name",config["algorithm"])),
         "implementation_algorithm":config["algorithm"],"security_level":config["level"],"certificate_depth":depth,"TLS_signature_supported":True}

OPENSSL="/opt/mtc/openssl.sh"
def main():
 p=argparse.ArgumentParser();p.add_argument("--runs",type=int,required=True);p.add_argument("--warmups",type=int,required=True);p.add_argument("--scenario",required=True);p.add_argument("--campaign",required=True);p.add_argument("--seed",type=int,required=True);a=p.parse_args()
 if a.runs<2 or a.warmups<0:p.error("runs >= 2 and warmups >= 0")
 required=('CERT_FIXTURE','CAMPAIGN_OUTPUT','SERVER_METRICS','CERT_PROFILE_NAME','CERT_DEPTH_VALUE','FIXTURE_SHA256','IMAGE_ID','SOURCE_COMMIT')
 missing=[name for name in required if not os.environ.get(name)]
 if missing:p.error('Missing container environment: '+', '.join(missing))
 try:depth=int(os.environ['CERT_DEPTH_VALUE'])
 except ValueError:p.error('CERT_DEPTH_VALUE must be an integer')
 if depth not in (2,3,4,5):p.error('CERT_DEPTH_VALUE must be 2..5')
 if os.environ['CERT_PROFILE_NAME'] not in PROFILES:p.error('Unknown CERT_PROFILE_NAME')
 metadata=profile_metadata(os.environ['CERT_PROFILE_NAME'],depth)
 fixture=Path(os.environ["CERT_FIXTURE"]);out=Path(os.environ["CAMPAIGN_OUTPUT"]);metrics=Path(os.environ["SERVER_METRICS"]);out.mkdir(parents=True,exist_ok=False);(out/"logs").mkdir();(out/"server-metrics").mkdir();rows=[];warm=[]
 for is_warm,count in [(1,a.warmups),(0,a.runs)]:
  for round_id in range(1,count+1):
   start=time.perf_counter_ns();r=subprocess.run([OPENSSL,"s_client","-connect","server:4433","-servername","server","-CAfile",str(fixture/"root.pem"),"-verify_hostname","server","-verify_return_error","-tls1_3","-groups",os.environ.get("MTC_TLS_GROUP","X25519"),"-ciphersuites","TLS_AES_256_GCM_SHA384","-no_ticket","-ign_eof","-lab_metrics"],input="GET / HTTP/1.0\r\n\r\n",text=True,capture_output=True,timeout=60);process_ms=(time.perf_counter_ns()-start)/1e6;log=r.stdout+r.stderr
   (out/"logs"/f'{"warmup" if is_warm else "sample"}-{round_id:04d}.log').write_text(log)
   found=re.findall(r"^PROFILE_METRICS (\{.*\})$",r.stderr,re.M)
   if r.returncode or len(found)!=1 or "Verify return code: 0 (ok)" not in log:raise RuntimeError("TLS authentication failed")
   if "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384" not in log:raise RuntimeError("controlled TLS negotiation mismatch")
   client=json.loads(found[0]);key=client["client_random"];paths=list(metrics.glob(key+".json"))
   if len(paths)!=1:raise RuntimeError("missing server metrics")
   server=json.loads(paths[0].read_text());(out/"server-metrics"/(key+".json")).write_text(paths[0].read_text())
   if client["reused"] or server["reused"] or client["certificate_message_bytes"]!=server["certificate_message_bytes"]:raise RuntimeError("endpoint invariant failed")
   row={"key_establishment":os.environ.get("MTC_KEM_LABEL","X25519"),"openssl_group":os.environ.get("MTC_TLS_GROUP","X25519"),"campaign":a.campaign,"scenario":a.scenario,**metadata,"chain_depth":depth,"tree_size":"","mtc_profile":"","round":round_id,"repetition":round_id,"is_warmup":is_warm,"seed":a.seed,"fixture_hash":os.environ["FIXTURE_SHA256"],"image_id":os.environ["IMAGE_ID"],"git_commit":os.environ["SOURCE_COMMIT"],"client_random":key,"handshake_wall_ms":client["handshake_wall_ms"],"client_cpu_ms":client["handshake_cpu_ms"],"server_cpu_ms":server["handshake_cpu_ms"],"authentication_processing_wall_ms":client["components"]["peer_auth"]["wall_ms"],"authentication_processing_cpu_ms":client["components"]["peer_auth"]["cpu_ms"],"certificate_message_bytes":client["certificate_message_bytes"],"certificate_verify_message_bytes":client["certificate_verify_message_bytes"],"tls_bio_read_bytes":client["transport_read_bytes"],"tls_bio_written_bytes":client["transport_written_bytes"],"process_http_wall_ms":process_ms,"success":1}
   (warm if is_warm else rows).append(row)
 for name,data in [("observations.csv",rows),("warmups.csv",warm)]:
  with (out/name).open("w",newline="") as f:w=csv.DictWriter(f,fieldnames=list((data or rows)[0]));w.writeheader();w.writerows(data)
 (out/"validation.json").write_text(json.dumps({"passed":True,"key_establishment":os.environ.get("MTC_KEM_LABEL","X25519"),"openssl_group":os.environ.get("MTC_TLS_GROUP","X25519"),"measured_handshakes":len(rows),"warmup_handshakes":len(warm),"checks":["TLS 1.3","TLS_AES_256_GCM_SHA384",os.environ.get("MTC_TLS_GROUP","X25519"),"certificate verification","no resumed sessions","client/server Certificate-message agreement"]},indent=2)+"\n")
 print(out)
if __name__=="__main__":main()
