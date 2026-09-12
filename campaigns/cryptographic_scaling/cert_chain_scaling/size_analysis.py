#!/usr/bin/env python3
"""Measure real DER objects and model MTC sizes with the real -05 encoder."""
import argparse,csv,json,sys
from pathlib import Path
HERE=Path(__file__).resolve();REPO=HERE.parents[3];sys.path.insert(0,str(REPO/"src/mtc"))
from core import certificate,certificate_parts,cover,proof
from config import MTC_PROFILE_MAP,PROFILES
def write(path,rows,fields=None):
 fields=fields or list(rows[0]);path.parent.mkdir(parents=True,exist_ok=True)
 with path.open("w",newline="") as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
def cert_metrics(path):
 data=path.read_bytes();outer,_=certificate_parts(data);bit=outer[2][1]
 if not bit or bit[0]:raise ValueError(f"invalid certificate signature BIT STRING: {path}")
 return len(data),len(bit)-1
def tls_certificate_message_size(certs):
 # Handshake(4), certificate_request_context vector(1), certificate_list vector(3),
 # and, per CertificateEntry, cert_data vector(3) plus extensions vector(2).
 return 8+sum(len(x)+5 for x in certs)
def crossover_status(profile, fixtures_supplied, series, crossed):
 if profile not in MTC_PROFILE_MAP:return "UNSUPPORTED_MTC_PROFILE"
 if not fixtures_supplied:return "MTC_FIXTURES_NOT_PROVIDED"
 if not series:return "MISSING_MTC_FIXTURES"
 return "CROSSED" if crossed else "OUTSIDE_SEARCH_RANGE"
def main():
 p=argparse.ArgumentParser();p.add_argument("fixtures",type=Path);p.add_argument("--output",type=Path,required=True);p.add_argument("--mtc-fixtures",type=Path);p.add_argument("--max-tree-power",type=int,default=20);a=p.parse_args()
 if a.output.exists():p.error("Output exists; choose a new analysis directory")
 if not 0<=a.max_tree_power<=30:p.error("--max-tree-power must be 0..30")
 a.output.mkdir(parents=True);keys=[];certs=[];chains=[]
 for manifest in sorted(a.fixtures.glob("*/depth-*/manifest.json")):
  d=manifest.parent;m=json.loads(manifest.read_text());profile=m["profile"];depth=m["depth_including_root"]
  positions=["server"]+[f"intermediate-{i}" for i in range(depth-2,0,-1)]
  for position in ["root"]+[f"intermediate-{i}" for i in range(1,depth-1)]+["server"]:
   keys.append({"security_level":m["security_level"],"family":m["family"],"algorithm":profile,"depth":depth,"certificate_position":position,"private_key_der_bytes":(d/f"{position}-private.der").stat().st_size,"spki_der_bytes":(d/f"{position}-spki.der").stat().st_size})
   size,sig=cert_metrics(d/f"{position}.der");certs.append({"security_level":m["security_level"],"family":m["family"],"algorithm":profile,"depth":depth,"certificate_position":position,"certificate_der_bytes":size,"signature_bytes":sig})
  transmitted=[(d/f"{x}.der").read_bytes() for x in positions]
  chains.append({"security_level":m["security_level"],"family":m["family"],"algorithm":profile,"depth":depth,"transmitted_certificates":len(transmitted),"certificate_der_sum_bytes":sum(map(len,transmitted)),"certificate_entry_framing_bytes":5*len(transmitted),"tls_certificate_fixed_framing_bytes":8,"tls_certificate_message_bytes":tls_certificate_message_size(transmitted),"root_transmitted":False})
 write(a.output/"key_sizes.csv",keys);write(a.output/"certificate_sizes.csv",certs);write(a.output/"chain_sizes.csv",chains)
 mtc=[]
 if a.mtc_fixtures:
  for profile,family in MTC_PROFILE_MAP.items():
   candidates=sorted(a.mtc_fixtures.glob(f"**/mtc/{family}/landmark-0000.der"))
   if not candidates:continue
   for landmark in candidates:
    directory=landmark.parent;meta=json.loads((directory/"manifest.json").read_text());n=int(meta["tree_size"])
    for mode in ["landmark","standalone"]:
     actual=(directory/f"{mode}-0000.der").read_bytes();actual_outer,_=certificate_parts(actual);actual_proof=actual_outer[2][1][1:];proof_hashes=int(meta["sizes"][mode]["mtc_inclusion_proof_bytes"])//32
     mtc.append({"security_level":PROFILES[profile]["level"],"family":PROFILES[profile]["family"],"algorithm":profile,"mtc_profile":mode,"tree_size":n,"proof_hashes":proof_hashes,"inclusion_hash_bytes":32*proof_hashes,"encoded_proof_bytes":len(actual_proof),"certificate_der_bytes":len(actual),"tls_certificate_message_bytes":tls_certificate_message_size([actual]),"evidence":"measured fixture","seed_fixture":str(directory/f'{mode}-0000.der')})
   seed=candidates[-1].read_bytes();outer,_=certificate_parts(seed);tbs=outer[0][2]
   for power in range(a.max_tree_power+1):
    n=1<<power;start,end=cover(0,n)[0];proof_hashes=(end-start-1).bit_length();pbytes=proof(start,end,[bytes(32)]*proof_hashes);der=certificate(tbs,pbytes)
    mtc.append({"security_level":PROFILES[profile]["level"],"family":PROFILES[profile]["family"],"algorithm":profile,"mtc_profile":"landmark","tree_size":n,"proof_hashes":proof_hashes,"inclusion_hash_bytes":32*proof_hashes,"encoded_proof_bytes":len(pbytes),"certificate_der_bytes":len(der),"tls_certificate_message_bytes":tls_certificate_message_size([der]),"evidence":"exact serialization model","seed_fixture":str(candidates[-1])})
 write(a.output/"mtc_sizes.csv",mtc,["security_level","family","algorithm","mtc_profile","tree_size","proof_hashes","inclusion_hash_bytes","encoded_proof_bytes","certificate_der_bytes","tls_certificate_message_bytes","evidence","seed_fixture"])
 model_validation=[]
 for actual in [r for r in mtc if r["mtc_profile"]=="landmark" and r["evidence"]=="measured fixture"]:
  modeled=[r for r in mtc if r["algorithm"]==actual["algorithm"] and r["tree_size"]==actual["tree_size"] and r["evidence"]=="exact serialization model"]
  if len(modeled)!=1:raise RuntimeError("missing unique model row for measured MTC fixture")
  passed=modeled[0]["certificate_der_bytes"]==actual["certificate_der_bytes"] and modeled[0]["encoded_proof_bytes"]==actual["encoded_proof_bytes"]
  model_validation.append({"algorithm":actual["algorithm"],"tree_size":actual["tree_size"],"passed":passed,"measured_certificate_bytes":actual["certificate_der_bytes"],"modeled_certificate_bytes":modeled[0]["certificate_der_bytes"]})
  if not passed:raise RuntimeError(f"MTC serialization model mismatch for {actual['algorithm']} N={actual['tree_size']}")
 crossings=[]
 for chain in chains:
  series=[r for r in mtc if r["algorithm"]==chain["algorithm"] and r["mtc_profile"]=="landmark" and r["evidence"]=="exact serialization model"];target=chain["tls_certificate_message_bytes"]
  before=None;cross=None
  for row in series:
   if row["tls_certificate_message_bytes"]>=target:cross=row;break
   before=row
  status=crossover_status(chain["algorithm"],a.mtc_fixtures is not None,series,cross is not None)
  crossings.append({"security_level":chain["security_level"],"algorithm":chain["algorithm"],"x509_depth":chain["depth"],"x509_bytes":target,"mtc_previous_N":before["tree_size"] if before else "","mtc_previous_bytes":before["tls_certificate_message_bytes"] if before else "","mtc_cross_N":cross["tree_size"] if cross else "","mtc_cross_bytes":cross["tls_certificate_message_bytes"] if cross else "","proof_hashes":cross["proof_hashes"] if cross else "","difference_bytes":cross["tls_certificate_message_bytes"]-target if cross else "","status":status})
 write(a.output/"crossover.csv",crossings)
 metadata={"schema":1,"result_domain":"STATIC_CRYPTOGRAPHIC_CERTIFICATE","tls_support_required":False,"x509_fixture_root":str(a.fixtures),"mtc_fixture_root":str(a.mtc_fixtures) if a.mtc_fixtures else None,"model_validation":model_validation,"crossover_status_definitions":{"MTC_FIXTURES_NOT_PROVIDED":"Supported MTC profile; --mtc-fixtures was omitted","MISSING_MTC_FIXTURES":"Supported MTC profile; supplied directory has no matching landmark fixtures","UNSUPPORTED_MTC_PROFILE":"Profile is not implemented by the MTC issuer","CROSSED":"Model reaches or exceeds X.509 size within the search range","OUTSIDE_SEARCH_RANGE":"Available model does not cross within the search range"},"definitions":{"x509_bytes":"complete TLS 1.3 Certificate handshake message through CertificateEntry extensions; excludes CertificateVerify","mtc_bytes":"same TLS Certificate message boundary; landmark trust material is offline","modeled_mtc":"real DER and MTCProof encoders with deterministic 32-byte placeholder hashes; validated against supplied fixtures"}}
 (a.output/"analysis.json").write_text(json.dumps(metadata,indent=2)+"\n");(a.output/"manifest.json").write_text(json.dumps(metadata,indent=2)+"\n")
 print(a.output)
if __name__=="__main__":main()
