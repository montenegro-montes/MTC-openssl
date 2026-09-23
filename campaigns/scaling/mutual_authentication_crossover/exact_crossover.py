#!/usr/bin/env python3
"""Calculate exact mutual-authentication size crossovers from client/server anchors."""
import argparse,csv,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[2]
sys.path.insert(0,str(REPO/'campaigns/scaling/cert_chain_scaling'))
from landmark_size_model import audit,intervals,model

def rows(path):
 with path.open(newline='') as f:return list(csv.DictReader(f))
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--analysis',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if a.output.exists():p.error('output exists')
 baselines=rows(a.analysis/'x509-baselines.csv');result=[]
 for base in baselines:
  profile=base['profile'];target=int(base['certificate_total_bytes']);tbss=[]
  for role in ('server','client'):
   raw=(a.fixtures/f'{role}-mtc'/'batch16'/profile/'landmark-0000.der').read_bytes();tbss.append(audit(raw,16)[0])
  crossing=None
  for first,last,_ in intervals():
   total=sum(model(tbs,first)['tls_certificate_message_bytes'] for tbs in tbss)
   if total>=target:
    previous=sum(model(tbs,first-1)['tls_certificate_message_bytes'] for tbs in tbss) if first>1 else None
    crossing=(first,previous,total);break
  n,previous,total=crossing
  result.append({'profile':profile,'chain_profile':base['chain_profile'],'x509_certificate_total_bytes':target,'crossover_N':n,'n_before':n-1 if n>1 else '','mtc_total_bytes_before':previous if previous is not None else '','mtc_total_bytes_at_crossover':total,'difference_bytes':total-target,'native_auditable':1<n<=1024,'model':'server MTC Certificate bytes + client MTC Certificate bytes'})
 a.output.mkdir(parents=True);fields=list(result[0])
 with (a.output/'mutual-crossover-exact.csv').open('x',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(result)
 (a.output/'mutual-crossover-exact.json').write_text(json.dumps({'rows':result,'native_limit':1024},indent=2)+'\n');print(a.output)
if __name__=='__main__':main()
