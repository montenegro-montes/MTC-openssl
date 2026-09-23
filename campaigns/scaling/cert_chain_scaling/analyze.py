#!/usr/bin/env python3
import argparse,csv,random,statistics,json
from capabilities import load_support, write_support
from result_state import validate_complete,cell_name
from config import PROFILES
from pathlib import Path
def collect(root,environment):
 manifest=json.loads((root/"manifest.json").read_text())
 hashes=json.loads((root/"fixture_hashes.json").read_text())
 support=load_support(environment);caps={r['profile']:r for r in support}
 image_id=environment.get('image_id') or environment['image']['Id']
 if image_id!=manifest['image_id']:raise ValueError('Analysis capability image differs from measurements')
 manifest['accepted_source_commits']=[json.loads(f.read_text())['git_commit'] for f in root.glob('resume/*/execution.json')]
 rows=[];excluded=[]
 for cell in manifest['cells']:
  profile,depth,index=(cell[k] for k in ('profile','depth','campaign'));name=cell_name(profile,depth,index)
  if not caps[profile]['tls_experiment_enabled']:
   excluded.append({**cell,'status':'SKIPPED_UNSUPPORTED_TLS','reason':caps[profile]['reason']});continue
  key=f'{profile}/depth-{depth}/manifest.json'
  candidates=[root/name,*sorted(root.glob('resume/*/cells/'+name))];complete=[]
  for directory in candidates:
   state,errors=validate_complete(directory,profile,depth,index,manifest,hashes.get(key,''))
   if state=='COMPLETE':complete.append(directory)
   elif state=='INVALID_INCOMPLETE':excluded.append({**cell,'directory':str(directory),'status':state,'reason':str(errors)})
  if len(complete)>1:raise ValueError('Duplicate completed cell: '+name)
  if not complete:
   excluded.append({**cell,'status':'MISSING_ELIGIBLE_TLS'});continue
  with (complete[0]/'data/observations.csv').open() as f:
   for row in csv.DictReader(f):
    # Enrich derived analysis only. Never rewrite legacy rows with blank metadata.
    cap=caps[profile]
    row.update(profile=profile,family=cap['family'],algorithm=cap['algorithm'],security_level=cap['security_level'],TLS_signature_supported=True)
    rows.append(row)
 return rows,excluded,support

def main():
 p=argparse.ArgumentParser();p.add_argument("root",type=Path);p.add_argument('--environment',type=Path);p.add_argument('--output',type=Path);a=p.parse_args()
 environment=json.loads((a.environment or a.root/'environment.json').read_text())
 rows,excluded,support=collect(a.root,environment)
 target=a.output or a.root/'summary.csv';meta=target.with_suffix('.json');table=target.with_name(target.stem+'-algorithm_support.csv')
 if any(x.exists() for x in (target,meta,table)):p.error('Analysis output exists; choose another --output')
 if not rows:raise SystemExit("No complete eligible TLS observations; unsupported/missing cells are not zero-valued results")
 metrics=["handshake_wall_ms","client_cpu_ms","server_cpu_ms","authentication_processing_wall_ms","authentication_processing_cpu_ms","certificate_message_bytes","certificate_verify_message_bytes","tls_bio_read_bytes","tls_bio_written_bytes"]
 output=[]
 for scenario in sorted({r["scenario"] for r in rows}):
  group=[r for r in rows if r["scenario"]==scenario];entry={"result_domain":"TLS_PERFORMANCE","scenario":scenario,"profile":group[0]["profile"],"family":group[0]["family"],"algorithm":group[0]["algorithm"],"security_level":group[0]["security_level"],"TLS_signature_supported":True,"n":len(group),"campaigns":len({r["campaign"] for r in group})}
  for metric in metrics:
   values=[statistics.median(float(r[metric]) for r in group if r["campaign"]==c) for c in sorted({r["campaign"] for r in group})];entry[metric+"_median_of_campaign_medians"]=statistics.median(values)
   if len(values)>=2:
    rng=random.Random(73001);boot=sorted(statistics.median(rng.choices(values,k=len(values))) for _ in range(2000));entry[metric+"_bootstrap95_low"]=boot[49];entry[metric+"_bootstrap95_high"]=boot[1949]
   else:entry[metric+"_bootstrap95_low"]="";entry[metric+"_bootstrap95_high"]=""
  output.append(entry)
 with target.open("x",newline="") as f:w=csv.DictWriter(f,fieldnames=list(output[0]));w.writeheader();w.writerows(output)
 write_support(table,support)
 with meta.open('x') as f:json.dump({'result_domain':'TLS_PERFORMANCE','excluded_cells':excluded,'image_id':environment.get('image_id') or environment['image']['Id'],
   'caption':'Only complete cells supported by the recorded TLS stack are summarized. Unsupported signature schemes have no timing observation; static certificate results are separate.'},f,indent=2)
 print(target)
if __name__=="__main__":main()
