#!/usr/bin/env python3
"""Execute N-1/N mutual-authentication checks for exact crossover boundaries."""
import argparse,csv,json,os,statistics,subprocess,sys
from html import escape
from pathlib import Path
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[2]
def rows(path):
 with path.open(newline='') as f:return list(csv.DictReader(f))
def call(cmd,env=None):print('+',' '.join(map(str,cmd)),flush=True);subprocess.run(list(map(str,cmd)),cwd=REPO,env=env,check=True)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--exact',type=Path,required=True);p.add_argument('--source-fixtures',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--runs',type=int,default=30);p.add_argument('--warmups',type=int,default=5);p.add_argument('--image',default='mt-tls-mtc-mutual:local');p.add_argument('--execute',action='store_true');a=p.parse_args()
 exact=rows(a.exact/'mutual-crossover-exact.csv');targets={}
 for row in exact:
  if row['native_auditable'].lower()=='true':
   n=int(row['crossover_N']);targets.setdefault(row['profile'],set()).update((n-1,n))
 targets={k:sorted(v) for k,v in targets.items()};plan={'profiles':targets,'runs':a.runs,'warmups':a.warmups,'comparison':'server Certificate + client Certificate'};print(json.dumps(plan,indent=2))
 if not a.execute:return
 if a.output.exists():p.error('output exists')
 a.output.mkdir(parents=True);(a.output/'plan.json').write_text(json.dumps(plan,indent=2)+'\n');fixtures=a.output/'fixtures';raw=a.output/'raw';fixtures.mkdir()
 source=a.source_fixtures.resolve()
 if not source.is_relative_to(REPO):raise SystemExit('source fixtures must be below repository root')
 for profile,sizes in targets.items():
  for n in sizes:
   for role in ('server','client'):
    out=f'/output/fixtures/{role}-mtc/batch{n}/{profile}'
    call(['docker','run','--rm','-e','PYTHONPATH=/repo/src/mtc','-e','MUTUAL_CROSSOVER_FIXTURES=/output/fixtures','-e',f'MUTUAL_CROSSOVER_SOURCE_ROOT=/repo/{source.relative_to(REPO)}','-v',f'{REPO}:/repo:ro','-v',f'{a.output.resolve()}:/output','-w','/repo','--entrypoint','python3',a.image,f'campaigns/scaling/mutual_authentication_crossover/prepare_{role}_mtc.py','--profile',profile,'--n',n,'--output',out])
  env=os.environ.copy();env['MUTUAL_CROSSOVER_FIXTURES']=str(fixtures);env['MUTUAL_CROSSOVER_SOURCE_ROOT']=str(source)
  cmd=[sys.executable,HERE/'run.py','--root',raw/profile,'--profile',profile,'--mtc-only','--runs',a.runs,'--warmups',a.warmups]
  for n in sizes:cmd.extend(['--tree-size',n])
  call(cmd,env)
 measured={}
 for path in raw.rglob('observations.csv'):
  for row in rows(path):
   if row['auth_family']=='mtc-experimental' and row.get('is_warmup')!='1':measured.setdefault((row['profile'],int(row['tree_size'])),[]).append(int(row['certificate_total_bytes']))
 med={k:int(statistics.median(v)) for k,v in measured.items()};audit=[]
 for row in exact:
  if row['native_auditable'].lower()!='true':continue
  profile=row['profile'];n=int(row['crossover_N']);x=int(row['x509_certificate_total_bytes']);before,at=med[(profile,n-1)],med[(profile,n)];passed=before<x and at>=x
  audit.append({'profile':profile,'chain_profile':row['chain_profile'],'x509_total_bytes':x,'predicted_crossover_n':n,'n_before':n-1,'mtc_total_before':before,'mtc_total_at':at,'result':'PASS' if passed else 'FAIL'})
 fields=list(audit[0]);
 with (a.output/'mutual-boundary-audit.csv').open('x',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(audit)
 passed=all(r['result']=='PASS' for r in audit);(a.output/'mutual-boundary-audit.json').write_text(json.dumps({'passed':passed,'rows':audit},indent=2)+'\n')
 if not passed:raise SystemExit('one or more mutual crossover boundaries failed')
if __name__=='__main__':main()
