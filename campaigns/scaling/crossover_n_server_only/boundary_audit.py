#!/usr/bin/env python3
"""Plan or execute empirical N-1/N checks of analytical crossover boundaries."""
import argparse, csv, json, os, statistics, subprocess, sys
from html import escape
from pathlib import Path

HERE=Path(__file__).resolve().parent;REPO=HERE.parents[2]

def read(path):
    with path.open(newline='') as f:return list(csv.DictReader(f))

def targets(analysis):
    rows=read(analysis/'crossover_extended.csv');chosen={}
    for row in rows:
        if row.get('status')!='CROSSED':continue
        n=int(row['crossover_N'])
        if row.get('x509_depth')=='2' and 1<n<=256:chosen.setdefault(row['algorithm'],set()).update((n-1,n))
    return rows,{k:sorted(v) for k,v in chosen.items()}

def call(cmd):
    print('+',' '.join(map(str,cmd)),flush=True);subprocess.run(list(map(str,cmd)),cwd=REPO,check=True)

def render(rows,path):
    fields=['profile','x509_depth','predicted_crossover_n','n_before','bytes_before','relation_before','n_at','bytes_at','relation_at','result']
    head=''.join(f'<th>{escape(x.replace("_"," ").title())}</th>' for x in fields)
    body=''.join('<tr>'+''.join(f'<td>{escape(str(r[x]))}</td>' for x in fields)+'</tr>' for r in rows)
    path.write_text(f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Crossover boundary audit</title><style>body{{font:15px system-ui;max-width:1200px;margin:auto;padding:30px;color:#172b4d}}table{{border-collapse:collapse;width:100%}}th,td{{padding:9px;border-bottom:1px solid #ccd6e0;text-align:left}}th{{background:#edf3f8}}</style></head><body><h1>Empirical crossover boundary audit</h1><p>Each row checks the analytically predicted boundary using real MTC TLS Certificate-message observations at N-1 and N. PASS requires MTC(N-1) &lt; X.509 and MTC(N) &gt;= X.509.</p><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></body></html>''')

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--analysis',type=Path,required=True);p.add_argument('--source-fixtures',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--runs',type=int,default=30);p.add_argument('--warmups',type=int,default=5);p.add_argument('--image',default='mt-tls-mtc:local');p.add_argument('--execute',action='store_true');a=p.parse_args()
    analytical,chosen=targets(a.analysis)
    plan={'profiles':chosen,'boundary_definition':'N-1 smaller; N greater than or equal to X.509','runs':a.runs,'warmups':a.warmups,'output':str(a.output)}
    print(json.dumps(plan,indent=2))
    if not a.execute:return
    if a.output.exists():p.error('output exists')
    if not chosen:raise SystemExit('no D=2 analytical crossover can be audited inside N<=256')
    a.output.mkdir(parents=True);(a.output/'plan.json').write_text(json.dumps(plan,indent=2)+'\n')
    fixtures=a.output/'fixtures';raw=a.output/'raw'
    def container(path):
        path=path.resolve();return Path('/repo')/path.relative_to(REPO) if path.is_relative_to(REPO) else None
    source_in=container(a.source_fixtures);analysis_in=container(a.analysis)
    if source_in is None or analysis_in is None:raise SystemExit('inputs must be below the repository root')
    call(['docker','run','--rm','-e','PYTHONPATH=/repo/src/mtc','-v',f'{REPO}:/repo:ro','-v',f'{a.output.resolve()}:/output','-w','/repo','--entrypoint','python3',a.image,'campaigns/scaling/crossover_n_server_only/generate_boundary_fixtures.py','--source',source_in,'--analysis',analysis_in,'--output','/output/fixtures'])
    for profile,sizes in chosen.items():
        cmd=[sys.executable,HERE/'run_mtc_by_n.py','--mtc-root',fixtures,'--output',raw/profile,'--profile',profile,'--runs',a.runs,'--warmups',a.warmups,'--execute']
        for n in sizes:cmd.extend(['--tree-size',n])
        call(cmd)
    measured={}
    for path in raw.rglob('observations.csv'):
        for row in read(path):measured.setdefault((row['profile'],int(row['tree_size'])),[]).append(int(row['certificate_message_bytes']))
    med={key:int(statistics.median(values)) for key,values in measured.items()};result=[]
    for row in analytical:
        if row.get('status')!='CROSSED':continue
        n=int(row['crossover_N']);profile=row['algorithm']
        if row.get('x509_depth')!='2' or not 1<n<=256:continue
        before,at=med[(profile,n-1)],med[(profile,n)];x=int(row['x509_bytes']);passed=before<x and at>=x
        result.append({'profile':profile,'x509_depth':row['x509_depth'],'x509_bytes':x,'predicted_crossover_n':n,'n_before':n-1,'bytes_before':before,'relation_before':'MTC < X.509' if before<x else 'MTC >= X.509','n_at':n,'bytes_at':at,'relation_at':'MTC >= X.509' if at>=x else 'MTC < X.509','result':'PASS' if passed else 'FAIL'})
    fields=list(result[0]);
    with (a.output/'crossover-boundary-audit.csv').open('x',newline='') as f:w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(result)
    passed=all(r['result']=='PASS' for r in result);(a.output/'crossover-boundary-audit.json').write_text(json.dumps({'passed':passed,'rows':result},indent=2)+'\n');render(result,a.output/'report.html')
    if not passed:raise SystemExit('one or more crossover boundaries failed empirical confirmation')
if __name__=='__main__':main()
