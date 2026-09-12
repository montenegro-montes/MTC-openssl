"""PCMA Stage B: explicit manual TLS modes; no arguments print help."""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from design import ROOT,load_config,plan

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    mode=p.add_mutually_exclusive_group()
    for name in ('validate','diagnostic','stage-b1','stage-b2','capture','audit','check-model','analyze','plots','tables'):
        mode.add_argument('--'+name,action='store_true')
    p.add_argument('--plan',action='store_true',help='print design only; never starts Docker/TLS')
    p.add_argument('--config',type=Path,default=Path(__file__).parent/'configs/stage-b1.json')
    p.add_argument('--output',type=Path,help='new result/analysis directory; never overwrites')
    p.add_argument('--results',type=Path,help='completed Stage-B results for read-only audit/analysis')
    p.add_argument('--openssl-prefix',type=Path,default=Path(os.environ.get('OPENSSL_PREFIX','/opt/openssl')))
    a=p.parse_args(argv)
    selected=next((x for x in ('validate','diagnostic','stage_b1','stage_b2','capture','audit','check_model','analyze','plots','tables') if getattr(a,x)),None)
    if selected is None and not a.plan:p.print_help();return
    if a.validate:
        env=dict(os.environ,OPENSSL_PREFIX=str(a.openssl_prefix))
        for test in ('test_native.py','test_lab.py'):
            subprocess.run([sys.executable,str(Path(__file__).parent/test)],env=env,check=True)
        return
    config=load_config(a.config)
    selected=selected or 'stage_b1'
    if selected in ('stage_b1','stage_b2','diagnostic','capture'):
        design=plan(config,selected.replace('_','-'))
        if a.plan:
            print(json.dumps(design,indent=2));return
        from runner import execute
        output=a.output or ROOT/'artifacts/results'/('pcma-stage-b-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8])
        execute(config,design,output,capture=a.capture)
        print(output);return
    if a.plan:p.error('--plan applies only to TLS execution designs')
    if a.results is None:p.error('--results required')
    if a.audit or a.check_model:
        from audit import audit
        print(json.dumps(audit(a.results),indent=2));return
    output=a.output or a.results/('derived-'+selected+'-'+uuid.uuid4().hex[:8])
    if output.exists():p.error('output exists')
    from analysis import analyze,plots,tables
    {'analyze':analyze,'plots':plots,'tables':tables}[selected](a.results,output)
    print(output)

if __name__=='__main__':
    try:main()
    except (ValueError,FileNotFoundError,FileExistsError,KeyError,subprocess.CalledProcessError) as e:
        raise SystemExit(str(e))
