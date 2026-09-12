#!/usr/bin/env python3
"""Capability-gated, immutable manual TLS runner with read-only resume planning."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import platform
import subprocess
import uuid
from config import DEPTHS, IMAGE, PROFILES, TLS
from capabilities import load_support, write_support, fixture_evidence
from inspect_environment import inspect
from result_state import cell_name, digest, validate_complete, validate_fixture

REPO=Path(__file__).resolve().parents[3]
COMPOSE=['docker','compose','-f',str(REPO/'docker/cryptographic_scaling/compose.cert-chain-scaling.yaml')]


def write_json(path,data):
    with path.open('x') as f:json.dump(data,f,indent=2);f.write('\n')


def diagnostics(directory, env):
    directory.mkdir(parents=True,exist_ok=False)
    commands=[('ps',['ps','-a']),('server-logs',['logs','--no-color','server']),('container-ids',['ps','-a','-q','server'])]
    for name,args in commands:
        try:
            result=subprocess.run(COMPOSE+args,env=env,capture_output=True,text=True,timeout=20)
            write_json(directory/(name+'.json'),{'command':args,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
            if name=='container-ids' and result.returncode==0 and result.stdout.split():
                ids=result.stdout.split()
                result=subprocess.run(['docker','inspect',*ids],env=env,capture_output=True,text=True,timeout=20)
                write_json(directory/'inspect.json',{'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        except (OSError,subprocess.SubprocessError) as error:
            write_json(directory/(name+'-error.json'),{'error':str(error)})


def execute_cell(cell,args,plan,attempt,commit):
    profile,depth,index=cell['profile'],cell['depth'],cell['campaign'];name=cell_name(profile,depth,index)
    target=args.output/name
    # Incomplete outputs stay in place. Retry into a separate attempts tree.
    result_root=args.output
    if target.exists():
        result_root=attempt/'cells';result_root.mkdir(exist_ok=True)
    env=os.environ.copy();env.update(CERT_CHAIN_IMAGE=plan['image_id'],CERT_CHAIN_FIXTURES=str(args.fixtures.resolve()),
        CERT_CHAIN_RESULTS=str(result_root.resolve()),CERT_PROFILE=profile,CERT_DEPTH=str(depth),CERT_CAMPAIGN=name,
        FIXTURE_SHA256=cell['fixture_hash'],SOURCE_COMMIT=commit,IMAGE_ID=plan['image_id'])
    seed=plan['seed']+index+depth*100+list(PROFILES).index(profile)*1000
    try:
        subprocess.run(COMPOSE+['up','-d','--force-recreate','--wait','server'],env=env,check=True)
        subprocess.run(COMPOSE+['run','--rm','client','python3','/repo/campaigns/cryptographic_scaling/cert_chain_scaling/measure.py',
                       '--runs',str(plan['repetitions']),'--warmups',str(plan['warmups']),'--scenario',f'{profile}-d{depth}',
                       '--campaign',name,'--seed',str(seed)],env=env,check=True)
        status,errors=validate_complete(result_root/name,profile,depth,index,plan,cell['fixture_hash'])
        if status!='COMPLETE':raise ValueError('Post-run validation failed: '+str(errors))
    except BaseException:
        try:diagnostics(attempt/('failure-'+name),env)
        finally:raise
    finally:
        subprocess.run(COMPOSE+['down'],env=env,check=False)


def parser():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--profile',action='append',choices=PROFILES);p.add_argument('--family',choices=['ECDSA','ML-DSA','SLH-DSA'])
    p.add_argument('--security-level',type=int,choices=[1,3,5]);p.add_argument('--depth',action='append',type=int,choices=DEPTHS)
    p.add_argument('--campaign',action='append',type=int,help='Select an individual campaign index (repeatable)')
    p.add_argument('--campaigns',type=int);p.add_argument('--repetitions',type=int);p.add_argument('--warmups',type=int);p.add_argument('--seed',type=int)
    p.add_argument('--image',default=IMAGE);p.add_argument('--environment',type=Path,help='Recorded capability manifest; required for offline planning')
    p.add_argument('--resume',action='store_true');p.add_argument('--dry-run',action='store_true')
    p.add_argument('--execute',action='store_true');p.add_argument('--full-matrix',action='store_true')
    return p


def build_plan(args,p):
    old=None
    if args.output.exists():
        if not args.resume:p.error('Output exists; use --resume to validate and preserve existing cells')
        try:old=json.loads((args.output/'manifest.json').read_text())
        except (OSError,ValueError) as error:p.error('Cannot resume without original manifest: '+str(error))
    elif args.resume:p.error('Resume output does not exist; a deleted run cannot be resumed')
    for key,default in [('campaigns',1),('repetitions',30),('warmups',5),('seed',41000)]:
        value=getattr(args,key)
        if old and value is not None and value!=old[key]:p.error('Resume must preserve '+key)
        setattr(args,key,old[key] if old else (default if value is None else value))
    if args.campaigns<1 or args.repetitions<2 or args.warmups<0:p.error('campaigns >= 1, repetitions >= 2, warmups >= 0')
    if args.environment:environment=json.loads(args.environment.read_text())
    elif args.execute and not args.dry_run:environment=inspect(args.image)
    else:p.error('Offline planning requires --environment; no Docker commands run in dry-run mode')
    if environment.get('configured_profiles',PROFILES)!=PROFILES:p.error('Capability configuration differs from current profiles; inspect the intended image/configuration again')
    support=fixture_evidence(load_support(environment),args.fixtures,environment.get('openssl'),environment.get('image_id') or environment['image']['Id']);by_profile={r['profile']:r for r in support}
    image_id=environment.get('image_id') or environment['image']['Id']
    if old and image_id!=old['image_id']:p.error('Image differs from original campaign; use a separate output for a different stack')
    if old and 'configured_profiles' in old and old['configured_profiles']!=PROFILES:p.error('Frozen configuration differs; use the original configuration')
    profiles=list(dict.fromkeys(args.profile or (old['profiles'] if old else PROFILES)))
    profiles=[x for x in profiles if (not args.family or PROFILES[x]['family']==args.family) and (not args.security_level or PROFILES[x]['level']==args.security_level)]
    depths=list(dict.fromkeys(args.depth or (old['depths'] if old else DEPTHS)))
    campaigns=list(dict.fromkeys(args.campaign or range(1,args.campaigns+1)))
    if not profiles or any(c<1 or c>args.campaigns for c in campaigns):p.error('Empty profile selection or invalid campaign index')
    if len(profiles)==len(PROFILES) and len(depths)==len(DEPTHS) and not args.full_matrix:p.error('Full matrix requires --full-matrix')
    all_cells=old['cells'] if old else [{'profile':x,'depth':d,'campaign':c} for x in profiles for d in depths for c in range(1,args.campaigns+1)]
    allowed={(r['profile'],r['depth'],r['campaign']) for r in all_cells}
    if any((x,d,c) not in allowed for x in profiles for d in depths for c in campaigns):p.error('Selection is outside frozen original matrix')
    plan=dict(old or {},schema=2,profiles=(old['profiles'] if old else profiles),depths=(old['depths'] if old else depths),
              campaigns=args.campaigns,repetitions=args.repetitions,warmups=args.warmups,seed=args.seed,image_id=image_id,
              configured_profiles=(old.get('configured_profiles',PROFILES) if old else PROFILES),cells=[],tls=TLS,
              algorithm_support=support,network='Docker bridge; no NET_ADMIN and no qdisc configuration')
    if old:
        accepted={old['git_commit']}
        for f in args.output.glob('resume/*/execution.json'):
            accepted.add(json.loads(f.read_text())['git_commit'])
        plan['accepted_source_commits']=sorted(accepted)
    for original in all_cells:
        profile,depth,index=(original[k] for k in ('profile','depth','campaign'))
        cell={'profile':profile,'depth':depth,'campaign':index,'selected':profile in profiles and depth in depths and index in campaigns}
        cap=by_profile[profile]
        cell['tls_signature_supported']=cap['tls_signature_supported']
        if not cap['tls_experiment_enabled']:
            cell.update(status='SKIPPED_UNSUPPORTED_TLS',reason=cap['reason'])
        else:
            try:
                h=validate_fixture(args.fixtures/profile/f'depth-{depth}',profile,depth);cell['fixture_hash']=h
                if old:
                    saved=json.loads((args.output/'fixture_hashes.json').read_text())
                    if h!=saved[f'{profile}/depth-{depth}/manifest.json']:raise ValueError('Fixture differs from original campaign')
                name=cell_name(profile,depth,index);candidates=[args.output/name,*sorted(args.output.glob('resume/*/cells/'+name))]
                findings=[(d,*validate_complete(d,profile,depth,index,plan,h)) for d in candidates]
                complete=[(d,e) for d,state,e in findings if state=='COMPLETE']
                if len(complete)>1:raise ValueError('Multiple complete observations for one cell; review duplicate provenance')
                if complete:cell.update(status='COMPLETE',directory=str(complete[0][0]))
                elif any(state=='INVALID_INCOMPLETE' for _,state,_ in findings):
                    cell.update(status='INVALID_INCOMPLETE',reason=str([(str(d),e) for d,state,e in findings if state=='INVALID_INCOMPLETE']))
                else:cell['status']='MISSING'
            except (OSError,KeyError,ValueError) as error:cell.update(status='BLOCKED_FIXTURE',reason=str(error))
        plan['cells'].append(cell)
    plan['counts']={status:sum(c['status']==status for c in plan['cells']) for status in
                    ['COMPLETE','MISSING','INVALID_INCOMPLETE','SKIPPED_UNSUPPORTED_TLS','BLOCKED_FIXTURE']}
    plan['expected_eligible_tls_cells']=sum(c['tls_signature_supported'] for c in plan['cells'])
    return plan,environment


def main():
    p=parser();args=p.parse_args();plan,environment=build_plan(args,p)
    for cell in plan['cells']:
        label={'COMPLETE':'SKIP complete','SKIPPED_UNSUPPORTED_TLS':'SKIP unsupported TLS'}.get(cell['status'],cell['status'])
        print(f"{label}: {cell['profile']} D={cell['depth']} campaign={cell['campaign']}")
    print(json.dumps({'counts':plan['counts'],'expected_eligible_tls_cells':plan['expected_eligible_tls_cells']},indent=2))
    if not args.execute or args.dry_run:return
    pending=[c for c in plan['cells'] if c['selected'] and c['status'] not in ('COMPLETE','SKIPPED_UNSUPPORTED_TLS')]
    if any(c['status']=='BLOCKED_FIXTURE' for c in pending):p.error('Fixture/provenance validation blocked execution')
    if not pending and args.resume:print('No missing eligible cells. Nothing written.');return
    # Mutable tag changes cannot silently mix different images on resume.
    live=json.loads(subprocess.check_output(['docker','image','inspect',args.image],text=True))[0]
    if live['Id']!=plan['image_id']:p.error('Current image does not match capability evidence')
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip()
    execution={'git_commit':commit,'git_status':subprocess.check_output(['git','status','--porcelain'],cwd=REPO,text=True),
               'source_hashes':{str(f.relative_to(REPO)):digest(f) for f in Path(__file__).parent.glob('*.py')},'image_id':plan['image_id']}
    if not args.resume:
        args.output.mkdir(parents=True,exist_ok=False);plan.update(git_commit=commit,git_status=execution['git_status'],platform=platform.platform())
        write_json(args.output/'manifest.json',plan);write_json(args.output/'environment.json',environment);write_support(args.output/'algorithm_support.csv',plan['algorithm_support'])
        write_json(args.output/'fixture_hashes.json',{f"{c['profile']}/depth-{c['depth']}/manifest.json":c['fixture_hash'] for c in plan['cells'] if 'fixture_hash' in c})
    attempt=args.output/'resume'/(dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]);attempt.mkdir(parents=True,exist_ok=False)
    write_json(attempt/'execution.json',execution);write_json(attempt/'environment.json',environment)
    write_support(attempt/'algorithm_support.csv',plan['algorithm_support']);write_json(attempt/'plan.json',plan)
    plan['accepted_source_commits']=[*plan.get('accepted_source_commits',[]),commit]
    # No modification to old manifests, completed cells, or incomplete attempts.
    for cell in pending:execute_cell(cell,args,plan,attempt,commit)

if __name__=='__main__':main()
