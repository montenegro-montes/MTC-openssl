"""Read-only preflight gate; full outputs never write into the approved root."""
import hashlib
import json
import re
from pathlib import Path


def load(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def check_hashes(repo,root,transitions=None):
    changes={}
    for name in ['baseline-source-sha256.json','fixture-sha256.json']:
        inventory=load(root/name)
        if not isinstance(inventory,dict) or not inventory:raise RuntimeError('Empty preservation inventory: '+name)
        for relative,expected in inventory.items():
            path=(repo/relative).resolve()
            if not path.is_relative_to(repo.resolve()) or not path.is_file():raise RuntimeError('Preservation mismatch: '+relative)
            actual=sha(path)
            if actual!=expected:
                transition=(transitions or {}).get(relative,{}) if name=='baseline-source-sha256.json' else {}
                if expected!=transition.get('before') or actual!=transition.get('after'):raise RuntimeError('Preservation mismatch: '+relative)
                changes[relative]=transition
    return changes


def validate(repo,root,conditions,collect,transitions=None):
    root=root.resolve()
    if not root.is_dir() or not root.is_relative_to(repo/'artifacts/results'):raise RuntimeError('Preflight root must exist under artifacts/results')
    tests=load(root/'tests-status.json');status=load(root/'preflight-status.json')
    if tests.get('passed') is not True or status.get('passed') is not True:raise RuntimeError('Successful tests and preflight are required')
    if set(status.get('conditions',{}))!=set(conditions):raise RuntimeError('All three conditions must pass')
    changes=check_hashes(repo,root,transitions)
    for condition in conditions:
        result=status['conditions'][condition]
        stored=load(root/f'preflight-{condition}-status.json')
        if stored!=result or result.get('passed') is not True:raise RuntimeError('Preflight condition status mismatch')
        if result.get('condition')!=condition or result.get('scenario')!='pq':raise RuntimeError('Preflight design mismatch')
        for flag in ['association_valid','integrity_valid','image_identity_valid']:
            if result.get(flag) is not True:raise RuntimeError('Preflight integrity/identity gate failed')
        for key in ['capture_status','analysis_status','tls_status']:
            if result.get(key)!='SUCCESS':raise RuntimeError('Preflight outcome gate failed')
        if result.get('network_image_id')!=tests.get('network_image_id') or result.get('capture_image_id')!=tests.get('capture_image_id'):raise RuntimeError('Preflight image mismatch')
        campaign=result.get('campaign_id')
        if (not isinstance(campaign,str) or not re.fullmatch(r'[A-Za-z0-9_-]+',campaign)
            or not campaign.endswith(f'-{condition}-preflight')):
            raise RuntimeError('Invalid preflight campaign identifier')
        collect(root/f'preflight-{condition}'/campaign,condition,campaign,1,1,conditions[condition]['failure_aware'],preflight=True)
    # Hash the approved root contents read-only: catches changes during full execution.
    files={str(p.relative_to(root)):sha(p) for p in root.rglob('*') if p.is_file()}
    return {'root':str(root),'tests':tests,'evidence_sha256':files,'source_transitions':changes}


def unchanged(provenance):
    root=Path(provenance['root'])
    current={str(p.relative_to(root)):sha(p) for p in root.rglob('*') if p.is_file()}
    if current!=provenance['evidence_sha256']:raise RuntimeError('Approved preflight evidence changed')
