"""Offline authenticated MCP2 snapshots, not an operational landmark sequence.

The caller supplies an independently trusted authority.bin and checker binary.
state.json is never a trust anchor. Preserve old snapshots outside the log.
MCP2 contains checkpoint material only and has no landmark signaling identity.
"""
import json
import os
from pathlib import Path
import subprocess
import time

import prepare
from core import root, verify_consistency
from crypto_profiles import crypto_profile
from local_log import LocalLog


def export_snapshot(log, destination, family, keys, *, log_number=1):
    destination=Path(destination)
    if destination.suffix!='.mcp2':raise ValueError('Snapshot destination must use .mcp2')
    location=destination.resolve()
    if location==log.directory.resolve() or log.directory.resolve() in location.parents:
        raise ValueError('Retain snapshots outside the mutable log directory')
    if destination.exists() or destination.is_symlink():raise FileExistsError(destination)
    if len(keys)!=2:raise ValueError('CA and additional cosigner keys required')
    profile=crypto_profile(family);caid=profile['ca_id'];ids=profile['cosigner_ids']
    # Signing uses private temporary copies because prepare.sign writes a scratch file.
    import shutil
    import tempfile
    with log._locked(), tempfile.TemporaryDirectory(prefix='mtc-snapshot-sign-') as temp:
        entries,_=log._read();n=len(entries)
        if not 1<=n<=1024:raise ValueError('Snapshot policy supports 1..1024 entries')
        copied=[]
        for i,key in enumerate(keys):
            target=Path(temp)/f'{i}.key';shutil.copyfile(key,target);target.chmod(0o600)
            copied.append(target)
        timestamp=int(time.time());r=root(entries)
        signatures=[
            prepare.checkpoint_signature(
                i, k, caid, n, r, timestamp, family, log=log_number)
            for i, k in zip(ids, copied)
        ]
        data=prepare.checkpoint_config_v2(entries,timestamp,signatures)
        # Exclusive creation: never replaces a retained snapshot, including on failure.
        with destination.open('xb') as out:
            out.write(data);out.flush();os.fsync(out.fileno())
            os.fchmod(out.fileno(),0o444)
    return destination


def authenticate_snapshot(snapshot, trusted_authority, checker):
    result=subprocess.run([str(checker),str(trusted_authority),str(snapshot)],capture_output=True,text=True)
    if result.returncode:raise ValueError('Snapshot authentication failed: '+result.stderr.strip())
    state=json.loads(result.stdout)
    if not isinstance(state,dict) or set(state)!={'log_number','tree_size','hash'}:
        raise ValueError('Invalid authenticated snapshot state')
    log_number=state['log_number']
    if type(log_number) is not int or not 1<=log_number<=65535:
        raise ValueError('Invalid authenticated snapshot issuance log')
    LocalLog._check_state({'tree_size':state['tree_size'],'hash':state['hash']})
    return state


def verify_snapshot_consistency(old_snapshot,new_snapshot,trusted_authority,checker,path):
    old=authenticate_snapshot(old_snapshot,trusted_authority,checker)
    new=authenticate_snapshot(new_snapshot,trusted_authority,checker)
    if old['log_number']!=new['log_number']:
        raise ValueError('Cannot verify consistency across issuance logs')
    return verify_consistency(old['tree_size'],new['tree_size'],
                              bytes.fromhex(old['hash']),bytes.fromhex(new['hash']),path)
