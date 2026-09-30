"""Offline authenticated MCF1 snapshots, not an operational landmark sequence.

The caller supplies an independently trusted authority.bin and checker binary.
state.json is never a trust anchor. Preserve old snapshots outside the log.
The container's legacy landmark slot is not used as a snapshot identity.
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


def export_snapshot(log, destination, family, keys):
    destination=Path(destination)
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
        if not 1<=n<=1024:raise ValueError('MCF1 supports snapshots of 1..1024 entries')
        copied=[];public=[]
        for i,key in enumerate(keys):
            target=Path(temp)/f'{i}.key';shutil.copyfile(key,target);target.chmod(0o600)
            copied.append(target)
            public.append(prepare.command('pkey','-in',target,'-pubout','-outform','DER'))
        timestamp=int(time.time());r=root(entries)
        signatures=[prepare.checkpoint_signature(i,k,caid,n,r,timestamp,family)
                    for i,k in zip(ids,copied)]
        data=prepare.checkpoint_config(prepare.authority_config(caid,ids,public,n),
                                       entries,timestamp,signatures)
        # Exclusive creation: never replaces a retained snapshot, including on failure.
        with destination.open('xb') as out:
            out.write(data);out.flush();os.fsync(out.fileno())
            os.fchmod(out.fileno(),0o444)
    return destination


def authenticate_snapshot(snapshot, trusted_authority, checker):
    result=subprocess.run([str(checker),str(trusted_authority),str(snapshot)],capture_output=True,text=True)
    if result.returncode:raise ValueError('Snapshot authentication failed: '+result.stderr.strip())
    state=json.loads(result.stdout)
    LocalLog._check_state(state)
    return state


def verify_snapshot_consistency(old_snapshot,new_snapshot,trusted_authority,checker,path):
    old=authenticate_snapshot(old_snapshot,trusted_authority,checker)
    new=authenticate_snapshot(new_snapshot,trusted_authority,checker)
    return verify_consistency(old['tree_size'],new['tree_size'],
                              bytes.fromhex(old['hash']),bytes.fromhex(new['hash']),path)
