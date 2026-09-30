"""Manual offline tests: temporary keys/logs/snapshots and native checker only."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

import prepare
from core import root
from crypto_profiles import crypto_profile
from local_log import LocalLog
from landmarks import Landmark
from trusted_subtrees import build_evidence, validate_trusted_subtrees
from snapshots import export_snapshot, authenticate_snapshot, verify_snapshot_consistency


def rejected(operation):
    try:operation()
    except (ValueError,OSError):return
    raise AssertionError('Invalid snapshot/history accepted')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl-prefix',type=Path,required=True)
    parser.add_argument('--profile',default='ecdsa-p256',choices=['ecdsa-p256','mldsa65'])
    parser.add_argument('--cc',default='cc')
    args=parser.parse_args();prefix=args.openssl_prefix.resolve()
    prepare.OPENSSL=str(prefix/'bin/openssl')
    lib=prefix/'lib'
    if not lib.is_dir():lib=prefix/'lib64'
    source=Path(__file__).resolve().parent
    profile=crypto_profile(args.profile)
    with tempfile.TemporaryDirectory(prefix='mtc-authenticated-snapshots-') as temporary:
        temp=Path(temporary);checker=temp/'check_snapshot'
        subprocess.run([args.cc,'-Wall','-Wextra','-g','-fsanitize=address,undefined',
                        '-fno-omit-frame-pointer','-I'+str(prefix/'include'),
                        str(source/'check_snapshot.c'),'-L'+str(lib),
                        '-Wl,-rpath,'+str(lib),'-lcrypto','-o',str(checker)],check=True)
        # Independently provision trust BEFORE exporting or reading any snapshot.
        def provision(label):
            keys=[temp/f'{label}-{i}.key' for i in range(2)]
            for key in keys:prepare.keygen(key,args.profile)
            public=[prepare.command('pkey','-in',key,'-pubout','-outform','DER') for key in keys]
            data=prepare.authority_config(profile['ca_id'],profile['cosigner_ids'],public,16)
            authority=temp/f'{label}-authority.bin';authority.write_bytes(data)
            return keys,authority
        keys,trusted=provision('trusted')
        log=LocalLog(temp/'log-directory');entries=[bytes([i]) for i in range(16)]
        for entry in entries[:8]:log.append(entry)
        old=export_snapshot(log,temp/'snapshot-8.mcf1',args.profile,keys)
        retained=old.read_bytes()
        state8=authenticate_snapshot(old,trusted,checker)
        assert state8=={'tree_size':8,'hash':root(entries[:8]).hex()}
        log=LocalLog(log.directory)
        for entry in entries[8:]:log.append(entry)
        new=export_snapshot(log,temp/'snapshot-16.mcf1',args.profile,keys)
        state16=authenticate_snapshot(new,trusted,checker)
        assert state16=={'tree_size':16,'hash':root(entries).hex()}

        # Draft-06 Section 7.4: incorporate active landmark subtrees only
        # after authenticating the reference checkpoint and validating each
        # subtree against it with a Section 4.4 consistency proof.
        sequence=[
            Landmark(0,0,0),
            Landmark(1,8,state16['tree_size']+100),
            Landmark(2,16,state16['tree_size']+200),
        ]
        evidence=build_evidence(log,sequence,0)
        trusted_subtrees=validate_trusted_subtrees(
            1,sequence,0,state16,evidence)
        assert [(x.log_number,x.start,x.end) for x in trusted_subtrees]==[
            (1,0,4),(1,4,8),(1,8,12),(1,12,16)
        ]
        print('PASS: authenticated MCF1 checkpoint -> Section 7.4 trusted subtrees')

        from prepare import write_trusted_subtrees
        from trusted_subtrees import decode_trusted_subtrees

        trusted_file = temp / "trusted-subtrees.bin"

        write_trusted_subtrees(trusted_file, trusted_subtrees)

        assert decode_trusted_subtrees(
            trusted_file.read_bytes()
        ) == trusted_subtrees

        print('PASS: trusted subtrees exported as MTS1 configuration')

        different=LocalLog(temp/'different-log')
        for i in range(16):
            different.append(b'x'+bytes([i]))
        foreign_evidence=build_evidence(different,sequence,0)
        assert validate_trusted_subtrees(
            1,sequence,0,state16,foreign_evidence)==[]
        print('PASS: foreign same-size subtree evidence not incorporated')
        current,path=log.prove_consistency(state8)
        assert current==state16
        assert verify_snapshot_consistency(old,new,trusted,checker,path)
        rejected(lambda:export_snapshot(log,old,args.profile,keys))
        assert old.read_bytes()==retained
        print('PASS: independently authenticated N=8 -> N=16; consistency; overwrite refused')

        # authority.bin has fixed-width serial bounds, so its length is size-independent.
        root_offset=len(trusted.read_bytes())+4+6+8
        for label,snapshot,offset in [('old-root',old,root_offset),('new-root',new,root_offset)]:
            data=bytearray(snapshot.read_bytes());data[offset]^=1
            bad=temp/(label+'.mcf1');bad.write_bytes(data)
            rejected(lambda:authenticate_snapshot(bad,trusted,checker))
        data=bytearray(new.read_bytes())
        sig_offset=root_offset+32+2  # MCF1 outer signatures length remains uint16.
        sig_offset+=1+data[sig_offset]+2  # ID vector, individual signature uint16.
        data[sig_offset]^=1
        bad=temp/'bad-signature.mcf1';bad.write_bytes(data)
        rejected(lambda:authenticate_snapshot(bad,trusted,checker))
        attacker_keys,attacker_authority=provision('attacker')
        substituted=export_snapshot(log,temp/'substituted.mcf1',args.profile,attacker_keys)
        assert authenticate_snapshot(substituted,attacker_authority,checker)==state16
        rejected(lambda:authenticate_snapshot(substituted,trusted,checker))
        modified=[bytes([path[0][0]^1])+path[0][1:]]+path[1:]
        assert not verify_snapshot_consistency(old,new,trusted,checker,modified)
        print('PASS: altered roots/signature, substituted signer keys and modified proof rejected')

        (log.directory/'log/000003.entry').write_bytes(b'rewritten')
        rejected(lambda:LocalLog(log.directory))
        rejected(lambda:export_snapshot(log,temp/'must-not-export.mcf1',args.profile,keys))
        # Model coordinated replacement of unsigned metadata plus history, then
        # even obtain legitimate signatures. Only retained authenticated N=8 is trusted.
        changed=list(entries);changed[3]=b'rewritten'
        (log.directory/'state.json').write_text(json.dumps({'tree_size':16,'hash':root(changed).hex()}))
        rewritten_log=LocalLog(log.directory)
        rewritten=export_snapshot(rewritten_log,temp/'rewritten-16.mcf1',args.profile,keys)
        changed_state=authenticate_snapshot(rewritten,trusted,checker)
        assert changed_state['hash']==root(changed).hex()
        from core import consistency
        assert not verify_snapshot_consistency(old,rewritten,trusted,checker,consistency(changed,8))
        rejected(lambda:rewritten_log.prove_consistency(state8))
        assert old.read_bytes()==retained
        print('PASS: disk tampering detected; validly signed rewritten history fails consistency')
    print('Authenticated MCF1 snapshot tests PASS; temporary data removed')


if __name__=='__main__':main()
