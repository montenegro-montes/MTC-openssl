"""Manual offline tests: temporary keys/logs/snapshots and native checker only."""
import argparse
import json
from pathlib import Path
import tempfile

import prepare
from build_check_snapshot import build_check_snapshot
from config_formats import decode_mca2, decode_mcp2
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
    profile=crypto_profile(args.profile)
    with tempfile.TemporaryDirectory(prefix='mtc-authenticated-snapshots-') as temporary:
        temp=Path(temporary);checker=temp/'check_snapshot'
        build_check_snapshot(prefix, checker, args.cc, (
            '-g', '-fsanitize=address,undefined', '-fno-omit-frame-pointer'))
        # Independently provision trust BEFORE exporting or reading any snapshot.
        def provision(label):
            keys=[temp/f'{label}-{i}.key' for i in range(2)]
            for key in keys:prepare.keygen(key,args.profile)
            public=[prepare.command('pkey','-in',key,'-pubout','-outform','DER') for key in keys]
            data=prepare.authority_config_v2(profile['ca_id'],profile['cosigner_ids'],public,16)
            authority=temp/f'{label}-authority.bin';authority.write_bytes(data)
            assert data.startswith(b'MCA2')
            assert decode_mca2(data).log_number==1
            return keys,authority
        keys,trusted=provision('trusted')
        log=LocalLog(temp/'log-directory');entries=[bytes([i]) for i in range(16)]
        for entry in entries[:8]:log.append(entry)
        old=export_snapshot(log,temp/'snapshot-8.mcp2',args.profile,keys)
        assert old.suffix=='.mcp2' and old.read_bytes().startswith(b'MCP2')
        assert decode_mcp2(old.read_bytes()).tree_size==8
        retained=old.read_bytes()
        state8=authenticate_snapshot(old,trusted,checker)
        assert state8=={
            'log_number':1,
            'tree_size':8,
            'hash':root(entries[:8]).hex(),
        }
        log=LocalLog(log.directory)
        for entry in entries[8:]:log.append(entry)
        new=export_snapshot(log,temp/'snapshot-16.mcp2',args.profile,keys)
        assert decode_mcp2(new.read_bytes()).tree_size==16
        state16=authenticate_snapshot(new,trusted,checker)
        assert state16=={
            'log_number':1,
            'tree_size':16,
            'hash':root(entries).hex(),
        }

        # The external checker output is untrusted until its issuance-log
        # identity and LocalLog state have been validated.
        invalid_checker_states=[
            {'tree_size':16,'hash':state16['hash']},
            {'log_number':0,'tree_size':16,'hash':state16['hash']},
            {'log_number':65536,'tree_size':16,'hash':state16['hash']},
            {'log_number':-1,'tree_size':16,'hash':state16['hash']},
            {'log_number':True,'tree_size':16,'hash':state16['hash']},
        ]
        for index,state in enumerate(invalid_checker_states):
            fake=temp/f'invalid-checker-{index}'
            fake.write_text(
                '#!/bin/sh\n'
                + "printf '%s\\n' "
                + repr(json.dumps(state))
                + '\n'
            )
            fake.chmod(0o755)
            rejected(lambda fake=fake:authenticate_snapshot(
                new,trusted,fake))

        malformed_checker=temp/'malformed-checker'
        malformed_checker.write_text(
            "#!/bin/sh\nprintf '%s\\n' 'not-json'\n"
        )
        malformed_checker.chmod(0o755)
        rejected(lambda:authenticate_snapshot(
            new,trusted,malformed_checker))
        print('PASS: invalid authenticated snapshot log identities rejected')

        # Draft-06 Section 7.4: incorporate active landmark subtrees only
        # after authenticating the reference checkpoint and validating each
        # subtree against it with a Section 4.4 consistency proof.
        sequence=[
            Landmark(0,0,0),
            Landmark(1,8,state16['tree_size']+100),
            Landmark(2,16,state16['tree_size']+200),
        ]
        evidence=build_evidence(log,sequence,0)
        local_state16={
            'tree_size':state16['tree_size'],
            'hash':state16['hash'],
        }
        trusted_subtrees=validate_trusted_subtrees(
            1,sequence,0,local_state16,evidence)
        assert [(x.log_number,x.start,x.end) for x in trusted_subtrees]==[
            (1,0,4),(1,4,8),(1,8,12),(1,12,16)
        ]
        print('PASS: authenticated MCP2 checkpoint -> Section 7.4 trusted subtrees')

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
            1,sequence,0,local_state16,foreign_evidence)==[]
        print('PASS: foreign same-size subtree evidence not incorporated')
        local_state8={
            'tree_size':state8['tree_size'],
            'hash':state8['hash'],
        }
        current,path=log.prove_consistency(local_state8)
        assert current=={
            'tree_size':state16['tree_size'],
            'hash':state16['hash'],
        }
        assert verify_snapshot_consistency(old,new,trusted,checker,path)

        # Independently authenticated issuance-log domains remain distinct
        # even when they describe the same underlying tree and root.
        public=[
            prepare.command('pkey','-in',key,'-pubout','-outform','DER')
            for key in keys
        ]
        trusted_log2=temp/'trusted-log2-authority.bin'
        trusted_log2.write_bytes(
            prepare.authority_config_v2(
                profile['ca_id'],
                profile['cosigner_ids'],
                public,
                16,
                log_number=2,
            )
        )
        snapshot_log2=export_snapshot(
            log,
            temp/'snapshot-log2-16.mcp2',
            args.profile,
            keys,
            log_number=2,
        )
        state_log2=authenticate_snapshot(
            snapshot_log2,trusted_log2,checker)
        assert state_log2=={
            'log_number':2,
            'tree_size':state16['tree_size'],
            'hash':state16['hash'],
        }
        assert state_log2['tree_size']==state16['tree_size']
        assert state_log2['hash']==state16['hash']
        assert state_log2['log_number']!=state16['log_number']
        rejected(lambda:authenticate_snapshot(new,trusted_log2,checker))
        rejected(lambda:authenticate_snapshot(snapshot_log2,trusted,checker))
        print('PASS: independently authenticated log 1/log 2 checkpoints remain distinct')

        rejected(lambda:export_snapshot(log,old,args.profile,keys))
        assert old.read_bytes()==retained
        print('PASS: independently authenticated N=8 -> N=16; consistency; overwrite refused')

        root_offset=4+6+8
        for label,snapshot,offset in [('old-root',old,root_offset),('new-root',new,root_offset)]:
            data=bytearray(snapshot.read_bytes());data[offset]^=1
            bad=temp/(label+'.mcp2');bad.write_bytes(data)
            rejected(lambda:authenticate_snapshot(bad,trusted,checker))
        data=bytearray(new.read_bytes())
        sig_offset=root_offset+32+3
        sig_offset+=1+data[sig_offset]+2  # ID vector, individual signature uint16.
        data[sig_offset]^=1
        bad=temp/'bad-signature.mcp2';bad.write_bytes(data)
        rejected(lambda:authenticate_snapshot(bad,trusted,checker))
        data=bytearray(new.read_bytes())
        subtree_offset=53+int.from_bytes(data[50:53],'big')
        data[subtree_offset+5]^=1
        bad=temp/'bad-cover.mcp2';bad.write_bytes(data)
        rejected(lambda:authenticate_snapshot(bad,trusted,checker))
        attacker_keys,attacker_authority=provision('attacker')
        substituted=export_snapshot(log,temp/'substituted.mcp2',args.profile,attacker_keys)
        assert authenticate_snapshot(substituted,attacker_authority,checker)==state16
        rejected(lambda:authenticate_snapshot(substituted,trusted,checker))
        modified=[bytes([path[0][0]^1])+path[0][1:]]+path[1:]
        assert not verify_snapshot_consistency(old,new,trusted,checker,modified)
        print('PASS: altered roots/signature, substituted signer keys and modified proof rejected')

        (log.directory/'log/000003.entry').write_bytes(b'rewritten')
        rejected(lambda:LocalLog(log.directory))
        rejected(lambda:export_snapshot(log,temp/'must-not-export.mcp2',args.profile,keys))
        # Model coordinated replacement of unsigned metadata plus history, then
        # even obtain legitimate signatures. Only retained authenticated N=8 is trusted.
        changed=list(entries);changed[3]=b'rewritten'
        (log.directory/'state.json').write_text(json.dumps({'tree_size':16,'hash':root(changed).hex()}))
        rewritten_log=LocalLog(log.directory)
        rewritten=export_snapshot(rewritten_log,temp/'rewritten-16.mcp2',args.profile,keys)
        changed_state=authenticate_snapshot(rewritten,trusted,checker)
        assert changed_state['hash']==root(changed).hex()
        from core import consistency
        assert not verify_snapshot_consistency(old,rewritten,trusted,checker,consistency(changed,8))
        rejected(lambda:rewritten_log.prove_consistency(local_state8))
        assert old.read_bytes()==retained
        print('PASS: disk tampering detected; validly signed rewritten history fails consistency')
    print('Authenticated MCP2 snapshot tests PASS; temporary data removed')


if __name__=='__main__':main()
