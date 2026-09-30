"""Offline migration tests; all keys, certificates and binaries are temporary."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import core
import prepare


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl-prefix',type=Path,required=True,
                        help='Installed OpenSSL 3 prefix containing bin, include and lib')
    parser.add_argument('--cc',default='cc')
    parser.add_argument('--persistent',action='store_true',
                        help='Also generate N=16 material from an authenticated persistent log')
    parser.add_argument('--profiles',nargs=2,default=['ecdsa-p256','mldsa65'])
    args=parser.parse_args()
    if args.profiles[0]==args.profiles[1]:parser.error('Two distinct profiles are required')
    source=Path(__file__).resolve().parent
    prefix=args.openssl_prefix.resolve()
    prepare.OPENSSL=str(prefix/'bin/openssl')
    lib=prefix/'lib'
    if not lib.is_dir():lib=prefix/'lib64'
    subprocess.run([prepare.OPENSSL,'version'],check=True)
    subprocess.run([sys.executable,'-B',str(source/'test_core.py')],check=True)
    with tempfile.TemporaryDirectory(prefix='mtc-draft06-tests-') as directory:
        temp=Path(directory)
        for name in ['test_ids','test_revoked_ranges','test_trusted_subtrees_c',
                     'check','check_trusted_subtree']+(['check_snapshot'] if args.persistent else []):
            subprocess.run([args.cc,'-Wall','-Wextra','-g',
                            '-fsanitize=address,undefined','-fno-omit-frame-pointer',
                            '-I'+str(prefix/'include'),str(source/(name+'.c')),
                            '-L'+str(lib),'-Wl,-rpath,'+str(lib),'-lcrypto',
                            '-o',str(temp/name)],check=True)
        subprocess.run([str(temp/'test_ids')],check=True)
        subprocess.run([str(temp/'test_revoked_ranges')],check=True)
        subprocess.run([str(temp/'test_trusted_subtrees_c')],check=True)
        originals={}
        for family in args.profiles:
            key=temp/(family+'.key');cert=temp/(family+'.pem')
            prepare.keygen(key,family)
            prepare.command('req','-new','-x509','-key',key,'-out',cert,
                            '-subj','/CN=offline-mtc-test','-days','2',
                            '-addext','basicConstraints=critical,CA:FALSE',
                            '-addext','extendedKeyUsage=serverAuth')
            originals[family]=cert
        for n in [1,16]:
            batch=temp/('n'+str(n));batch.mkdir()
            for family in args.profiles:
                cert=originals[family];before=cert.read_bytes();out=batch/family
                # Synthetic repeated input tests the wire path, not issuance policy.
                options={}
                if args.persistent and n==16:
                    from local_log import LocalLog
                    from snapshots import export_snapshot,authenticate_snapshot,verify_snapshot_consistency
                    profile=prepare.crypto_profile(family)
                    keys=[temp/f'{family}-signer-{i}.key' for i in range(2)]
                    for key in keys:prepare.keygen(key,family)
                    public=[prepare.command('pkey','-in',key,'-pubout','-outform','DER') for key in keys]
                    trusted=temp/f'{family}-trusted.bin'
                    trusted.write_bytes(prepare.authority_config(profile['ca_id'],profile['cosigner_ids'],public,n))
                    persistent=LocalLog(temp/f'{family}-persistent')
                    encoded=[core.entry(core.mtc_tbs(core.from_pem(before),profile['ca_id'],i)) for i in range(n)]
                    for value in encoded[:8]:persistent.append(value)
                    old=export_snapshot(persistent,temp/f'{family}-8.mcf1',family,keys)
                    retained=old.read_bytes()
                    for value in encoded[8:]:persistent.append(value)
                    snapshot=export_snapshot(persistent,temp/f'{family}-16.mcf1',family,keys)
                    checker=temp/'check_snapshot'
                    state8=authenticate_snapshot(old,trusted,checker)
                    state16=authenticate_snapshot(snapshot,trusted,checker)
                    current,path=persistent.prove_consistency(state8)
                    assert current==state16 and verify_snapshot_consistency(old,snapshot,trusted,checker,path)
                    options=dict(persistent_log=persistent,authenticated_snapshot=snapshot,
                                 trusted_authority=trusted,snapshot_checker=checker,signer_keys=keys)
                    def reject_generation(label,**overrides):
                        target=temp/f'{family}-rejected-{label}'
                        kwargs=dict(options,originals=[cert]*n);kwargs.update(overrides)
                        try:prepare.prepare(target,temp,family,n,**kwargs)
                        except ValueError:pass
                        else:raise AssertionError('Accepted '+label)
                        assert not target.exists(),label+' created output before rejection'
                    reject_generation('old-size',authenticated_snapshot=old)
                    other=originals[args.profiles[1-args.profiles.index(family)]]
                    reject_generation('wrong-certificate-inputs',originals=[other]*n)
                    first=persistent.directory/'log/000000.entry'
                    first.write_bytes(b'tampered')
                    reject_generation('tampered-log')
                    first.write_bytes(encoded[0])  # Restore only this temporary negative fixture.
                    different=LocalLog(temp/f'{family}-different')
                    for value in [b'different']+encoded[1:]:different.append(value)
                    incompatible=export_snapshot(different,temp/f'{family}-different.mcf1',family,keys)
                    assert authenticate_snapshot(incompatible,trusted,checker)['tree_size']==n
                    reject_generation('incompatible-root',authenticated_snapshot=incompatible)
                    damaged=bytearray(snapshot.read_bytes());damaged[len(trusted.read_bytes())+4+6+8]^=1
                    bad=temp/f'{family}-bad-root.mcf1';bad.write_bytes(damaged)
                    reject_generation('corrupted-checkpoint',authenticated_snapshot=bad)
                meta=prepare.prepare(out,temp,family,n,originals=[cert]*n,**options)
                if options:
                    assert meta['tree_size']==state16['tree_size']==16
                    assert meta['checkpoint']['hash']==state16['hash']
                    assert authenticate_snapshot(out/'trust.bin',trusted,checker)==state16
                    assert [(out/'log'/f'{i:06d}.entry').read_bytes() for i in range(n)]==encoded
                    assert old.read_bytes()==retained
                    for i in range(n):
                        for mode in ['standalone','landmark']:
                            t=core.certificate_parts((out/f'{mode}-{i:04d}.der').read_bytes())[0][0][2]
                            assert core.entry(t)==encoded[i]
                    print(f'PASS {family}: authenticated persistent N=16 generation and mismatch rejection',flush=True)
                assert cert.read_bytes()==before
                expiration=meta['landmark_expirations'][1]
                tbs=core.certificate_parts((out/'landmark-0000.der').read_bytes())[0][0][2]
                assert expiration>=prepare.not_after(tbs)
                assert meta['latest_landmark']==1 and meta['landmark_expirations'][0]==0
                assert (out/'landmarks.txt').read_text()==f'1\n{n} {expiration}\n0 0\n'
                assert meta['subtrees']==core.cover(0,n)
                config=(out/'trust.bin').read_bytes()
                if n==1:
                    assert meta['subtrees']==[(0,1),(1,1)]
                    leaf=core.root([(out/'log/000000.entry').read_bytes()])
                    assert meta['checkpoint']['hash']==leaf.hex()
                    assert config[-89:]==b'\x02'+core.uint(0,6)+core.uint(1,6)+leaf+core.uint(1,6)*2+core.root([])
                    # Reject a missing empty descriptor and a false empty hash.
                    for bad in [config[:-89]+b'\x01'+config[-88:-44],
                                config[:-32]+bytes(32)]:
                        invalid=temp/'invalid-trust.bin';invalid.write_bytes(bad)
                        result=subprocess.run([str(temp/'check'),str(invalid),'1',
                                               str(out/'landmark-0000.der')],capture_output=True)
                        assert result.returncode==1,result.stderr.decode()
                # Check every index in both certificate modes.
                for index in range(n):
                    for mode,trust in [('standalone','authority.bin'),('landmark','trust.bin')]:
                        result=subprocess.run([str(temp/'check'),str(out/trust),
                                               str(int(mode=='landmark')),
                                               str(out/f'{mode}-{index:04d}.der')],capture_output=True)
                        assert result.returncode==0,(family,n,index,mode,result.stderr.decode())

                # Sections 6.4.4 and 7.4: an evolved landmark-relative
                # certificate is trusted only after its subtree is configured.
                if n==16:
                    from landmarks import Landmark,relative_proof

                    sequence=[
                        Landmark(0,0,0),
                        Landmark(1,8,expiration),
                        Landmark(2,16,expiration+1),
                    ]
                    entries=[
                        (out/'log'/f'{i:06d}.entry').read_bytes()
                        for i in range(n)
                    ]
                    source_cert=(out/'landmark-0000.der').read_bytes()
                    outer,_=core.certificate_parts(source_cert)
                    tbs=outer[0][2]

                    landmark,start,end,path=relative_proof(
                        entries,0,sequence
                    )
                    assert landmark.number==1
                    assert (start,end)==(0,4)
                    assert len(path)==2
                    assert core.entry(tbs)==entries[0]

                    subtree_hash=core.root(entries[start:end])
                    relative=temp/f'{family}-landmark-relative.der'
                    relative.write_bytes(
                        core.certificate(
                            tbs,
                            core.proof(start,end,path,()),
                        )
                    )

                    # The historical checkpoint subtrees are (0,8) and
                    # (8,16), so the new (0,4) certificate must fail
                    # without explicit Section 7.4 configuration.
                    legacy=subprocess.run([
                        str(temp/'check'),
                        str(out/'trust.bin'),
                        '1',
                        str(relative),
                    ],capture_output=True)
                    assert legacy.returncode==1,(
                        family,'unexpected legacy landmark acceptance',
                        legacy.stderr.decode()
                    )

                    configured=subprocess.run([
                        str(temp/'check_trusted_subtree'),
                        str(out/'trust.bin'),
                        str(relative),
                        '1',
                        str(start),
                        str(end),
                        subtree_hash.hex(),
                    ],capture_output=True)
                    assert configured.returncode==0,(
                        family,'trusted-subtree verification',
                        configured.stdout.decode(),
                        configured.stderr.decode()
                    )
                    assert (
                        b'PASS: real landmark-relative certificate obeys '
                        b'trusted-subtree policy'
                        in configured.stdout
                    )
                    print(
                        f'PASS {family}: evolved landmark-relative '
                        'certificate and trusted-subtree verification',
                        flush=True,
                    )

            env=dict(os.environ,MTC_BATCH=str(batch),MTC_CHECK=str(temp/'check'),
                     MTC_TEST_FAMILIES=','.join(args.profiles),PYTHONDONTWRITEBYTECODE='1')
            subprocess.run([sys.executable,'-B',str(source/'test_verifier.py')],env=env,check=True)
            print(f'PASS N={n}: generation, static landmarks, native verification and negatives',flush=True)
    print('PASS: draft-06 local migration tests; temporary fixtures removed')


if __name__=='__main__':main()
