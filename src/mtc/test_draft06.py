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
        for name in ['test_ids','check']:
            subprocess.run([args.cc,'-Wall','-Wextra','-g',
                            '-fsanitize=address,undefined','-fno-omit-frame-pointer',
                            '-I'+str(prefix/'include'),str(source/(name+'.c')),
                            '-L'+str(lib),'-Wl,-rpath,'+str(lib),'-lcrypto',
                            '-o',str(temp/name)],check=True)
        subprocess.run([str(temp/'test_ids')],check=True)
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
                meta=prepare.prepare(out,temp,family,n,originals=[cert]*n)
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
            env=dict(os.environ,MTC_BATCH=str(batch),MTC_CHECK=str(temp/'check'),
                     MTC_TEST_FAMILIES=','.join(args.profiles),PYTHONDONTWRITEBYTECODE='1')
            subprocess.run([sys.executable,'-B',str(source/'test_verifier.py')],env=env,check=True)
            print(f'PASS N={n}: generation, static landmarks, native verification and negatives',flush=True)
    print('PASS: draft-06 local migration tests; temporary fixtures removed')


if __name__=='__main__':main()
