"""Focused MTC-07 CA-certificate generation test; no fixtures are retained."""
import argparse
import os
import subprocess
import tempfile
from pathlib import Path

import core
import prepare
from config_formats import (MCA2Authority, encode_mca2,
                            reconcile_mtc_ca_certificate)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--profile',default='ecdsa-p256')
    args=parser.parse_args()
    profile=prepare.crypto_profile(args.profile)
    with tempfile.TemporaryDirectory(prefix='mtc-ca-certificate-') as directory:
        root=Path(directory);ca_key=root/'ca-cosigner.key'
        prepare.keygen(ca_key,args.profile)
        other_key=root/'other-cosigner.key'
        prepare.keygen(other_key,args.profile)
        first,last=1<<48,(1<<48)+15
        paths=prepare.generate_mtc_ca_hierarchy(
            root/'hierarchy',args.profile,profile['ca_id'],ca_key,first,last)
        cert=paths['ca_certificate_der'].read_bytes()
        outer,tbs=core.certificate_parts(cert)
        assert outer[1][2]==prepare.signature_algorithm_identifier(args.profile)
        assert tbs[5][2]==core.name(profile['ca_id'])
        extensions=core.items(core.content(tbs[-1][2],0xa3))
        assert len(extensions)==1 and extensions[0][0]==0x30
        encoded=core.items(core.content(extensions[0][2],0x30))
        mtc=[value[2] for value in encoded
             if core.items(core.content(value[2],0x30))[0][2]==core.oid(core.MTC_CA_OID)]
        assert len(mtc)==1
        assert core.parse_mtc_ca_extension(mtc[0])==(
            prepare.signature_algorithm_identifier(args.profile),first,last)
        ca_spki=prepare.command('pkey','-in',ca_key,'-pubout','-outform','DER')
        other_spki=prepare.command('pkey','-in',other_key,'-pubout','-outform','DER')
        authority=MCA2Authority(profile['ca_id'],
            ((profile['ca_id'],ca_spki),('32473.999',other_spki)),
            1,first,last)
        reconciled=reconcile_mtc_ca_certificate(authority,cert)
        assert reconciled['ca_id']==profile['ca_id'] and reconciled['spki']==ca_spki
        for inconsistent in (
                MCA2Authority('32473.999',authority.signers,1,first,last),
                MCA2Authority(profile['ca_id'],authority.signers,1,first,last-1)):
            try:reconcile_mtc_ca_certificate(inconsistent,cert)
            except ValueError:pass
            else:raise AssertionError('accepted inconsistent MCA2 authority')
        native_checker=os.environ.get('MTC_NATIVE_CA_CHECK')
        if native_checker:
            authority_path=root/'authority.bin'
            authority_path.write_bytes(encode_mca2(authority))
            subprocess.run([native_checker,authority_path,
                            paths['ca_certificate'],
                            paths['root_certificate']],check=True)
            def rejected(candidate_authority,candidate_certificate,candidate_root):
                candidate_path=root/'rejected-authority.bin'
                candidate_path.write_bytes(encode_mca2(candidate_authority))
                result=subprocess.run(
                    [native_checker,candidate_path,candidate_certificate,candidate_root],
                    capture_output=True,text=True)
                assert result.returncode!=0,result.stdout+result.stderr

            alternate=prepare.generate_mtc_ca_hierarchy(
                root/'alternate',args.profile,profile['ca_id'],other_key,first,last)
            rejected(authority,paths['ca_certificate'],alternate['root_certificate'])
            rejected(MCA2Authority(profile['ca_id'],
                ((profile['ca_id'],other_spki),('32473.999',ca_spki)),1,first,last),
                paths['ca_certificate'],paths['root_certificate'])
            rejected(MCA2Authority(profile['ca_id'],authority.signers,1,first,last-1),
                paths['ca_certificate'],paths['root_certificate'])

            wrong_oid=('1.2.840.10045.4.3.3'
                       if profile['signature_algorithm_oid']=='1.2.840.10045.4.3.2'
                       else '1.2.840.10045.4.3.2')
            wrong_algorithm=core.seq(core.oid(wrong_oid))
            wrong_extensions=[]
            for value in encoded:
                fields=core.items(core.content(value[2],0x30))
                wrong_extensions.append(
                    core.mtc_ca_extension(wrong_algorithm,first,last)
                    if fields[0][2]==core.oid(core.MTC_CA_OID) else value[2])
            wrong_tbs_fields=[value[2] for value in tbs]
            wrong_tbs_fields[-1]=core.der(0xa3,core.seq(*wrong_extensions))
            wrong_tbs=core.seq(*wrong_tbs_fields)
            wrong_signature=prepare.sign(paths['root_key'],wrong_tbs,args.profile)
            wrong_certificate=core.seq(
                wrong_tbs,outer[1][2],core.der(3,b'\0'+wrong_signature))
            wrong_certificate_path=root/'wrong-algorithm.pem'
            wrong_certificate_path.write_bytes(core.pem(wrong_certificate))
            try:reconcile_mtc_ca_certificate(authority,wrong_certificate)
            except ValueError:pass
            else:raise AssertionError('accepted inconsistent CA signature algorithm')
            rejected(authority,wrong_certificate_path,paths['root_certificate'])
        try:
            prepare.command('verify','-ignore_critical','-CAfile',
                            paths['root_certificate'],paths['ca_certificate'])
        except subprocess.CalledProcessError as error:
            raise AssertionError(
                'OpenSSL verification failed:\n'+error.stderr.decode(errors='replace')) from error
    print(f'PASS: MTC-07 CA certificate hierarchy ({args.profile})')


if __name__=='__main__':main()
