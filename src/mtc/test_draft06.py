"""Offline migration tests; all keys, certificates and binaries are temporary."""
import argparse
import json
import os
import socket
import time
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

import core
import prepare


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--openssl-prefix',type=Path,required=True,
                        help='Installed OpenSSL 3 development prefix containing include and lib')
    parser.add_argument('--openssl-bin',type=Path,
                        help='OpenSSL executable under test; defaults to PREFIX/bin/openssl')
    parser.add_argument('--cc',default='cc')
    parser.add_argument('--persistent',action='store_true',
                        help='Also generate N=16 material from an authenticated persistent log')
    parser.add_argument('--injection-only',action='store_true',
                        help='Run the focused N=1 external-cosigner injection path')
    parser.add_argument('--cli-cosigner-only',action='store_true',
                        help='Run focused standalone generation through CosignerCLIClient')
    parser.add_argument('--http-cosigner-only',action='store_true',
                        help='Run focused standalone generation through CosignerHTTPClient')
    parser.add_argument('--profiles',nargs=2,default=['ecdsa-p256','mldsa65'])
    args=parser.parse_args()
    if args.profiles[0]==args.profiles[1]:parser.error('Two distinct profiles are required')
    source=Path(__file__).resolve().parent
    prefix=args.openssl_prefix.resolve()
    openssl_bin=(args.openssl_bin.resolve()
                 if args.openssl_bin is not None
                 else prefix/'bin/openssl')
    if not openssl_bin.is_file():
        parser.error('OpenSSL executable missing')
    prepare.OPENSSL=str(openssl_bin)
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
        sizes=([16] if (args.cli_cosigner_only or args.http_cosigner_only) else
               ([1] if args.injection_only else [1,16]))
        for n in sizes:
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
                if args.http_cosigner_only:
                    from threading import Thread
                    from cosigner_http_client import CosignerHTTPClient
                    from cosigner_http_service import CosignerHTTPServer

                    profile=prepare.crypto_profile(family)
                    signer_keys=[temp/f'{family}-http-signer-{i}.key'
                                 for i in range(2)]
                    for key in signer_keys:prepare.keygen(key,family)
                    external_public=temp/f'{family}-http-external.pub'
                    external_public.write_bytes(prepare.command(
                        'pkey','-in',signer_keys[1],'-pubout'))
                    state_path=temp/f'{family}-http-state.json'

                    class RecordingHTTPClient(CosignerHTTPClient):
                        def __init__(self,*values,**kwargs):
                            super().__init__(*values,**kwargs)
                            self.calls=[];self.http_operations=[]
                        def _post(self,path,value):
                            self.http_operations.append(path)
                            return super()._post(path,value)
                        def accept_view(self,*values):
                            self.calls.append(('accept_view',values))
                            return super().accept_view(*values)
                        def cosign_accepted(self,*values):
                            result=super().cosign_accepted(*values)
                            self.calls.append(('cosign_accepted',values,result))
                            return result
                        def cosign_subtree(self,*values):
                            result=super().cosign_subtree(*values)
                            self.calls.append(('cosign_subtree',values,result))
                            return result

                    encoded=[core.entry(core.mtc_tbs(
                        core.from_pem(before),profile['ca_id'],i))
                        for i in range(n)]
                    checkpoint=core.root(encoded)
                    initial_proof=core.consistency(encoded,0)
                    server=CosignerHTTPServer(
                        ('127.0.0.1',0),profile['cosigner_ids'][1],
                        signer_keys[1],profile['ca_id'],family,state_path)
                    thread=Thread(target=server.serve_forever,daemon=True)
                    thread.start()
                    host,port=server.server_address
                    client=RecordingHTTPClient(
                        f'http://{host}:{port}',timeout=2)
                    try:
                        with patch(
                                'cosigner.ExternalCosigner',
                                side_effect=AssertionError('local fallback')):
                            meta=prepare.prepare(
                                out,temp,family,n,originals=[cert]*n,
                                signer_keys=signer_keys,
                                external_cosigner=client,
                                external_consistency_proof=initial_proof)

                        assert client.calls[0]==(
                            'accept_view',(n,checkpoint,initial_proof))
                        assert client.calls[0][1][2] is initial_proof
                        subtree_calls=[call for call in client.calls
                                       if call[0]=='cosign_subtree']
                        assert len(subtree_calls)==len(core.cover(0,n))==2
                        assert client.http_operations==[
                            '/accept-view','/cosign-accepted',
                            '/cosign-subtree','/cosign-subtree']

                        persisted=json.loads(state_path.read_text())
                        assert persisted=={
                            'tree_size':n,'root_hash':checkpoint.hex()}
                        checkpoint_call=next(
                            call for call in client.calls
                            if call[0]=='cosign_accepted')
                        timestamp=checkpoint_call[1][0]
                        checkpoint_identity,checkpoint_signature=(
                            checkpoint_call[2])

                        def verify_http_external(message,signature,label):
                            message_path=temp/f'{family}-{label}.message'
                            signature_path=temp/f'{family}-{label}.signature'
                            message_path.write_bytes(message)
                            signature_path.write_bytes(signature)
                            selected=prepare.crypto_profile(family)
                            prepare.command(
                                'pkeyutl','-verify','-rawin','-pubin',
                                '-inkey',external_public,'-in',message_path,
                                '-sigfile',signature_path,
                                *(['-digest',selected['digest']]
                                  if selected['digest'] else []))

                        verify_http_external(core.message(
                            checkpoint_identity,profile['ca_id'],0,n,
                            checkpoint,timestamp,1),checkpoint_signature,
                            'http-checkpoint')
                        trust=(out/'trust.bin').read_bytes()
                        checkpoint_encoding=(
                            core.vec(core.relid(checkpoint_identity),1)
                            +core.vec(checkpoint_signature))
                        assert checkpoint_encoding in trust

                        generated=[
                            (out/'log'/f'{i:06d}.entry').read_bytes()
                            for i in range(n)]
                        assert generated==encoded
                        for call,(start,end) in zip(
                                subtree_calls,core.cover(0,n)):
                            values=call[1]
                            identity,signature=call[2]
                            subtree_hash=core.root(encoded[start:end])
                            assert values[:3]==(start,end,subtree_hash)
                            assert core.verify_subtree_consistency(
                                start,end,n,subtree_hash,checkpoint,values[3])
                            verify_http_external(core.message(
                                identity,profile['ca_id'],start,end,
                                subtree_hash,0,1),signature,
                                f'http-subtree-{start}-{end}')
                            index=start
                            standalone=(
                                out/f'standalone-{index:04d}.der').read_bytes()
                            outer,_=core.certificate_parts(standalone)
                            mtc_proof=outer[2][1][1:]
                            path=core.inclusion(
                                encoded[start:end],index-start)
                            assert mtc_proof.startswith(
                                core.vec(b'')+core.uint(start,6)
                                +core.uint(end,6)+core.vec(b''.join(path)))
                            external_encoding=(
                                core.vec(core.relid(identity),1)
                                +core.vec(signature))
                            assert external_encoding in mtc_proof
                            ca_marker=core.vec(core.relid(
                                profile['cosigner_ids'][0]),1)
                            external_marker=core.vec(core.relid(
                                profile['cosigner_ids'][1]),1)
                            assert 0<=mtc_proof.find(
                                ca_marker)<mtc_proof.find(external_marker)

                        for index in range(n):
                            result=subprocess.run([
                                str(temp/'check'),str(out/'authority.bin'),'0',
                                str(out/f'standalone-{index:04d}.der')],
                                capture_output=True)
                            assert result.returncode==0,(
                                family,index,result.stderr.decode())
                        assert meta['subtrees']==core.cover(0,n)
                        print(
                            f'PASS {family}: standalone through '
                            'CosignerHTTPClient',flush=True)
                    finally:
                        server.shutdown()
                        server.server_close()
                        thread.join(timeout=2)
                        assert not thread.is_alive()
                    continue
                if args.cli_cosigner_only:
                    from cosigner_client import CosignerCLIClient

                    profile=prepare.crypto_profile(family)
                    signer_keys=[temp/f'{family}-cli-signer-{i}.key'
                                 for i in range(2)]
                    for key in signer_keys:prepare.keygen(key,family)
                    external_public=temp/f'{family}-cli-external.pub'
                    external_public.write_bytes(prepare.command(
                        'pkey','-in',signer_keys[1],'-pubout'))
                    state_path=temp/f'{family}-cli-state.json'
                    python_wrapper=temp/'python-with-mtc-openssl'
                    python_wrapper.write_text(
                        '#!'+sys.executable+'\n'
                        'import runpy,sys\n'
                        f'sys.path.insert(0,{str(source)!r})\n'
                        'import prepare\n'
                        f'prepare.OPENSSL={prepare.OPENSSL!r}\n'
                        'target=sys.argv.pop(1)\n'
                        "runpy.run_path(target,run_name='__main__')\n")
                    python_wrapper.chmod(0o700)

                    class RecordingCLIClient(CosignerCLIClient):
                        def __init__(self,*values,**kwargs):
                            super().__init__(*values,**kwargs)
                            self.calls=[];self.process_operations=[]
                        def _run(self,operation):
                            self.process_operations.append(operation[0])
                            return super()._run(operation)
                        def accept_view(self,*values):
                            self.calls.append(('accept_view',values))
                            return super().accept_view(*values)
                        def cosign_accepted(self,*values):
                            result=super().cosign_accepted(*values)
                            self.calls.append(('cosign_accepted',values,result))
                            return result
                        def cosign_subtree(self,*values):
                            result=super().cosign_subtree(*values)
                            self.calls.append(('cosign_subtree',values,result))
                            return result

                    encoded=[core.entry(core.mtc_tbs(
                        core.from_pem(before),profile['ca_id'],i))
                        for i in range(n)]
                    checkpoint=core.root(encoded)
                    initial_proof=core.consistency(encoded,0)
                    client=RecordingCLIClient(
                        profile['cosigner_ids'][1],signer_keys[1],
                        profile['ca_id'],family,state_path,
                        python_executable=python_wrapper)
                    with patch('cosigner.ExternalCosigner',
                               side_effect=AssertionError('local fallback')):
                        meta=prepare.prepare(
                            out,temp,family,n,originals=[cert]*n,
                            signer_keys=signer_keys,
                            external_cosigner=client,
                            external_consistency_proof=initial_proof)

                    assert client.calls[0]==(
                        'accept_view',(n,checkpoint,initial_proof))
                    assert client.calls[0][1][2] is initial_proof
                    subtree_calls=[call for call in client.calls
                                   if call[0]=='cosign_subtree']
                    assert len(subtree_calls)==len(core.cover(0,n))==2
                    assert client.process_operations==[
                        'accept-view','cosign-accepted',
                        'cosign-subtree','cosign-subtree']

                    persisted=json.loads(state_path.read_text())
                    assert persisted=={
                        'tree_size':n,'root_hash':checkpoint.hex()}
                    checkpoint_call=next(
                        call for call in client.calls
                        if call[0]=='cosign_accepted')
                    timestamp=checkpoint_call[1][0]
                    checkpoint_identity,checkpoint_signature=checkpoint_call[2]

                    def verify_external(message,signature,label):
                        message_path=temp/f'{family}-{label}.message'
                        signature_path=temp/f'{family}-{label}.signature'
                        message_path.write_bytes(message)
                        signature_path.write_bytes(signature)
                        selected=prepare.crypto_profile(family)
                        prepare.command(
                            'pkeyutl','-verify','-rawin','-pubin',
                            '-inkey',external_public,'-in',message_path,
                            '-sigfile',signature_path,
                            *(['-digest',selected['digest']]
                              if selected['digest'] else []))

                    verify_external(core.message(
                        checkpoint_identity,profile['ca_id'],0,n,checkpoint,
                        timestamp,1),checkpoint_signature,'checkpoint')
                    trust=(out/'trust.bin').read_bytes()
                    checkpoint_encoding=(
                        core.vec(core.relid(checkpoint_identity),1)
                        +core.vec(checkpoint_signature))
                    assert checkpoint_encoding in trust

                    generated=[(out/'log'/f'{i:06d}.entry').read_bytes()
                               for i in range(n)]
                    assert generated==encoded
                    for call,(start,end) in zip(
                            subtree_calls,core.cover(0,n)):
                        values=call[1]
                        identity,signature=call[2]
                        subtree_hash=core.root(encoded[start:end])
                        assert values[:3]==(start,end,subtree_hash)
                        assert core.verify_subtree_consistency(
                            start,end,n,subtree_hash,checkpoint,values[3])
                        verify_external(core.message(
                            identity,profile['ca_id'],start,end,
                            subtree_hash,0,1),signature,
                            f'subtree-{start}-{end}')
                        index=start
                        standalone=(out/f'standalone-{index:04d}.der').read_bytes()
                        outer,_=core.certificate_parts(standalone)
                        mtc_proof=outer[2][1][1:]
                        path=core.inclusion(encoded[start:end],index-start)
                        assert mtc_proof.startswith(
                            core.vec(b'')+core.uint(start,6)+core.uint(end,6)
                            +core.vec(b''.join(path)))
                        external_encoding=(
                            core.vec(core.relid(identity),1)+core.vec(signature))
                        assert external_encoding in mtc_proof
                        ca_marker=core.vec(core.relid(profile['cosigner_ids'][0]),1)
                        external_marker=core.vec(
                            core.relid(profile['cosigner_ids'][1]),1)
                        assert 0<=mtc_proof.find(ca_marker)<mtc_proof.find(
                            external_marker)

                    for index in range(n):
                        result=subprocess.run([
                            str(temp/'check'),str(out/'authority.bin'),'0',
                            str(out/f'standalone-{index:04d}.der')],
                            capture_output=True)
                        assert result.returncode==0,(
                            family,index,result.stderr.decode())
                    assert meta['subtrees']==core.cover(0,n)
                    print(
                        f'PASS {family}: standalone through '
                        'CosignerCLIClient',flush=True)
                    continue
                from cosigner import ExternalCosigner
                accepted=[];signed_subtrees=[]
                original_accept=ExternalCosigner.accept_view
                original_cosign_subtree=ExternalCosigner.cosign_subtree
                def record_accept(self,*values,**kwargs):
                    accepted.append((self,values,kwargs))
                    return original_accept(self,*values,**kwargs)
                def record_subtree(self,*values,**kwargs):
                    signed_subtrees.append((self,values,kwargs))
                    return original_cosign_subtree(self,*values,**kwargs)
                with patch.object(ExternalCosigner,'accept_view',record_accept), \
                     patch.object(ExternalCosigner,'cosign_subtree',record_subtree):
                    meta=prepare.prepare(out,temp,family,n,originals=[cert]*n,**options)
                assert len(accepted)==1
                external,values,kwargs=accepted[0]
                assert not kwargs and values==(n,core.root([
                    (out/'log'/f'{i:06d}.entry').read_bytes() for i in range(n)
                ]),core.consistency([
                    (out/'log'/f'{i:06d}.entry').read_bytes() for i in range(n)
                ],0))
                assert external.identity==prepare.crypto_profile(family)['cosigner_ids'][1]
                assert external.key==out/'cosigner-1.key'
                assert len(signed_subtrees)==len(core.cover(0,n))
                for recorded,(start,end) in zip(signed_subtrees,core.cover(0,n)):
                    signer,values,kwargs=recorded
                    subtree_hash=core.root([
                        (out/'log'/f'{i:06d}.entry').read_bytes()
                        for i in range(start,end)
                    ])
                    assert signer is external and not kwargs
                    assert values[:3]==(start,end,subtree_hash)
                    assert core.verify_subtree_consistency(
                        start,end,n,subtree_hash,
                        bytes.fromhex(meta['checkpoint']['hash']),values[3])
                if n==1 and family==args.profiles[0]:
                    bad_consistency=temp/'rejected-external-consistency'
                    with patch.object(prepare,'consistency',return_value=[core.root([])]), \
                         patch.object(ExternalCosigner,'cosign_subtree') as subtree_sign:
                        try:prepare.prepare(bad_consistency,temp,family,n,originals=[cert]*n)
                        except ValueError:pass
                        else:raise AssertionError('Accepted invalid external consistency proof')
                    subtree_sign.assert_not_called()
                    bad_subtree=temp/'rejected-external-subtree'
                    with patch.object(prepare,'subtree_consistency',return_value=[core.root([])]):
                        try:prepare.prepare(bad_subtree,temp,family,n,originals=[cert]*n)
                        except ValueError:pass
                        else:raise AssertionError('Accepted invalid subtree consistency proof')
                    class RecordingCosigner:
                        def __init__(self,delegate):
                            self.delegate=delegate;self.calls=[];self.signatures=[]
                        def accept_view(self,*values):
                            self.calls.append(('accept_view',values))
                            return self.delegate.accept_view(*values)
                        def cosign_accepted(self,*values):
                            self.calls.append(('cosign_accepted',values))
                            result=self.delegate.cosign_accepted(*values)
                            self.signatures.append(result);return result
                        def cosign_subtree(self,*values):
                            self.calls.append(('cosign_subtree',values))
                            result=self.delegate.cosign_subtree(*values)
                            self.signatures.append(result);return result
                    injected_proof=[]
                    delegate=ExternalCosigner(
                        prepare.crypto_profile(family)['cosigner_ids'][1],
                        out/'cosigner-1.key',
                        prepare.crypto_profile(family)['ca_id'],family)
                    injected=RecordingCosigner(delegate)
                    injected_out=temp/f'{family}-injected'
                    with patch('cosigner.ExternalCosigner',side_effect=AssertionError('fallback')):
                        injected_meta=prepare.prepare(
                            injected_out,temp,family,n,originals=[cert]*n,
                            signer_keys=[out/'cosigner-0.key',out/'cosigner-1.key'],
                            external_cosigner=injected,
                            external_consistency_proof=injected_proof)
                    injected_entries=[
                        (injected_out/'log'/f'{i:06d}.entry').read_bytes()
                        for i in range(n)
                    ]
                    injected_checkpoint=core.root(injected_entries)
                    assert injected.calls[0]==(
                        'accept_view',(n,injected_checkpoint,injected_proof))
                    assert injected.calls[0][1][2] is injected_proof
                    assert injected.calls[1][0]=='cosign_accepted'
                    subtree_calls=[call for call in injected.calls
                                   if call[0]=='cosign_subtree']
                    assert len(subtree_calls)==len(core.cover(0,n))
                    assert [call[1][:2] for call in subtree_calls]==core.cover(0,n)
                    standalone=(injected_out/'standalone-0000.der').read_bytes()
                    outer,_=core.certificate_parts(standalone)
                    encoded_proof=outer[2][1][1:]
                    start,end=core.cover(0,n)[0]
                    path=core.inclusion(injected_entries[start:end],0)
                    assert encoded_proof.startswith(
                        core.vec(b'')+core.uint(start,6)+core.uint(end,6)
                        +core.vec(b''.join(path)))
                    external_signature=injected.signatures[1][1]
                    assert core.vec(core.relid(delegate.identity),1)+core.vec(
                        external_signature) in encoded_proof
                    assert injected_meta['subtrees']==meta['subtrees']

                    missing=temp/f'{family}-injected-missing-proof'
                    try:prepare.prepare(
                        missing,temp,family,n,originals=[cert]*n,
                        external_cosigner=injected)
                    except ValueError as error:
                        assert str(error)==(
                            'Injected external cosigner requires an explicit '
                            'consistency proof')
                    else:raise AssertionError('Accepted injected cosigner without proof')
                    assert not missing.exists()

                    class FailingCosigner:
                        def __init__(self,operation):self.operation=operation
                        def accept_view(self,*values):
                            if self.operation=='accept_view':raise RuntimeError(self.operation)
                        def cosign_accepted(self,*values):
                            if self.operation=='cosign_accepted':raise RuntimeError(self.operation)
                            return delegate.identity,b'checkpoint'
                        def cosign_subtree(self,*values):
                            raise RuntimeError('cosign_subtree')
                    for operation in ['accept_view','cosign_accepted','cosign_subtree']:
                        failed=temp/f'{family}-injected-failed-{operation}'
                        with patch('cosigner.ExternalCosigner',side_effect=AssertionError('fallback')):
                            try:prepare.prepare(
                                failed,temp,family,n,originals=[cert]*n,
                                signer_keys=[out/'cosigner-0.key',out/'cosigner-1.key'],
                                external_cosigner=FailingCosigner(operation),
                                external_consistency_proof=[])
                            except RuntimeError as error:assert str(error)==operation
                            else:raise AssertionError('Ignored '+operation+' failure')
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

                    from trusted_subtrees import (
                        TrustedSubtree,
                        encode_trusted_subtrees,
                    )

                    mts1=temp/f'{family}-trusted-subtrees.mts1'
                    mts1.write_bytes(
                        encode_trusted_subtrees([
                            TrustedSubtree(
                                1,start,end,subtree_hash
                            )
                        ])
                    )

                    configured=subprocess.run([
                        str(temp/'check_trusted_subtree'),
                        str(out/'trust.bin'),
                        str(relative),
                        str(mts1),
                    ],capture_output=True)
                    assert configured.returncode==0,(
                        family,'MTS1 trusted-subtree verification',
                        configured.stdout.decode(),
                        configured.stderr.decode()
                    )
                    assert (
                        b'PASS: real landmark-relative certificate obeys '
                        b'MTS1 trusted-subtree policy'
                        in configured.stdout
                    )

                    wrong_hash=bytes([
                        subtree_hash[0]^1
                    ])+subtree_hash[1:]
                    wrong_mts1=temp/f'{family}-wrong-trusted-subtrees.mts1'
                    wrong_mts1.write_bytes(
                        encode_trusted_subtrees([
                            TrustedSubtree(
                                1,start,end,wrong_hash
                            )
                        ])
                    )

                    wrong=subprocess.run([
                        str(temp/'check_trusted_subtree'),
                        str(out/'trust.bin'),
                        str(relative),
                        str(wrong_mts1),
                    ],capture_output=True)
                    assert wrong.returncode!=0,(
                        family,
                        'wrong MTS1 subtree hash unexpectedly accepted',
                        wrong.stdout.decode(),
                        wrong.stderr.decode(),
                    )

                    # Sections 6.4.4 and 7.4 through the real TLS 1.3 path.
                    # The landmark-relative certificate reuses the original
                    # leaf TBS, so the synthetic population key remains its
                    # corresponding private key.
                    relative_pem=temp/f'{family}-landmark-relative.pem'
                    relative_pem.write_bytes(core.pem(relative.read_bytes()))

                    def tls_case(mts1_path,expect_success):
                        # Ask the kernel for an unused loopback port.  Close
                        # the reservation before s_server binds it; readiness
                        # below is detected from s_server's ACCEPT message,
                        # never by consuming an -naccept connection.
                        with socket.socket(
                            socket.AF_INET,socket.SOCK_STREAM
                        ) as reserved:
                            reserved.bind(('127.0.0.1',0))
                            port=reserved.getsockname()[1]

                        server=[
                            prepare.OPENSSL,'s_server',
                            '-accept',str(port),
                            '-cert',str(relative_pem),
                            '-key',str(temp/(family+'.key')),
                            '-mtc_id',meta['ca_id']+'.1.1.1',
                            '-num_tickets','0',
                            '-www',
                            '-naccept','1',
                            '-tls1_3',
                            '-groups','X25519',
                            '-ciphersuites','TLS_AES_256_GCM_SHA384',
                        ]

                        server_log=temp/f'{family}-tls-server.log'
                        with server_log.open('w+') as log:
                            process=subprocess.Popen(
                                server,
                                stdout=log,
                                stderr=subprocess.STDOUT,
                                text=True,
                            )
                            try:
                                deadline=time.monotonic()+10
                                while True:
                                    log.flush()
                                    log.seek(0)
                                    server_text=log.read()
                                    if 'ACCEPT' in server_text:
                                        break
                                    if process.poll() is not None:
                                        raise AssertionError((
                                            family,
                                            'TLS server exited before readiness',
                                            process.returncode,
                                            server_text,
                                        ))
                                    if time.monotonic()>deadline:
                                        raise AssertionError((
                                            family,
                                            'TLS server readiness timeout',
                                            server_text,
                                        ))
                                    time.sleep(.05)

                                client=[
                                    prepare.OPENSSL,'s_client',
                                    '-connect',f'127.0.0.1:{port}',
                                    '-servername','offline-mtc-test',
                                    '-verify_hostname','offline-mtc-test',
                                    '-verify_return_error',
                                    '-mtc_trust',str(out/'trust.bin'),
                                    '-mtc_landmark',
                                    '-no_ticket',
                                    '-ign_eof',
                                    '-tls1_3',
                                    '-groups','X25519',
                                    '-ciphersuites',
                                    'TLS_AES_256_GCM_SHA384',
                                ]
                                if mts1_path is not None:
                                    client += [
                                        '-mtc_trusted_subtrees',
                                        str(mts1_path),
                                    ]

                                result=subprocess.run(
                                    client,
                                    input='GET / HTTP/1.0\r\n\r\n',
                                    capture_output=True,
                                    text=True,
                                    timeout=30,
                                )
                                output=result.stdout+result.stderr

                                if expect_success:
                                    assert result.returncode==0,(
                                        family,
                                        'TLS MTS1 handshake failed',
                                        output,
                                    )
                                    assert 'MTC verification: OK' in output,(
                                        family,
                                        'missing MTC verification',
                                        output,
                                    )
                                    assert 'HTTP/1.0 200' in output,(
                                        family,
                                        'missing HTTP response',
                                        output,
                                    )
                                    assert (
                                        'New, TLSv1.3, Cipher is '
                                        'TLS_AES_256_GCM_SHA384'
                                    ) in output,(
                                        family,
                                        'wrong TLS version/cipher',
                                        output,
                                    )
                                    assert (
                                        'Peer Temp Key: X25519' in output
                                        or 'Server Temp Key: X25519' in output
                                    ),(
                                        family,
                                        'wrong TLS group',
                                        output,
                                    )
                                else:
                                    assert not (
                                        result.returncode==0
                                        and 'MTC verification: OK' in output
                                        and 'HTTP/1.0 200' in output
                                    ),(
                                        family,
                                        'unexpected TLS authentication success',
                                        output,
                                    )
                            finally:
                                if process.poll() is None:
                                    process.terminate()
                                try:
                                    process.wait(timeout=5)
                                except subprocess.TimeoutExpired:
                                    process.kill()
                                    process.wait()

                    # Historical checkpoint subtrees do not contain (0,4).
                    tls_case(None,False)

                    # The validated relying-party subtree enables the evolved
                    # landmark-relative certificate.
                    tls_case(mts1,True)

                    # An explicitly configured matching tuple with a wrong
                    # hash must fail closed and must not fall back to the
                    # historical checkpoint subtrees.
                    tls_case(wrong_mts1,False)

                    # MTS1 is meaningful only in landmark mode.  Reject this
                    # configuration before attempting a network handshake.
                    no_landmark=subprocess.run([
                        prepare.OPENSSL,'s_client',
                        '-mtc_trust',str(out/'trust.bin'),
                        '-mtc_trusted_subtrees',str(mts1),
                    ],capture_output=True,text=True,timeout=10)

                    no_landmark_output=(
                        no_landmark.stdout+no_landmark.stderr
                    )
                    assert no_landmark.returncode!=0,(
                        family,
                        'MTS1 without landmark unexpectedly accepted',
                        no_landmark_output,
                    )
                    assert (
                        'MTC-experimental configuration rejected'
                        in no_landmark_output
                    ),(
                        family,
                        'MTS1 without landmark did not fail closed',
                        no_landmark_output,
                    )

                    print(
                        f'PASS {family}: landmark-relative MTS1 TLS 1.3 '
                        'positive and negative cases',
                        flush=True,
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
