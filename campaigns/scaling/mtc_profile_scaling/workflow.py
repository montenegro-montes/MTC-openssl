#!/usr/bin/env python3
"""Manual-only MTC preparation; first gate is nine profiles, N=16, two modes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time

REPO=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(REPO/'src/mtc'))
import core
import prepare
from crypto_profiles import SIGNATURE_PROFILES, TREE_SIZES, TREE_HASH, DRAFT
from local_log import LocalLog
from snapshots import export_snapshot, authenticate_snapshot, verify_snapshot_consistency
HERE=Path(__file__).resolve().parent
OPENSSL='/opt/openssl/bin/openssl'
TLS_OPENSSL='/opt/mtc/openssl.sh'


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def dump(path,data):
    with path.open('x') as f:json.dump(data,f,indent=2);f.write('\n')
def read(path):return json.loads(path.read_text())
def hashes(root):return {str(p.relative_to(root)):sha(p) for p in sorted(root.rglob('*')) if p.is_file()}
def source_hashes():
    files=[REPO/'src/mtc'/x for x in (
        'crypto_profiles.py','prepare.py','core.py','local_log.py','snapshots.py',
        'check_snapshot.c','mtc.c','mtc.h','tls.c','patch.py')]
    files += [HERE/'workflow.py',HERE/'verify_profile.c']
    return {str(p.relative_to(REPO)):sha(p) for p in files}
def require_current_mtc_image():
    # Generation and validation must use binaries built from the mounted source.
    for filename in ('mtc.c','tls.c','patch.py','check_snapshot.c'):
        if sha(Path('/opt/mtc')/filename)!=sha(REPO/'src/mtc'/filename):
            raise ValueError('Rebuild MTC image before generation or validation: '+filename)
def checked(cmd,**kwargs):
    result=subprocess.run(list(map(str,cmd)),capture_output=True,**kwargs)
    if result.returncode:
        for stream in (result.stdout,result.stderr):
            print(stream.decode(errors='replace') if isinstance(stream,bytes) else stream,file=sys.stderr)
        result.check_returncode()
    return result


def provenance():
    # Called only inside an explicitly launched manual container.
    commits={k:Path(p).read_text().strip() for k,p in {
        'openssl':'/opt/openssl/SOURCE_COMMIT','liboqs':'/opt/oqs/SOURCE_COMMIT','oqs_provider':'/opt/oqs/PROVIDER_COMMIT'}.items()}
    provider=checked([OPENSSL,'list','-providers'],text=True).stdout
    version=re.search(r'OQS_VERSION_TEXT\s+"([^"]+)"',Path('/opt/oqs/include/oqs/oqsconfig.h').read_text())
    return dict(git_commit=os.environ['MTC_GIT_COMMIT'],git_status=os.environ['MTC_GIT_STATUS'],
        image_id=os.environ['MTC_IMAGE_ID'],openssl_version=checked([OPENSSL,'version','-a'],text=True).stdout,
        liboqs_version=version.group(1) if version else None,oqs_provider_commit=commits['oqs_provider'],
        source_commits=commits,providers=provider,source_hashes=source_hashes(),draft=DRAFT,merkle_hash=TREE_HASH)


def gate(report,fixtures,image_id):
    data=read(report)
    wanted={(name,mode) for name in SIGNATURE_PROFILES for mode in ('landmark','standalone')}
    rows=data.get('cells',[])
    if data.get('server_hostname','server')!='server':raise ValueError('Campaign gate requires the default server hostname')
    if not data.get('passed') or len(rows)!=18 or {(x['profile'],x['mtc_mode']) for x in rows}!=wanted:
        raise ValueError('N=16 gate must contain all nine profiles and both modes')
    if any(x.get('tree_size')!=16 or x.get('handshakes')!=1 or x.get('success') is not True for x in rows):
        raise ValueError('N=16 functional validation is incomplete')
    if data['provenance']['image_id']!=image_id or data['provenance']['source_hashes']!=source_hashes():
        raise ValueError('N=16 gate refers to different image/source code; revalidate first')
    if data['fixture_hashes']!=hashes(fixtures):raise ValueError('N=16 fixtures differ from gate')
    return data


def server_hostname(value):
    labels=value.split('.')
    if len(value)>253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in labels):
        raise argparse.ArgumentTypeError('Expected a DNS hostname (for example server.test)')
    return value


def populate(directory,name,count,server_hostname='server'):
    p=SIGNATURE_PROFILES[name];directory.mkdir(parents=True,exist_ok=True)
    digest=['-'+p['digest']] if p['digest'] else []
    ca_key=directory/'ca.key';ca=directory/'ca.pem'
    if not ca.exists():
        prepare.keygen(ca_key,name)
        prepare.command('req','-new','-x509','-key',ca_key,'-out',ca,'-days','30','-subj','/CN=Paper1 '+name,
                        '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign',*digest)
    for i in range(count):
        key=directory/f'{i}.key';cert=directory/f'{i}.pem'
        if cert.exists():continue  # Only a copied, gate-validated N=16 population.
        prepare.keygen(key,name);csr=directory/f'{i}.csr';ext=directory/f'{i}.cnf';dns=server_hostname if i==0 else f'member-{i}.lab'
        prepare.command('req','-new','-key',key,'-subj','/CN='+dns,'-out',csr,*digest)
        ext.write_text(f'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{dns}\n')
        prepare.command('x509','-req','-in',csr,'-CA',ca,'-CAkey',ca_key,'-set_serial',str(i+1),'-days','30','-extfile',ext,'-out',cert,*digest)
        csr.unlink();ext.unlink()
    prepare.command('verify','-CAfile',ca,'-purpose','sslserver',*[directory/f'{i}.pem' for i in range(count)])


def generate(args):
    require_current_mtc_image()
    sizes=sorted(set(args.sizes));prov=provenance();profiles=args.profile or list(SIGNATURE_PROFILES)
    print('Generating MTC fixtures (N='+','.join(map(str,sizes))+'):',flush=True)
    hostname_meta={'server_hostname':args.server_hostname} if args.server_hostname!='server' else {}
    if sizes!=[16] or args.seed_fixtures:gate(args.validated_n16,args.seed_fixtures,prov['image_id'])
    os.umask(0o077);args.output.mkdir(parents=True,exist_ok=False)
    population=args.output/'population'
    if args.seed_fixtures:shutil.copytree(args.seed_fixtures/'population',population)
    for position,name in enumerate(profiles,1):
        print(f'  [{position}/{len(profiles)}] {name} generating...',flush=True)
        populate(population/name,name,max(sizes),args.server_hostname)
        for n in sizes:
            out=args.output/f'batch{n}'/'mtc'/name;out.parent.mkdir(parents=True,exist_ok=True)
            originals=[population/name/f'{i}.pem' for i in range(n)]
            keys=([args.seed_fixtures/'batch16/mtc'/name/f'cosigner-{i}.key' for i in range(2)] if args.seed_fixtures else None)
            options={}

            # Fresh N=16 generation is bound to an authenticated persistent
            # append-only log. Scaling/seed-fixture paths retain their existing
            # generation semantics.
            if n==16 and not args.seed_fixtures:
                profile=prepare.crypto_profile(name)
                transparency=args.output/'transparency'/name
                transparency.mkdir(parents=True,exist_ok=False)

                keys=[transparency/f'cosigner-{i}.key' for i in range(2)]
                for key in keys:
                    prepare.keygen(key,name)

                public=[prepare.command('pkey','-in',key,'-pubout','-outform','DER')
                        for key in keys]
                trusted=transparency/'trusted-authority.bin'
                trusted.write_bytes(prepare.authority_config_v2(
                    profile['ca_id'],profile['cosigner_ids'],public,n))

                persistent=LocalLog(transparency/'persistent-log')
                encoded=[
                    core.entry(core.mtc_tbs(
                        core.from_pem(original.read_bytes()),
                        profile['ca_id'],i))
                    for i,original in enumerate(originals)
                ]

                for value in encoded[:8]:
                    persistent.append(value)

                old=export_snapshot(
                    persistent,transparency/'snapshot-n8.mcp2',name,keys)
                state8=authenticate_snapshot(
                    old,trusted,Path('/opt/mtc/check-snapshot'))

                for value in encoded[8:]:
                    persistent.append(value)

                snapshot=export_snapshot(
                    persistent,transparency/'snapshot-n16.mcp2',name,keys)
                state16=authenticate_snapshot(
                    snapshot,trusted,Path('/opt/mtc/check-snapshot'))

                local_state8={
                    'tree_size':state8['tree_size'],
                    'hash':state8['hash'],
                }
                current,path=persistent.prove_consistency(local_state8)
                local_state16={
                    'tree_size':state16['tree_size'],
                    'hash':state16['hash'],
                }
                if current!=local_state16 or not verify_snapshot_consistency(
                        old,snapshot,trusted,Path('/opt/mtc/check-snapshot'),path):
                    raise ValueError('Authenticated N=8 -> N=16 consistency failed')

                dump(transparency/'consistency-8-16.json',{
                    'old_state':state8,
                    'new_state':state16,
                    'proof':[value.hex() for value in path],
                    'verified':True,
                })

                options=dict(
                    persistent_log=persistent,
                    authenticated_snapshot=snapshot,
                    trusted_authority=trusted,
                    snapshot_checker=Path('/opt/mtc/check-snapshot'),
                )

            meta=prepare.prepare(
                out,population,name,n,originals=originals,
                signer_keys=keys,
                metadata={
                    'provenance':prov,
                    'population':'independent same-algorithm X.509 population',
                    **hostname_meta
                },
                **options)
            # Separate file so the generated manifest itself is covered as evidence.
            dump(out/'fixture-sha256.json',hashes(out))
        print(f'  [{position}/{len(profiles)}] {name} GENERATED',flush=True)
    transparency=args.output/'transparency'
    if transparency.exists():
        dump(args.output/'transparency-sha256.json',hashes(transparency))
    dump(args.output/'manifest.json',dict(schema=1,profiles=profiles,sizes=sizes,provenance=prov,**hostname_meta,
        modes=['landmark','standalone'],status='PREPARED_NOT_TLS_VALIDATED',
        independence='Issuance CA and MTC cosigners are distinct keys of the same signature profile'))


def check_fixture(directory,name,n):
    p=SIGNATURE_PROFILES[name];meta=read(directory/'manifest.json');saved=read(directory/'fixture-sha256.json')
    required={'manifest.json','authority.bin','trust.bin','cosigner-0.spki','cosigner-1.spki',
              'mtc-ca.pem','mtc-ca.der','mtc-representation-root.pem'}
    required.update(f'{mode}-{i:04d}.der' for mode in ('landmark','standalone') for i in range(n))
    if not required<=saved.keys():raise ValueError('Incomplete fixture hash manifest')
    for key,value in saved.items():
        path=directory/key
        if Path(key).is_absolute() or '..' in Path(key).parts or sha(path)!=value:raise ValueError('Fixture hash mismatch')
    for key in ('profile','standard_name','implementation_algorithm','security_level','ca_id'):
        if meta[key]!=p[key]:raise ValueError('Fixture profile differs from registry: '+key)
    if meta['cosigner_ids']!=list(p['cosigner_ids']) or meta['tree_size']!=n or meta['draft']!=DRAFT or meta['merkle_hash']!=TREE_HASH:
        raise ValueError('Fixture identity/draft/hash mismatch')
    for mode in ('landmark','standalone'):
        for i in range(n):
            outer,tbs=core.certificate_parts((directory/f'{mode}-{i:04d}.der').read_bytes())
            if outer[1][2]!=core.ALG or tbs[2][2]!=core.ALG:raise ValueError('Not an MTC proof algorithm')
    return meta


def tls_once(directory,population,name,mode,output,server_hostname='server'):
    p=SIGNATURE_PROFILES[name];output.mkdir(parents=True,exist_ok=False)
    # Reserve an ephemeral port without making a probe connection/handshake.
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    ident=p['ca_id']+('.1.1.1' if mode=='landmark' else '')
    common=['-tls1_3','-groups','X25519','-ciphersuites','TLS_AES_256_GCM_SHA384']
    server=[TLS_OPENSSL,'s_server','-accept',f'127.0.0.1:{port}','-cert',str(directory/f'{mode}-0000.pem'),
            '-key',str(population/'0.key'),'-mtc_id',ident,'-num_tickets','0','-www','-naccept','1',*common]
    client=[TLS_OPENSSL,'s_client','-connect',f'127.0.0.1:{port}','-servername',server_hostname,'-verify_hostname',server_hostname,
            '-verify_return_error','-mtc_trust',str(directory/('trust.bin' if mode=='landmark' else 'authority.bin')),
            '-mtc_ca',str(directory/'mtc-ca.pem'),
            '-mtc_ca_root',str(directory/'mtc-representation-root.pem'),
            '-no_ticket','-ign_eof',*common]+(['-mtc_landmark'] if mode=='landmark' else [])
    dump(output/'commands.json',{'server':server,'client':client})
    with (output/'server.log').open('w') as stream:
        process=subprocess.Popen(server,stdout=stream,stderr=subprocess.STDOUT,text=True)
        try:
            deadline=time.monotonic()+20
            while 'ACCEPT' not in (output/'server.log').read_text():
                if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Server not ready; inspect server.log')
                time.sleep(.05)
            result=subprocess.run(client,input='GET / HTTP/1.0\r\n\r\n',capture_output=True,text=True,timeout=60)
            log=result.stdout+result.stderr;(output/'client.log').write_text(log)
            if result.returncode or 'MTC verification: OK' not in log or 'HTTP/1.0 200' not in log:
                raise RuntimeError('MTC authentication failed')
            if 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384' not in log or not re.search(r'(?:Peer|Server) Temp Key: X25519',log):
                raise RuntimeError('Controlled TLS parameters not observed')
            if process.wait(timeout=10)!=0:raise RuntimeError('Server failed after handshake')
        finally:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()


def validate(args):
    prov=provenance();profiles=args.profile or list(SIGNATURE_PROFILES);modes=args.mode or ['landmark','standalone']
    if args.tree_size!=16:raise ValueError('Only the first N=16 functional gate is prepared')
    # Refuse stale binaries even when repository source is bind-mounted.
    require_current_mtc_image()
    if read(args.fixtures/'manifest.json').get('server_hostname','server')!=args.server_hostname:
        raise ValueError('Fixture hostname differs from --server-hostname; use matching immutable fixtures')
    print('Validating MTC fixtures: hashing inputs and preparing native verifier...',flush=True)
    args.output.mkdir(parents=True,exist_ok=False);before=hashes(args.fixtures);cells=[]
    binary=args.output/'verify-profile'
    checked(['cc','-std=c11','-D_POSIX_C_SOURCE=200809L','-I/opt/openssl/include','-I'+str(REPO/'src/mtc'),
             HERE/'verify_profile.c','-L/opt/openssl/lib','-Wl,-rpath,/opt/openssl/lib','-lssl','-lcrypto','-o',binary])
    try:
        # Finish parsing, public-key policy and real signature checks for all
        # profiles before starting either TLS mode (manual validation steps 2–4).
        for position,name in enumerate(profiles,1):
            print(f'  [{position}/{len(profiles)}] {name} checking certificates/signatures...',flush=True)
            p=SIGNATURE_PROFILES[name];directory=args.fixtures/'batch16/mtc'/name
            meta=check_fixture(directory,name,16)
            if meta['provenance']['image_id']!=prov['image_id'] or meta['provenance']['source_hashes']!=prov['source_hashes']:
                raise ValueError('Fixture generation used different image/source')
            for mode in ('landmark','standalone'):
                for i in (0,15):
                    checked([binary,directory/('trust.bin' if mode=='landmark' else 'authority.bin'),int(mode=='landmark'),
                             directory/f'{mode}-{i:04d}.der',p['implementation_algorithm'],(p['digest'] or '-').upper(),*p['cosigner_ids']])
            message=args.output/(name+'-message.bin');message.write_bytes(b'MTC signature validation\n')
            for i in range(2):
                signature=args.output/f'{name}-signature-{i}.bin'
                digest=['-digest',p['digest']] if p['digest'] else []
                checked([OPENSSL,'pkeyutl','-sign','-rawin','-inkey',directory/f'cosigner-{i}.key','-in',message,'-out',signature,*digest])
                checked([OPENSSL,'pkeyutl','-verify','-rawin','-pubin','-keyform','DER','-inkey',directory/f'cosigner-{i}.spki',
                         '-in',message,'-sigfile',signature,*digest])
            print(f'  [{position}/{len(profiles)}] {name} cryptographic checks PASS',flush=True)
        for mode in modes:
            print(f'Validating TLS 1.3/X25519: {mode}...',flush=True)
            for position,name in enumerate(profiles,1):
                p=SIGNATURE_PROFILES[name];directory=args.fixtures/'batch16/mtc'/name
                tls_once(directory,args.fixtures/'population'/name,name,mode,args.output/(name+'-'+mode),args.server_hostname)
                print(f'  [{position}/{len(profiles)}] {name} {mode} PASS',flush=True)
                cells.append(dict(profile=name,standard_name=p['standard_name'],implementation_algorithm=p['implementation_algorithm'],
                    security_level=p['security_level'],tree_size=16,mtc_mode=mode,draft=DRAFT,success=True,handshakes=1,
                    fixture_hash=sha(directory/'manifest.json'),**{k:prov[k] for k in ('git_commit','openssl_version','liboqs_version','oqs_provider_commit','image_id')}))
        if before!=hashes(args.fixtures):raise ValueError('Fixtures changed during validation')
        dump(args.output/'validation.json',dict(passed=True,cells=cells,fixture_hashes=before,provenance=prov,
             **({'server_hostname':args.server_hostname} if args.server_hostname!='server' else {}),
             status='FUNCTIONAL_VALIDATION_ONLY_NOT_PERFORMANCE',checks=['parsing','signer and leaf key policy','signature generation/verification','MTC authentication','TLS 1.3/X25519','no resumption']))
    except BaseException as error:
        dump(args.output/'failure.json',dict(passed=False,error=str(error),completed_cells=cells,provenance=prov))
        raise


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['generate','validate']);parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--fixtures',type=Path);parser.add_argument('--sizes',type=int,nargs='+',choices=TREE_SIZES,default=[16])
    parser.add_argument('--validated-n16',type=Path);parser.add_argument('--seed-fixtures',type=Path)
    parser.add_argument('--profile',action='append',choices=SIGNATURE_PROFILES);parser.add_argument('--mode',action='append',choices=['landmark','standalone'])
    parser.add_argument('--tree-size',type=int,choices=TREE_SIZES,default=16)
    parser.add_argument('--image',default='mt-tls-mtc:local');parser.add_argument('--execute',action='store_true');parser.add_argument('--inside',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--server-hostname',type=server_hostname,default='server',help='Leaf-0 CN/SAN and validation hostname; requires new fixtures')
    args=parser.parse_args(argv)
    if args.output.exists():parser.error('Output exists; choose a new immutable path')
    if args.action=='validate' and not args.fixtures:parser.error('--fixtures is required')
    if args.action=='generate' and args.mode:parser.error('Generation prepares both modes')
    if args.action=='generate' and args.profile and (set(args.sizes)!={16} or args.seed_fixtures):
        parser.error('Profile selection is only supported for fresh N=16 fixtures')
    if args.action=='generate' and args.seed_fixtures and args.server_hostname!='server':
        parser.error('Alternate hostname requires fresh N=16 fixtures without --seed-fixtures')
    if len(args.profile or [])!=len(set(args.profile or [])):parser.error('Duplicate profiles are not allowed')
    if args.action=='generate' and (set(args.sizes)!={16} or args.seed_fixtures):
        if not args.validated_n16 or not args.seed_fixtures:parser.error('Other sizes require --validated-n16 and --seed-fixtures')
    if args.action=='validate' and (args.tree_size!=16 or len(args.profile or [])!=len(set(args.profile or [])) or len(args.mode or [])!=len(set(args.mode or []))):
        parser.error('Validation is N=16 only; duplicate selections are not allowed')
    if not args.execute:
        print('PREPARATION ONLY:',args.action,'N='+str(args.sizes if args.action=='generate' else 16),
              'profiles='+str(args.profile or list(SIGNATURE_PROFILES)), 'server_hostname='+args.server_hostname, 'modes='+str(args.mode or ['landmark','standalone']))
        return
    if args.inside:
        (generate if args.action=='generate' else validate)(args);return
    image=json.loads(checked(['docker','image','inspect',args.image],text=True).stdout)[0]['Id']
    if args.action=='generate' and args.seed_fixtures:gate(args.validated_n16,args.seed_fixtures,image)
    commit=checked(['git','rev-parse','HEAD'],cwd=REPO,text=True).stdout.strip()
    status=checked(['git','status','--porcelain'],cwd=REPO,text=True).stdout
    args.output.resolve().parent.mkdir(parents=True,exist_ok=True)
    command=['docker','run','--rm','--network','none','--user',f'{os.getuid()}:{os.getgid()}',
             '-e','HOME=/tmp','-e','MTC_IMAGE_ID='+image,'-e','MTC_GIT_COMMIT='+commit,'-e','MTC_GIT_STATUS='+status,
             '-v',str(REPO)+':/repo:ro','-v',str(args.output.resolve().parent)+':/output']
    inner=['python3','/repo/'+str(Path(__file__).resolve().relative_to(REPO)),args.action,'--inside','--execute','--output','/output/'+args.output.name]
    for flag,path,mount in [('--fixtures',args.fixtures,'/fixtures'),('--seed-fixtures',args.seed_fixtures,'/seed'),('--validated-n16',args.validated_n16,'/gate.json')]:
        if path:
            if not path.exists():parser.error('Missing input: '+str(path))
            command+=['-v',str(path.resolve())+':'+mount+':ro'];inner += [flag,mount]
    inner+=['--server-hostname',args.server_hostname]
    if args.action=='generate':inner+=['--sizes',*map(str,args.sizes)]
    for flag,values in [('--profile',args.profile),('--mode',args.mode)]:
        for value in values or []:inner += [flag,value]
    subprocess.run(command+['--entrypoint','python3',image]+inner[1:],check=True)
    print(args.output)

if __name__=='__main__':main()
