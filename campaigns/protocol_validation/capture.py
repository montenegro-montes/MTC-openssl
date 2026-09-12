"""Explicit single-handshake capture; no builds, installs, fixture generation or retries."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

HERE=Path(__file__).resolve().parent
OPENSSL='/opt/mtc/openssl.sh'
COMMON=['-tls1_3','-groups','X25519','-ciphersuites','TLS_AES_256_GCM_SHA384']
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def run(cmd,**kw):return subprocess.run(cmd,check=True,capture_output=True,text=True,**kw).stdout
def save(path,data):
    with path.open('x') as f:json.dump(data,f,indent=2);f.write('\n')
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()

def inside(a):
    out=Path('/capture');fixture=Path('/fixture');m=json.loads((fixture/'manifest.json').read_text())
    if m['tree_size']!=16 or m.get('profile',m['crypto_family'])!=a.profile:raise ValueError('N=16/profile mismatch')
    if a.inside=='server':
        ident=m['ca_id']+('.1.1.1' if a.mode=='landmark' else '')
        command=[OPENSSL,'s_server','-accept','4433','-cert',str(fixture/(a.mode+'-0000.pem')),'-key','/server.key',
                 '-mtc_id',ident,'-num_tickets','0','-www','-naccept','1',*COMMON]
        save(out/'server-command.json',command)
        with (out/'server.log').open('x') as log:
            process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
            try:
                deadline=time.monotonic()+25
                while 'ACCEPT' not in (out/'server.log').read_text():
                    if process.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Server readiness failed')
                    time.sleep(.1)
                (out/'server.ready').touch(exist_ok=False)
                code=process.wait()
                save(out/'server-result.json',dict(returncode=code,finished=now()))
                if code:raise RuntimeError('Server failed')
            finally:
                if process.poll() is None:process.terminate();process.wait()
    else:
        command=[OPENSSL,'s_client','-connect','server:4433','-servername','server','-verify_hostname','server',
                 '-verify_return_error','-mtc_trust',str(fixture/('trust.bin' if a.mode=='landmark' else 'authority.bin')),
                 '-no_ticket','-ign_eof','-showcerts','-keylogfile','/capture/tls.keys',*COMMON]
        if a.mode=='landmark':command+=['-mtc_landmark']
        save(out/'client-command.json',command)
        r=subprocess.run(command,input='GET / HTTP/1.0\r\n\r\n',capture_output=True,text=True,timeout=90)
        text=r.stdout+r.stderr;(out/'client.log').write_text(text)
        ok=r.returncode==0 and 'MTC verification: OK' in text and 'HTTP/1.0 200' in text and 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384' in text and re.search(r'(Peer|Server) Temp Key: X25519',text) is not None
        # -showcerts is a reserialization of the received X509, not retained raw DER.
        match=re.search(r'-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----',text)
        if match:
            import base64
            (out/'receiver-reserialized.der').write_bytes(base64.b64decode(match.group(1)))
        save(out/'client-result.json',dict(passed=ok,returncode=r.returncode,handshakes_attempted=1,finished=now()))
        if not ok:raise RuntimeError('Handshake did not meet authentication/TLS controls')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode',choices=['landmark','standalone'],required=True)
    p.add_argument('--profile',choices=['pq','classic','ecdsa-p256','mldsa65','slhdsa128s'],default='pq')
    p.add_argument('--fixture-dir',type=Path);p.add_argument('--server-key',type=Path);p.add_argument('--output',type=Path)
    p.add_argument('--image',default='mt-tls-measurement:local');p.add_argument('--capture-image',default='mt-tls-capture:local')
    p.add_argument('--execute',action='store_true');p.add_argument('--inside',choices=['server','client'],help=argparse.SUPPRESS)
    a=p.parse_args()
    if a.inside:inside(a);return
    if not all((a.fixture_dir,a.server_key,a.output)):p.error('Specify --fixture-dir, --server-key and --output')
    if a.output.exists():p.error('Output exists; captures are immutable')
    if not a.execute:print('PLAN ONLY: one N=16',a.profile,a.mode,'handshake; isolated server eth0, tcp port 4433');return
    fixture=a.fixture_dir.resolve();key=a.server_key.resolve();out=a.output.resolve();repo=HERE.parents[1]
    if not key.is_file():p.error('Server key missing')
    m=json.loads((fixture/'manifest.json').read_text())
    if m['tree_size']!=16 or m.get('profile',m['crypto_family'])!=a.profile:p.error('Wrong fixture profile/N')
    source_files=[repo/'src/mtc'/name for name in ('core.py','mtc.c','mtc.h','tls.c','patch.py','prepare.py')]
    source_files += [HERE/name for name in ('capture.py','compose.yaml','validate_mtc.py','extract_pcap.py')]
    source_hashes={str(path.relative_to(repo)):sha(path) for path in source_files}
    images=[json.loads(run(['docker','image','inspect',name]))[0]['Id'] for name in (a.image,a.capture_image)]
    # Query the exact running stack; no image builds or dependency installation.
    version_code="""import json,pathlib,subprocess,re
p=pathlib.Path
header=p('/opt/oqs/include/oqs/oqsconfig.h').read_text()
m=re.search(r'OQS_VERSION_TEXT\\s+\"([^\"]+)\"',header)
print(json.dumps(dict(openssl_version=subprocess.check_output(['/opt/mtc/openssl.sh','version','-a'],text=True),liboqs_version=m.group(1) if m else None,oqs_provider_commit=p('/opt/oqs/PROVIDER_COMMIT').read_text().strip(),mtc_build_hash=p('/opt/openssl-mtc/MTC_SHA256').read_text().strip())))
"""
    versions=json.loads(run(['docker','run','--rm','--network','none','--entrypoint','python3',images[0],'-c',version_code]))
    os.umask(0o077);out.mkdir(parents=True)
    before={str(path):sha(path) for path in [*fixture.glob('*') ,key] if path.is_file()}
    scenario=(a.profile+'-mtc-experimental-'+a.mode)
    meta=dict(draft='draft-ietf-plants-merkle-tree-certs-05',claim='implemented-subset conformance',scenario=scenario,
              profile=a.profile,tree_size=16,mode=a.mode,timestamp=now(),image_id=images[0],capture_image_id=images[1],
              git_commit=run(['git','rev-parse','HEAD'],cwd=repo).strip(),source_hashes=source_hashes,
              fixture_path=str(fixture),fixture_sha256=sha(fixture/(a.mode+'-0000.der')),
              status='STARTED',tls_version='TLSv1.3',cipher='TLS_AES_256_GCM_SHA384',key_exchange='X25519',
              capture=dict(interface='server namespace eth0',filter='tcp port 4433',format='pcap',handshakes=1),**versions)
    save(out/'started.json',meta)
    env=os.environ.copy();env.update(PROTOCOL_IMAGE=images[0],PROTOCOL_CAPTURE_IMAGE=images[1],PROTOCOL_CODE=str(HERE),
        PROTOCOL_FIXTURE=str(fixture),PROTOCOL_KEY=str(key),PROTOCOL_OUTPUT=str(out),PROTOCOL_MODE=a.mode,PROTOCOL_PROFILE=a.profile)
    compose=['docker','compose','-p','mtcprotocol-'+hashlib.sha256(str(out).encode()).hexdigest()[:12],'-f',str(HERE/'compose.yaml')]
    try:
        run(compose+['up','-d','--no-build','--wait','server'],env=env)
        run(compose+['up','-d','--no-build','capture'],env=env)
        deadline=time.monotonic()+20
        while 'listening on eth0' not in run(compose+['logs','--no-color','capture'],env=env):
            if time.monotonic()>deadline:raise RuntimeError('Capture not ready')
            time.sleep(.2)
        run(compose+['run','--rm','--no-deps','client'],env=env)
        deadline=time.monotonic()+15
        while not (out/'server-result.json').exists():
            if time.monotonic()>deadline:raise RuntimeError('Server did not finish')
            time.sleep(.2)
        if json.loads((out/'server-result.json').read_text())['returncode']!=0:raise RuntimeError('Server failure')
        meta['status']='CAPTURED_NOT_PROTOCOL_VALIDATED'
    except Exception as error:
        meta.update(status='FAIL',error=str(error));raise
    finally:
        subprocess.run(compose+['kill','-s','SIGINT','capture'],env=env,capture_output=True)
        # Wait for tcpdump to flush before hashing the scientific artifact.
        cid=subprocess.run(compose+['ps','-a','-q','capture'],env=env,capture_output=True,text=True).stdout.strip()
        if cid:
            try:subprocess.run(['docker','wait',cid],capture_output=True,timeout=15)
            except subprocess.TimeoutExpired:
                meta.update(status='FAIL',error='Capture did not flush before timeout')
                subprocess.run(compose+['kill','capture'],env=env,capture_output=True)
        log=subprocess.run(compose+['logs','--no-color','capture'],env=env,capture_output=True,text=True).stdout
        (out/'tcpdump.log').write_text(log)
        subprocess.run(compose+['down'],env=env,capture_output=True)
        meta['inputs_preserved']=all(Path(path).is_file() and sha(Path(path))==digest for path,digest in before.items())
        meta['sources_preserved']=all(sha(repo/path)==digest for path,digest in source_hashes.items())
        drops=re.findall(r'(\d+) packets dropped by kernel',log)
        meta['kernel_drops']=sum(map(int,drops)) if drops else None
        for name,field in [('handshake.pcap','pcap_sha256'),('tls.keys','keylog_sha256'),('receiver-reserialized.der','receiver_reserialized_sha256')]:
            if (out/name).is_file():meta[field]=sha(out/name)
        if not meta['inputs_preserved'] or not meta['sources_preserved'] or meta['kernel_drops']!=0 or 'pcap_sha256' not in meta or 'keylog_sha256' not in meta:meta['status']='FAIL'
        meta['evidence_sha256']={name:sha(out/name) for name in ('client-result.json','server-result.json','client.log','server.log','client-command.json','server-command.json') if (out/name).is_file()}
        meta['finished']=now();save(out/'metadata.json',meta)
    if meta['status']=='FAIL':raise SystemExit('Capture failed integrity checks')
    print(out)
if __name__=='__main__':main()
