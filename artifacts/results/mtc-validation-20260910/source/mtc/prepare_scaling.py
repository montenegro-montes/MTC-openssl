"""Generate one shared population, then compact/MTC snapshots for each N.
New output only; first 16 identities preserve the original compact population.
"""
import argparse,datetime as dt,importlib.util,json,os,shutil,struct,time
from pathlib import Path
from core import *
from prepare import command,keygen,prepare
spec=importlib.util.spec_from_file_location('old_compact','/opt/compact/prepare.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
def dates(cert):
    _,t=certificate_parts(cert);values=items(t[4][1]);result=[]
    for v in values:
        fmt='%y%m%d%H%M%SZ' if v[0]==23 else '%Y%m%d%H%M%SZ'
        result.append(int(dt.datetime.strptime(v[1].decode(),fmt).replace(tzinfo=dt.timezone.utc).timestamp()))
    return result

def compact_snapshot(out,family,files,keys,n):
    start=time.perf_counter();out.mkdir();issued=out/'issued';issued.mkdir();certs=[from_pem(p.read_bytes()) for p in files[:n]]
    ca=Path('/work/certs')/family/'ca.pem';cakey=ca.with_name('ca.key');ca_der=from_pem(ca.read_bytes());ca_fields=certificate_parts(ca_der)[1]
    ca_spki=ca_fields[6][2];intervals=[dates(c) for c in certs]+[dates(ca_der)];nb=max(v[0] for v in intervals);na=min(v[1] for v in intervals)
    values=[]
    for i,cert in enumerate(certs):
        name='server' if i==0 else f'member-{i}.lab';t=certificate_parts(cert)[1];a,b=dates(cert)
        values.append(b'MTC2'+vec(name.encode())+uint(a,8)+uint(b,8)+H(t[6][2])+b'\1')
        if i:shutil.copyfile(files[i],issued/f'{i}.pem');shutil.copyfile(keys[i],issued/f'{i}.key')
    tree_start=time.perf_counter();root_value,proofs=old.tree(values);tree_ms=(time.perf_counter()-tree_start)*1000
    header=b'MTR2'+uint(n,4)+root_value+uint(nb,8)+uint(na,8)+H(ca_spki);(out/'root.header').write_bytes(header)
    signature=command('pkeyutl','-sign','-rawin','-inkey',cakey,'-in',out/'root.header',*(['-digest','sha256'] if family=='classic' else []))
    signed=header+vec(signature);(out/'root.signed').write_bytes(signed)
    for i,(value,p) in enumerate(zip(values,proofs)):
        (out/f'credential-{i:04d}.bin').write_bytes(value);(out/f'proof-{i:04d}.bin').write_bytes(p);(out/f'bundle-{i:04d}.bin').write_bytes(old.bundle(value,p))
    import subprocess
    subprocess.run(['/opt/mt/bin/mt_bundle',str(out/'x509-merkle'),*map(str,files[:n])],check=True,capture_output=True)
    info={'format':'compact-v2','scenario':family,'leaves':n,'proof0_bytes':len(proofs[0]),'root_signed_bytes':len(signed),'root_signature_bytes':len(signature),
          'credential0_bytes':len(values[0]),'bundle0_bytes':len(old.bundle(values[0],proofs[0])),'offline_timings':{'tree_and_all_proofs_ms':tree_ms,'snapshot_ms':(time.perf_counter()-start)*1000},
          'source':'same population as corresponding MTC snapshot; prior compact wire format unchanged'}
    (out/'manifest.json').write_text(json.dumps(info,indent=2)+'\n')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--base',type=Path,default=Path('/work/compact/batch16'));p.add_argument('--sizes',type=int,nargs='+',default=[1,4,16,64,256,1024]);a=p.parse_args()
    if a.output.exists() or not a.sizes or min(a.sizes)<1 or max(a.sizes)>1024:p.error('new output and sizes 1..1024 required')
    os.umask(0o077);a.output.mkdir(parents=True);population=a.output/'population';population.mkdir();start=time.perf_counter()
    families={}
    for family in ['classic','pq']:
        directory=population/family;directory.mkdir();files=[Path('/work/certs')/family/'server.pem'];keys=[Path('/work/certs')/family/'server.key']
        for i in range(1,max(a.sizes)):
            cert=directory/f'{i}.pem';key=directory/f'{i}.key'
            if i<16:
                shutil.copyfile(a.base/family/'issued'/f'{i}.pem',cert);shutil.copyfile(a.base/family/'issued'/f'{i}.key',key)
            else:
                keygen(key,family);csr=directory/'request.csr';ext=directory/'request.cnf';name=f'member-{i}.lab'
                command('req','-new','-key',key,'-subj','/CN='+name,'-out',csr)
                ext.write_text(f'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{name}\n')
                command('x509','-req','-in',csr,'-CA',Path('/work/certs')/family/'ca.pem','-CAkey',Path('/work/certs')/family/'ca.key','-set_serial',str(i+1000),'-days','30','-extfile',ext,'-out',cert)
            files.append(cert);keys.append(key)
        command('verify','-CAfile',Path('/work/certs')/family/'ca.pem','-purpose','sslserver',*files)
        families[family]=(files,keys);print('population',family,len(files),flush=True)
    population_ms=(time.perf_counter()-start)*1000
    for n in sorted(set(a.sizes)):
        batch=a.output/f'compact-{n}';batch.mkdir();mtc=a.output/f'mtc-{n}';mtc.mkdir()
        for family,(files,keys) in families.items():
            compact_snapshot(batch/family,family,files,keys,n);prepare(mtc/family,batch,family,n)
        print('snapshots',n,flush=True)
    (a.output/'manifest.json').write_text(json.dumps({'sizes':a.sizes,'population_setup_ms':population_ms,'source_batch':str(a.base),'note':'Independent initial MTC CA instances per size; server keys and X509 CA fixed; CA key generation included in snapshot setup.'},indent=2)+'\n')
    print(a.output)
