"""Controlled new populations; reuse saved encoders and keys, never overwrite inputs."""
import argparse,datetime as dt,hashlib,importlib.util,json,os,shutil,sys,time,types
from pathlib import Path
sys.path.insert(0,'/opt/mtc')
import core,prepare
spec=importlib.util.spec_from_file_location('saved_scaling','/opt/mtc/prepare_scaling.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
if a.output.exists():p.error('Refusing to overwrite fixtures')
os.umask(0o077);a.output.mkdir();population=a.output/'population';population.mkdir()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
stamp=int(time.time());prepare.time=types.SimpleNamespace(time=lambda:stamp,perf_counter=time.perf_counter)
def fixed_key(path,family):shutil.copyfile(Path('/work/mtc/batch16-v2')/family/path.name,path)
prepare.keygen=fixed_key
families={}
for family in ['classic','pq']:
 directory=population/family;directory.mkdir();base=Path('/work/certs')/family
 files=[base/'server.pem'];keys=[base/'server.key'];nb,na=old.dates(core.from_pem(files[0].read_bytes()))
 dates=[dt.datetime.fromtimestamp(t,dt.timezone.utc).strftime('%Y%m%d%H%M%SZ') for t in [nb,na]]
 for i in range(1,1024):
  key=directory/f'{i}.key';cert=directory/f'{i}.pem';csr=directory/'request.csr';ext=directory/'request.cnf';name=f'member-{i}.lab'
  if i<16:shutil.copyfile(Path('/work/compact/batch16')/family/'issued'/f'{i}.key',key)
  else:old.keygen(key,family)
  prepare.command('req','-new','-key',key,'-subj','/CN='+name,'-out',csr)
  ext.write_text(f'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:{name}\n')
  prepare.command('x509','-req','-in',csr,'-CA',base/'ca.pem','-CAkey',base/'ca.key','-set_serial',str(1000+i),'-not_before',dates[0],'-not_after',dates[1],'-extfile',ext,'-out',cert)
  assert old.dates(core.from_pem(cert.read_bytes()))==[nb,na]
  files.append(cert);keys.append(key)
  if i%256==0:print('population',family,i+1,flush=True)
 prepare.command('verify','-CAfile',base/'ca.pem','-purpose','sslserver',*files)
 families[family]=(files,keys)
 print('population complete',family,len(files),flush=True)
for n in [1,4,16,64,256,1024]:
 batch=a.output/f'batch{n}';batch.mkdir();compact=batch/'compact';compact.mkdir();mtc=batch/'mtc';mtc.mkdir()
 for family,(files,keys) in families.items():
  old.compact_snapshot(compact/family,family,files,keys,n)
  path=compact/family/'manifest.json';m=json.loads(path.read_text());cert=core.from_pem(files[0].read_bytes());spki=core.certificate_parts(cert)[1][6][2]
  m.update(leaf0_spki_bytes=len(spki),leaf0_der_bytes=len(cert),leaf0_x509_sha256=sha(files[0]),authority_spki_sha256=core.H(core.certificate_parts(core.from_pem((Path('/work/certs')/family/'ca.pem').read_bytes()))[1][6][2]).hex(),input_sha256={str(f):sha(f) for f in files[:n]},metadata_correction='actual serialized server SPKI DER length required by frozen controlled measurement driver')
  path.write_text(json.dumps(m,indent=2)+'\n');prepare.prepare(mtc/family,compact,family,n)
  assert len(list((mtc/family/'log').glob('*.entry')))==n
  assert len({(compact/family/f'credential-{i:04d}.bin').read_bytes() for i in range(n)})==n
  assert len({(mtc/family/'log'/f'{i:06d}.entry').read_bytes() for i in range(n)})==n
  for i in range(2):assert sha(mtc/family/f'cosigner-{i}.spki')==sha(Path('/work/mtc/batch16-v2')/family/f'cosigner-{i}.spki')
 print('snapshot complete',n,flush=True)
(a.output/'manifest.json').write_text(json.dumps({'sizes':[1,4,16,64,256,1024],'timestamp':stamp,'generation_policy':'One shared 1024-identity population per family; prefix N. Identity zero original server certificate/key. Others issued with original server validity and fixed DNS/serial policy. Keys 1..15 reused, others generated once. MTC CA/cosigner keys reused from N16. Saved wire encoders unchanged.','source_hashes':{p:sha(Path(p)) for p in ['/opt/mtc/core.py','/opt/mtc/prepare.py','/opt/mtc/prepare_scaling.py','/opt/compact/prepare.py']}},indent=2))
print(a.output,flush=True)
