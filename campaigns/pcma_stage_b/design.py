"""Side-effect-free experiment design and provenance helpers."""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'campaigns/pcma'))
from workloads import generate
VERSION='pcma-stage-b-v1'
PROFILES={
 'baseline':dict(code=0,rtt_ms=0,half_delay_ms=0,rate_mbit=None,loss_percent='0'),
 'wan':dict(code=1,rtt_ms=50,half_delay_ms=25,rate_mbit=20,loss_percent='0.5'),
 'constrained':dict(code=2,rtt_ms=100,half_delay_ms=50,rate_mbit=5,loss_percent='1')}

def digest(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
    return h.hexdigest()

def save(p,data):
    with Path(p).open('x') as f:json.dump(data,f,indent=2,sort_keys=True);f.write('\n')

def load_config(path):
    c=json.loads(Path(path).read_text())
    if c['version']!=VERSION:raise ValueError('protocol version mismatch')
    for field,allowed in [('sizes',[16,64,256,1024]),('workloads',['uniform','zipf','clustered']),('budgets_kb',range(0,138)),('profiles',PROFILES)]:
        v=c[field]
        if not v or len(v)!=len(set(v)) or any(x not in allowed for x in v):raise ValueError('invalid '+field)
    for k in ('repetitions','measured_rounds','bootstrap_resamples'):
        if type(c[k]) is not int or c[k]<1:raise ValueError('invalid '+k)
    if type(c['warmup_rounds']) is not int or c['warmup_rounds']<0:raise ValueError('invalid warmup')
    expected=dict(version='TLSv1.3',group='X25519',cipher='TLS_AES_256_GCM_SHA384',signature='ML-DSA-65',tickets=False,resumption=False,mutual_auth=False)
    if c['tls']!=expected:raise ValueError('TLS controls cannot vary in v1')
    for n in c['sizes']:
        for w in c['workloads']:
            for kb in c['budgets_kb']:
                if c['policies'].get(f'{n}/{w}/{kb}') not in ('lru','upper-level'):raise ValueError('policy selection missing')
    return c

def plan(c,mode):
    if mode=='stage-b2' and (not c.get('selection_approved') or not c.get('selection_justification') or c['selection_justification'].startswith('REQUIRED')):
        raise ValueError('Stage B.2 requires an explicit configuration subset and written Stage-B.1 justification')
    if mode=='stage-b1' and c['profiles']!=['baseline']:raise ValueError('B.1 is baseline only')
    diagnostic=mode in ('diagnostic','capture')
    cells=[]
    for n in ([16] if diagnostic else c['sizes']):
        for w in (['targeted'] if diagnostic else c['workloads']):
            for profile in (['baseline'] if diagnostic else c['profiles']):
                for rep in range(1,(1 if diagnostic else c['repetitions'])+1):
                    seed=c['base_seed']+n*10000+(['uniform','zipf','clustered','targeted'].index(w))*100+rep
                    warm=0 if diagnostic else c['warmup_rounds'];measured=4 if diagnostic else c['measured_rounds']
                    sequence=[0,1,2,8] if diagnostic else generate(w,n,warm+measured,seed)
                    arms=[] if diagnostic else [dict(scenario='pq',budget_kb=0,policy='lru')]
                    arms.append(dict(scenario='pq-compact-warm',budget_kb=0,policy='lru'))
                    for kb in ([2] if diagnostic else c['budgets_kb']):
                        policy='lru' if diagnostic else c['policies'][f'{n}/{w}/{kb}']
                        arms.append(dict(scenario='pq-compact-pcma',budget_kb=kb,policy=policy))
                    cells.append(dict(campaign_id=f'n{n}-{w}-{profile}-r{rep:02d}',N=n,workload=w,profile=profile,
                                      repetition=rep,seed=seed,sequence=sequence,warmup_rounds=warm,measured_rounds=measured,arms=arms))
    return dict(version=VERSION,mode=mode,cells=cells,expected_campaigns=len(cells),
                expected_handshakes=sum(len(x['sequence'])*len(x['arms']) for x in cells),
                measured_handshakes=sum(x['measured_rounds']*len(x['arms']) for x in cells),
                warmup_handshakes=sum(x['warmup_rounds']*len(x['arms']) for x in cells))

def fixture_records(c,cells):
    manifest_path=ROOT/c['fixtures'];fixture=json.loads(manifest_path.read_text());certbase=ROOT/c['cert_base']
    records={}
    for n in sorted({x['N'] for x in cells}):
        entry=fixture['sizes'][str(n)];directory=Path(entry['directory'])
        from core import decode_mtp1,verify_mtp1
        root=bytes.fromhex(entry['tree_root_sha256'])
        signed=directory/'root.signed'
        if digest(signed)!=entry['root_signed_sha256']:raise ValueError('signed root digest differs')
        leaves={}
        for leaf in sorted({leaf for cell in cells if cell['N']==n for leaf in cell['sequence']}):
            credential=directory/f'credential-{leaf:04d}.bin';proof=directory/f'proof-{leaf:04d}.bin';bundle=directory/f'bundle-{leaf:04d}.bin'
            cert=certbase/'server.pem' if leaf==0 else directory/'issued'/f'{leaf}.pem'
            key=certbase/'server.key' if leaf==0 else directory/'issued'/f'{leaf}.key'
            data=credential.read_bytes();p=decode_mtp1(proof.read_bytes())
            if p.root!=root or p.leaves!=n or p.leaf_index!=leaf:raise ValueError('fixture identity mismatch')
            verify_mtp1(data,p)
            name=data[6:6+int.from_bytes(data[4:6],'big')].decode('ascii')
            paths=dict(credential=credential,proof=proof,bundle=bundle,cert=cert,key=key,authority=certbase/'ca.pem',root=signed)
            # Every path must be in the repository artifacts tree, mounted read-only.
            paths={k:str(v.resolve().relative_to((ROOT/'artifacts').resolve())) for k,v in paths.items()}
            leaves[str(leaf)]=dict(hostname=name,paths=paths,sha256={k:digest(ROOT/'artifacts'/v) for k,v in paths.items()},credential_bytes=len(data),normal_proof_bytes=proof.stat().st_size)
        records[str(n)]=dict(root=root.hex(),leaves=leaves)
    return dict(manifest_sha256=digest(manifest_path),trees=records)
