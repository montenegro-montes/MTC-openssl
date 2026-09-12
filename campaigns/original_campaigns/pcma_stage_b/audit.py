"""Full fail-closed audit and A.2 replay, only on explicit manual invocation."""
import csv
import hashlib
import struct
import json
import math
from pathlib import Path
import sys
from design import ROOT,VERSION,digest,plan

sys.path.append(str(ROOT/'campaigns/original_campaigns/pcma_stage_a2'))
from formats import encode,universe
from core import decode_mtp1,encode_mtp2,verify_mtp2,proof_nodes
from cache import NodeCache

def require(ok,message):
    if not ok:raise ValueError('AUDIT FAILED: '+message)

def read_rows(path):
    with path.open(newline='') as f:return list(csv.DictReader(f))

def audit(directory,model=True):
    m=json.loads((directory/'manifest.json').read_text());complete=json.loads((directory/'complete.json').read_text())
    require(m['version']==VERSION==complete['version'],'protocol version')
    expected=plan(m['config'],m['plan']['mode']);require(expected==m['plan'],'configuration/sequence/seed plan')
    require(complete['expected_handshakes']==expected['expected_handshakes'],'completion count')
    for path,value in complete['hashes'].items():require(digest(directory/path)==value,'file integrity: '+path)
    require({'manifest.json','sequences.json','environment.json','observations.csv'}<=set(complete['hashes']),'incomplete integrity inventory')
    env=json.loads((directory/'environment.json').read_text())['endpoints']
    require(env['client']['binary_sha256']==env['server']['binary_sha256'],'endpoint build mismatch')
    require(env['client']['openssl_commit']==env['server']['openssl_commit'],'OpenSSL commit mismatch')
    sequence_file=json.loads((directory/'sequences.json').read_text());require(sequence_file['cells']==expected['cells'],'saved sequences')
    data=read_rows(directory/'observations.csv');require(len(data)==expected['expected_handshakes'],'handshake count')
    cells={c['campaign_id']:c for c in expected['cells']};seen=set();groups={};fixture_checked=set()
    for row in data:
        cid=row['campaign_id'];require(cid in cells,'unexpected campaign');c=cells[cid];t=int(row['sequence_position'])
        arm=(row['scenario'],int(row['cache_budget'])//1024,row['cache_policy'])
        expected_arms=[(a['scenario'],a['budget_kb'],a['policy']) for a in c['arms']]
        require(arm in expected_arms and 1<=t<=len(c['sequence']),'unexpected arm/access')
        key=(cid,t,arm);require(key not in seen,'duplicate attempt');seen.add(key)
        require(int(row['cache_budget'])==arm[1]*1024,'budget units')
        require(int(row['leaf'])==c['sequence'][t-1] and int(row['seed'])==c['seed'] and int(row['base_seed'])==m['config']['base_seed'],'sequence seed pairing')
        require(int(row['N'])==c['N'] and row['workload']==c['workload'] and row['network_profile']==c['profile'],'cell dimensions')
        require(int(row['round'])==t-c['warmup_rounds'] and int(row['is_warmup'])==int(t<=c['warmup_rounds']),'warmup/round phase')
        require(sequence_file['arm_orders'][cid][t-1][int(row['order'])]==expected_arms.index(arm),'arm order')
        tree=m['fixtures']['trees'][row['N']];fixture=tree['leaves'][row['leaf']]
        require(row['root']==tree['root'] and row['hostname']==fixture['hostname'],'root/credential identity')
        for name,path in fixture['paths'].items():
            if path not in fixture_checked:
                require(digest(ROOT/'artifacts'/path)==fixture['sha256'][name],'fixture hash');fixture_checked.add(path)
        require(row['success']=='True','failed handshake')
        client=json.loads(row['client_metrics']);server=json.loads(row['server_metrics'])
        require(client['success'] and server['success'],'endpoint authentication')
        for endpoint in (client,server):
            require(endpoint['protocol']==VERSION and endpoint['tls_version']==772 and endpoint['resumed']==0 and endpoint['cipher']=='TLS_AES_256_GCM_SHA384' and endpoint['group']==1034,'TLS controls')
        # OpenSSL NID_X25519 = 1034 in the pinned build; native code checks it too.
        require(client['peer_key_ml_dsa65']==1 and client['certificate_verify_scheme']>0,'missing observed ML-DSA-65 peer/signature scheme')
        for k,v in client.items():
            if k in row and k not in ('success','protocol'):
                if isinstance(v,(float,int)):
                    require(math.isfinite(float(row[k])) and math.isclose(float(row[k]),v,abs_tol=1e-8),'raw/client metric mismatch '+k)
                else:require(row[k]==str(v),'raw/client metric mismatch '+k)
        def num(k):
            v=float(row[k]);require(math.isfinite(v),'nonfinite '+k);return v
        require(num('tls_total_bytes')==num('tls_read_bytes')+num('tls_written_bytes'),'TLS record byte equation')
        require(num('handshake_total_bytes')==num('handshake_read_bytes')+num('handshake_written_bytes'),'handshake byte equation')
        require(num('server_authentication_bytes')==num('encrypted_extensions_bytes')+num('certificate_bytes')+num('certificate_verify_bytes'),'server authentication equation')
        require(client['handshake_read_bytes']==server['handshake_written_bytes'] and client['handshake_written_bytes']==server['handshake_read_bytes'],'endpoint handshake byte agreement')
        require(num('fallback_events')==0 and num('wall_ms')>=0 and num('cpu_ms')>=0 and num('server_cpu_ms')>=0,'timing/fallback')
        pcma=row['scenario']=='pq-compact-pcma'
        if pcma:
            require(num('pcma_extension_bytes')==num('advertisement_bytes')+4,'extension framing')
            require(num('net_authentication_bytes')==num('advertisement_bytes')+num('proof_bytes'),'net auth equation')
            require(num('net_authentication_saving')==fixture['normal_proof_bytes']-num('net_authentication_bytes'),'A.2 net saving equation')
            require(num('cache_bytes')==69*num('cache_nodes')<=num('cache_budget'),'cache capacity')
            require(num('normal_hashes')==num('reused_hashes')+num('transmitted_hashes'),'reuse equation')
            require(num('advertisement_bytes')==server['advertisement_bytes'] and num('proof_bytes')==server['proof_bytes'] and num('reused_hashes')==server['reused_hashes'],'server/client PCMA agreement')
            require(row['cache_after_sha256']!='','missing committed cache')
        else:
            require(num('advertisement_bytes')==0 and num('cache_nodes')==0,'baseline has no PCMA state')
        groups.setdefault((cid,arm),[]).append(row)
    for cid,c in cells.items():
        require((directory/cid/'complete.json').exists(),'campaign incomplete')
        for arm in c['arms']:
            key=(cid,(arm['scenario'],arm['budget_kb'],arm['policy']))
            require(key in groups and len(groups[key])==len(c['sequence']),'scenario balance/incomplete sequence')
    lookup={(r['campaign_id'],r['sequence_position'],r['scenario'],r['cache_budget']):r for r in data}
    for row in data:
        if row['scenario']!='pq-compact-pcma':continue
        warm=lookup[(row['campaign_id'],row['sequence_position'],'pq-compact-warm','0')]
        expected_delta=float(row['net_authentication_saving'])+36
        require(float(warm['handshake_total_bytes'])-float(row['handshake_total_bytes'])==expected_delta,'TLS plaintext framing differs from +36-byte A.2 adjustment')
        require(json.loads(warm['client_metrics'])['certificate_verify_scheme']==json.loads(row['client_metrics'])['certificate_verify_scheme'],'signature scheme changed between paired arms')
    compared=0
    if model:
        for (cid,arm),rows in groups.items():
            if arm[0]!='pq-compact-pcma':continue
            c=cells[cid];root=bytes.fromhex(m['fixtures']['trees'][str(c['N'])]['root']);cache=NodeCache(arm[1]*1024,arm[2]);prior=0;previous_hash=''
            for row in sorted(rows,key=lambda r:int(r['sequence_position'])):
                fixture=m['fixtures']['trees'][row['N']]['leaves'][row['leaf']];paths=fixture['paths']
                proof=decode_mtp1((ROOT/'artifacts'/paths['proof']).read_bytes());credential=(ROOT/'artifacts'/paths['credential']).read_bytes()
                wire=encode('ranges',c['N'],root,cache.advertised_keys(root));partial,sent=encode_mtp2(proof,set(cache.advertised_keys(root)))
                for field,value in [('advertisement_bytes',len(wire)),('proof_bytes',len(partial)),('transmitted_hashes',sent),('reused_hashes',len(proof.siblings)-sent)]:require(int(row[field])==value,'A.2 model mismatch '+field)
                cache.account(proof_nodes(proof));known=verify_mtp2(credential,partial,cache.values(),root);cache.update({k:v for k,v in known.items() if k.level<len(proof.siblings)})
                require(int(row['cache_nodes'])==len(cache.values()) and int(row['cache_bytes'])==cache.bytes,'cache model evolution')
                require(prior+int(row['nodes_added'])-int(row['nodes_evicted'])==int(row['cache_nodes']),'cache evolution equation')
                require(row['cache_before_sha256']==previous_hash,'transactional cache chain')
                positions={k:i for i,k in enumerate(universe(c['N'],root))}
                stored=b'PCS1'+struct.pack('!I',c['N'])+root+struct.pack('!IBI',arm[1]*1024,int(arm[2]=='upper-level'),len(cache.values()))
                stored+=b''.join(struct.pack('!I',positions[k])+v for k,v in cache.values().items())
                require(hashlib.sha256(stored).hexdigest()==row['cache_after_sha256'],'exact persisted state differs from A.2')
                previous_hash=row['cache_after_sha256'];prior=int(row['cache_nodes']);compared+=1
    return dict(status='PASS',campaigns=len(cells),handshakes=len(data),model_compared=compared,manifest_sha256=digest(directory/'manifest.json'))
