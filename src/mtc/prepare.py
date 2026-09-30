"""Create immutable MTC issuance snapshots from an explicit X.509 population."""
import json,shutil,subprocess,time
from datetime import datetime, timezone
from pathlib import Path
from core import *
from crypto_profiles import crypto_profile, SIGNATURE_PROFILES, TREE_HASH
OPENSSL='/opt/openssl/bin/openssl'
def command(*args,data=None):return subprocess.run([OPENSSL,*map(str,args)],input=data,capture_output=True,check=True).stdout
def keygen(path,family):
    profile=crypto_profile(family)
    command('genpkey','-algorithm',profile['implementation_algorithm'],*(['-pkeyopt','ec_paramgen_curve:'+profile['curve']] if profile['curve'] else []),'-out',path)
def sign(path,data,family):
    profile=crypto_profile(family)
    tmp=path.parent/'sign-input.tmp';tmp.write_bytes(data)
    try:return command('pkeyutl','-sign','-rawin','-inkey',path,'-in',tmp,*(['-digest',profile['digest']] if profile['digest'] else []))
    finally:tmp.unlink()
def checkpoint_signature(ident,key,caid,n,checkpoint,timestamp,family):
    return ident,sign(key,message(ident,caid,0,n,checkpoint,timestamp),family)
def authority_config(caid,ids,public,n):
    """Existing local MCF1 authority encoding; not a certificate wire format."""
    if not 1<=n<=1024 or len(ids)!=2 or len(public)!=2:raise ValueError('MCF1 configuration')
    config=b'MCF1'+vec(caid.encode(),1)+bytes([len(ids)])
    for ident,spki in zip(ids,public):config+=vec(ident.encode(),1)+vec(spki)
    return config+uint(1,2)+uint(1<<48,8)+uint((1<<48)+n-1,8)

def write_trusted_subtrees(path, subtrees):
    """Write authenticated trusted-subtree cache in MTS1 format."""
    from trusted_subtrees import encode_trusted_subtrees

    if not subtrees:
        raise ValueError('empty trusted subtree set')

    log_number = subtrees[0].log_number
    data = encode_trusted_subtrees(subtrees)

    target = Path(path)
    if target.exists():
        raise FileExistsError(target)

    target.write_bytes(data)
    return target

def checkpoint_config(authority,entries,timestamp,cp_sigs):
    """Existing trust.bin layout, including its local landmark-slot field.

    Offline snapshots reuse this container, not a mutable landmark allocation.
    """
    n=len(entries);subtrees=cover(0,n)
    config=authority+uint(1,4)+uint(n,6)+uint(timestamp,8)+root(entries)+signatures(cp_sigs)+bytes([len(subtrees)])
    for start,end in subtrees:config+=uint(start,6)+uint(end,6)+root(entries[start:end])
    return config
def not_after(tbs):
    validity=items(content(tbs,0x30))[4]
    times=items(content(validity[2],0x30))
    if len(times)!=2:raise ValueError('Invalid certificate validity')
    tag,value,_=times[1];text=value.decode('ascii')
    if tag==23 and len(text)==13:
        text=('19' if int(text[:2])>=50 else '20')+text
    elif tag!=24 or len(text)!=15:raise ValueError('Invalid notAfter encoding')
    if not text.endswith('Z') or not text[:-1].isdigit():raise ValueError('Invalid notAfter encoding')
    return int(datetime.strptime(text,'%Y%m%d%H%M%SZ').replace(tzinfo=timezone.utc).timestamp())
def prepare(out,batch,family,n,*,originals=None,signer_keys=None,metadata=None,
            persistent_log=None,authenticated_snapshot=None,trusted_authority=None,snapshot_checker=None):
    """Generate the usual material, optionally bound to an authenticated log view.

    Originals supply certificate fields absent from MTCLogEntry. Their derived
    entries must match the persisted entries byte-for-byte, in index order.
    This allocates the existing initial landmark for the selected final tree;
    it does not evolve/reassign an earlier landmark or embed consistency proofs.
    """
    profile=crypto_profile(family)
    if not 1<=n<=1024:raise ValueError('Unsupported MTC population')
    if originals is None:raise ValueError('MTC requires an explicit same-profile X.509 population')
    begin=time.perf_counter();caid=profile['ca_id'];ids=list(profile['cosigner_ids'])
    if len(originals)!=n:raise ValueError('Population length differs from N')
    certs=[from_pem(p.read_bytes()) for p in originals]
    tbs=[mtc_tbs(c,caid,i) for i,c in enumerate(certs)];entries=[entry(t) for t in tbs]
    authenticated=None
    options=(persistent_log,authenticated_snapshot,trusted_authority,snapshot_checker)
    if any(v is not None for v in options):
        if any(v is None for v in options) or signer_keys is None or len(signer_keys)!=2:
            raise ValueError('Persistent generation requires log, snapshot, trusted authority, checker and signer keys')
        if out.resolve()==persistent_log.directory.resolve() or persistent_log.directory.resolve() in out.resolve().parents:
            raise ValueError('Generated material must be outside the persistent log')
        from snapshots import authenticate_snapshot
        authenticated=authenticate_snapshot(authenticated_snapshot,trusted_authority,snapshot_checker)
        with persistent_log._locked():
            persisted,state=persistent_log._read()
            if state!=authenticated or state['tree_size']!=n:
                raise ValueError('Persistent log differs from authenticated snapshot')
            if entries!=persisted:
                raise ValueError('Certificate inputs differ from authenticated log entries')
            entries=persisted  # Immutable in-memory view; later appends do not alter it.
    out.mkdir()
    keys=[];public=[]
    for i in range(2):
        key=out/f'cosigner-{i}.key'
        if signer_keys is None:keygen(key,family)
        else:shutil.copyfile(signer_keys[i],key)
        keys.append(key)
        public.append(command('pkey','-in',key,'-pubout','-outform','DER'))
        (out/f'cosigner-{i}.spki').write_bytes(public[-1])
    log=out/'log';log.mkdir()
    for i,e in enumerate(entries):(log/f'{i:06d}.entry').write_bytes(e)
    checkpoint=root(entries);timestamp=int(time.time());subtrees=cover(0,n)
    expiration=max(timestamp+1,max(not_after(t) for t in tbs))
    # Each local cosigner independently reconstructs its entire initial view.
    cp_sigs=[];sub_sigs={}
    for ident,key in zip(ids,keys):
        mirror=[(log/f'{i:06d}.entry').read_bytes() for i in range(n)]
        assert root(mirror)==checkpoint
        cp_sigs.append(checkpoint_signature(ident,key,caid,n,checkpoint,timestamp,family))
        for start,end in subtrees:
            sub_sigs.setdefault((start,end),[]).append((ident,sign(key,message(ident,caid,start,end,root(mirror[start:end])),family)))
    for i,t in enumerate(tbs):
        start,end=next(x for x in subtrees if x[0]<=i<x[1]);path=inclusion(entries[start:end],i-start)
        assert evaluate(entries[i],i,start,end,path)==root(entries[start:end])
        for mode,sigs in [('standalone',sub_sigs[start,end]),('landmark',[])]:
            p=proof(start,end,path,sigs);cert=certificate(t,p)
            (out/f'{mode}-{i:04d}.der').write_bytes(cert);(out/f'{mode}-{i:04d}.pem').write_bytes(pem(cert))
    # OOB configuration: keys, serial limits, signed checkpoint and its two covering subtrees.
    # This file is a lab storage format, never sent as an MTC certificate.
    config=authority_config(caid,ids,public,n)
    (out/'authority.bin').write_bytes(config)
    config=checkpoint_config(config,entries,timestamp,cp_sigs)
    (out/'trust.bin').write_bytes(config)
    if authenticated is not None:
        # Do not accept output signed with keys different from independently pinned trust.
        generated=authenticate_snapshot(out/'trust.bin',trusted_authority,snapshot_checker)
        if generated!=authenticated:raise ValueError('Generated checkpoint differs from authenticated state')
    (out/'landmarks.txt').write_text(f'1\n{n} {expiration}\n0 0\n')
    sizes={}
    for mode in ['standalone','landmark']:
        cert=(out/f'{mode}-0000.der').read_bytes();outer,t=certificate_parts(cert)
        start,end=next(x for x in subtrees if x[0]==0);path=inclusion(entries[start:end],0)
        ss=sub_sigs[start,end] if mode=='standalone' else []
        sizes[mode]={'mtc_certificate_bytes':len(cert),'mtc_tbs_bytes':len(outer[0][2]),'mtc_inclusion_proof_bytes':32*len(path),
            'mtc_proof_encoded_bytes':len(outer[2][1])-1,'mtc_signature_bytes':len(ss[0][1]) if ss else 0,
            'mtc_cosignature_bytes':sum(len(s) for _,s in ss[1:]),'mtc_checkpoint_bytes':0,'mtc_landmark_reference_bytes':12,
            'mtc_predistributed_bytes':len(config) if mode=='landmark' else 0}
    source_metadata={'source_population':str(batch)}
    meta={'draft':DRAFT,'trust_anchor_draft':TA_DRAFT,'status':'MTC-experimental','tree_size':n,'crypto_family':family,'ca_id':caid,
        'cosigner_ids':ids,'cosigner_policy':'CA AND one additional local cosigner; no public transparency claim',
        'subtrees':subtrees,'landmarks':[0,n],'checkpoint':{'tree_size':n,'timestamp':timestamp,'hash':checkpoint.hex()},
        'latest_landmark':1,'landmark_expirations':[0,expiration],
        'ca_spki_sha256':H(public[0]).hex(),'cosigner_spki_sha256':H(public[1]).hex(),
        'input_sha256':{str(p):H(p.read_bytes()).hex() for p in originals},**source_metadata,
        'setup_ms':(time.perf_counter()-begin)*1000,'sizes':sizes,'trust_file_bytes':len(config),
        'ca_key_note':'Separate from directly-signing X509 CA as required by MTC -06 section 5.4',
        'changed_fields':['issuer','serialNumber','signature algorithm','signatureValue','old authorityKeyIdentifier omitted']}
    if family in SIGNATURE_PROFILES:meta.update(profile=family,standard_name=profile['standard_name'],implementation_algorithm=profile['implementation_algorithm'],security_level=profile['security_level'],merkle_hash=TREE_HASH,mtc_modes=['landmark','standalone'])
    if metadata:
        if authenticated is not None and set(metadata)&set(meta):
            raise ValueError('Metadata must not override authenticated generation fields')
        meta.update(metadata)
    (out/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n');return meta
