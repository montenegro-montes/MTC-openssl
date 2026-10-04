"""Create immutable MTC issuance snapshots from an explicit X.509 population."""
import json,shutil,subprocess,tempfile,time
from datetime import datetime, timezone
from pathlib import Path
from core import *
from config_formats import (MCA2Authority, MCP2Checkpoint, MTB2Bundle,
                            encode_mca2, encode_mcp2, encode_mtb2)
from crypto_profiles import crypto_profile, SIGNATURE_PROFILES, TREE_HASH
OPENSSL='/opt/openssl/bin/openssl'
def command(*args,data=None):return subprocess.run([OPENSSL,*map(str,args)],input=data,capture_output=True,check=True).stdout
def keygen(path,family):
    profile=crypto_profile(family)
    command('genpkey','-algorithm',profile['implementation_algorithm'],*(['-pkeyopt','ec_paramgen_curve:'+profile['curve']] if profile['curve'] else []),'-out',path)
def sign(path,data,family):
    profile=crypto_profile(family)
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(data)
        tmp.flush()
        return command('pkeyutl','-sign','-rawin','-inkey',path,'-in',tmp.name,*(['-digest',profile['digest']] if profile['digest'] else []))
def cosign(ident,key,caid,start,end,subtree_hash,family,timestamp=0,log=1):
    return ident,sign(key,message(ident,caid,start,end,subtree_hash,timestamp,log),family)
def checkpoint_signature(ident,key,caid,n,checkpoint,timestamp,family,log=1):
    return cosign(ident,key,caid,0,n,checkpoint,family,timestamp,log)
def authority_config_v2(caid,ids,public,n,*,log_number=1):
    """Canonical MCA2 authority.bin from the same authority source data."""
    return encode_mca2(authority_value_v2(
        caid,ids,public,n,log_number=log_number))

def authority_value_v2(caid,ids,public,n,*,log_number=1):
    if (type(n) is not int or not 1<=n<1<<48 or len(ids)!=len(public)
            or type(log_number) is not int or not 1<=log_number<=65535):
        raise ValueError('MCA2 configuration')
    first=log_number<<48
    return MCA2Authority(
        caid,tuple(zip(ids,public)),log_number,first,first+n-1)

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

def checkpoint_config_v2(entries,timestamp,cp_sigs):
    """Canonical authority-independent MCP2 authenticated checkpoint."""
    return encode_mcp2(checkpoint_value_v2(entries,timestamp,cp_sigs))

def checkpoint_value_v2(entries,timestamp,cp_sigs):
    n=len(entries);subtrees=cover(0,n)
    return MCP2Checkpoint(
        n,timestamp,root(entries),tuple(cp_sigs),
        tuple((start,end,root(entries[start:end])) for start,end in subtrees))
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
            persistent_log=None,authenticated_snapshot=None,trusted_authority=None,snapshot_checker=None,
            external_cosigner=None,external_consistency_proof=None,
            log_number=1,landmark_reference=None,signaling_landmark=1):
    """Generate the usual material, optionally bound to an authenticated log view.

    Originals supply certificate fields absent from MTCLogEntry. Their derived
    entries must match the persisted entries byte-for-byte, in index order.
    Without landmark_reference this retains the legacy initial-landmark output.
    A supplied reference is selected and persisted by IssuanceLifecycle; this
    function only consumes its log-bound immutable sequence.
    signaling_landmark independently selects explicit MTB2 trust signaling;
    None encodes no landmark identity and no lifecycle value is inferred.
    """
    profile=crypto_profile(family)
    if not 1<=n<=1024:raise ValueError('Unsupported MTC population')
    if type(log_number) is not int or not 1<=log_number<=65535:
        raise ValueError('Invalid issuance log number')
    if (signaling_landmark is not None and
            (type(signaling_landmark) is not int
             or not 1<=signaling_landmark<1<<48)):
        raise ValueError('Invalid MTB2 signaling landmark')
    landmark_sequence=None
    if landmark_reference is not None:
        from landmarks import validate_sequence
        if (not isinstance(landmark_reference,tuple)
                or len(landmark_reference)!=2):
            raise ValueError('Invalid lifecycle landmark reference')
        landmark_log,landmark_sequence=landmark_reference
        if type(landmark_log) is not int or landmark_log!=log_number:
            raise ValueError('Lifecycle landmark issuance log differs from prepare log')
        if not isinstance(landmark_sequence,tuple):
            raise ValueError('Invalid lifecycle landmark reference')
        validate_sequence(landmark_sequence)
    if originals is None:raise ValueError('MTC requires an explicit same-profile X.509 population')
    if external_cosigner is not None and external_consistency_proof is None:
        raise ValueError('Injected external cosigner requires an explicit consistency proof')
    if (external_cosigner is not None and hasattr(external_cosigner,'log')
            and external_cosigner.log!=log_number):
        raise ValueError('External cosigner issuance log differs from prepare log')
    begin=time.perf_counter();caid=profile['ca_id'];ids=list(profile['cosigner_ids'])
    if len(originals)!=n:raise ValueError('Population length differs from N')
    certs=[from_pem(p.read_bytes()) for p in originals]
    tbs=[mtc_tbs(c,caid,i,log_number) for i,c in enumerate(certs)];entries=[entry(t) for t in tbs]
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
            if authenticated['log_number']!=log_number:
                raise ValueError('Authenticated snapshot issuance log differs from prepare log')
            authenticated_state={
                'tree_size':authenticated['tree_size'],
                'hash':authenticated['hash'],
            }
            if state!=authenticated_state or state['tree_size']!=n:
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
    if (landmark_sequence is not None
            and landmark_sequence[-1].tree_size>n):
        raise ValueError('Lifecycle landmark exceeds prepared issuance log')
    # Each cosigner independently reconstructs its entire initial view.
    cp_sigs=[];sub_sigs={}
    mirror=[(log/f'{i:06d}.entry').read_bytes() for i in range(n)]
    assert root(mirror)==checkpoint
    cp_sigs.append(checkpoint_signature(
        ids[0],keys[0],caid,n,checkpoint,timestamp,family,log_number))
    for start,end in subtrees:
        sub_sigs.setdefault((start,end),[]).append(
            cosign(ids[0],keys[0],caid,start,end,root(mirror[start:end]),
                   family,log=log_number))
    mirror=[(log/f'{i:06d}.entry').read_bytes() for i in range(n)]
    assert root(mirror)==checkpoint
    if external_cosigner is None:
        from cosigner import ExternalCosigner
        external_cosigner=ExternalCosigner(
            ids[1],keys[1],caid,family,log=log_number)
        external_consistency_proof=consistency(mirror,0)
    external_cosigner.accept_view(n,checkpoint,external_consistency_proof)
    cp_sigs.append(external_cosigner.cosign_accepted(timestamp))
    for start,end in subtrees:
        sub_sigs[start,end].append(external_cosigner.cosign_subtree(
            start,end,root(mirror[start:end]),
            subtree_consistency(mirror,start,end)))
    landmark_certificates=[]
    for i,t in enumerate(tbs):
        start,end=next(x for x in subtrees if x[0]<=i<x[1]);path=inclusion(entries[start:end],i-start)
        assert evaluate(entries[i],i,start,end,path)==root(entries[start:end])
        p=proof(start,end,path,sub_sigs[start,end],entry_extensions(entries[i]))
        cert=certificate(t,p)
        (out/f'standalone-{i:04d}.der').write_bytes(cert)
        (out/f'standalone-{i:04d}.pem').write_bytes(pem(cert))
        if landmark_sequence is None:
            landmark_start,landmark_end,landmark_path=start,end,path
        else:
            from landmarks import relative_proof
            try:
                _,landmark_start,landmark_end,landmark_path=relative_proof(
                    entries,i,landmark_sequence)
            except ValueError as error:
                if str(error)=='landmark not allocated':
                    continue
                raise
        p=proof(landmark_start,landmark_end,landmark_path,[],
                entry_extensions(entries[i]))
        cert=certificate(t,p)
        (out/f'landmark-{i:04d}.der').write_bytes(cert)
        (out/f'landmark-{i:04d}.pem').write_bytes(pem(cert))
        landmark_certificates.append(i)
    # OOB configuration: keys, serial limits, signed checkpoint and its two covering subtrees.
    # This file is a lab storage format, never sent as an MTC certificate.
    authority_v2=authority_value_v2(
        caid,ids,public,n,log_number=log_number)
    checkpoint_v2=checkpoint_value_v2(entries,timestamp,cp_sigs)
    (out/'authority.bin').write_bytes(encode_mca2(authority_v2))
    config=encode_mtb2(MTB2Bundle(
        authority_v2,checkpoint_v2,signaling_landmark))
    (out/'trust.bin').write_bytes(config)
    if authenticated is not None:
        # Do not accept output signed with keys different from independently pinned trust.
        with tempfile.NamedTemporaryFile(suffix='.mcp2') as generated_snapshot:
            generated_snapshot.write(checkpoint_config_v2(entries,timestamp,cp_sigs))
            generated_snapshot.flush()
            generated=authenticate_snapshot(
                generated_snapshot.name,trusted_authority,snapshot_checker)
        if generated!=authenticated:raise ValueError('Generated checkpoint differs from authenticated state')
    if landmark_sequence is None:
        published_landmarks=(0,n);latest_landmark=1
        landmark_expirations=(0,expiration)
        landmark_publication=f'1\n{n} {expiration}\n0 0\n'.encode()
    else:
        from landmarks import encode_publication
        published_landmarks=tuple(value.tree_size for value in landmark_sequence)
        latest_landmark=landmark_sequence[-1].number
        landmark_expirations=tuple(value.expiration for value in landmark_sequence)
        landmark_publication=encode_publication(landmark_sequence,timestamp)
    (out/'landmarks.txt').write_bytes(landmark_publication)
    sizes={}
    modes=['standalone']+(['landmark'] if landmark_certificates else [])
    for mode in modes:
        cert=(out/f'{mode}-0000.der').read_bytes();outer,t=certificate_parts(cert)
        start,end=next(x for x in subtrees if x[0]==0);path=inclusion(entries[start:end],0)
        ss=sub_sigs[start,end] if mode=='standalone' else []
        sizes[mode]={'mtc_certificate_bytes':len(cert),'mtc_tbs_bytes':len(outer[0][2]),'mtc_inclusion_proof_bytes':32*len(path),
            'mtc_proof_encoded_bytes':len(outer[2][1])-1,'mtc_signature_bytes':len(ss[0][1]) if ss else 0,
            'mtc_cosignature_bytes':sum(len(s) for _,s in ss[1:]),'mtc_checkpoint_bytes':0,'mtc_landmark_reference_bytes':12,
            'mtc_predistributed_bytes':len(config) if mode=='landmark' else 0}
    source_metadata={'source_population':str(batch)}
    meta={'draft':DRAFT,'trust_anchor_draft':TA_DRAFT,'status':'MTC-experimental','tree_size':n,'log_number':log_number,'crypto_family':family,'ca_id':caid,
        'cosigner_ids':ids,'cosigner_policy':'CA AND one additional local cosigner; no public transparency claim',
        'subtrees':subtrees,'landmarks':list(published_landmarks),'checkpoint':{'tree_size':n,'timestamp':timestamp,'hash':checkpoint.hex()},
        'latest_landmark':latest_landmark,'landmark_expirations':list(landmark_expirations),
        'ca_spki_sha256':H(public[0]).hex(),'cosigner_spki_sha256':H(public[1]).hex(),
        'input_sha256':{str(p):H(p.read_bytes()).hex() for p in originals},**source_metadata,
        'setup_ms':(time.perf_counter()-begin)*1000,'sizes':sizes,'trust_file_bytes':len(config),
        'ca_key_note':'Separate from directly-signing X509 CA as required by MTC -06 section 5.4',
        'changed_fields':['issuer','serialNumber','signature algorithm','signatureValue','old authorityKeyIdentifier omitted']}
    profile_modes=['landmark','standalone'] if landmark_certificates else ['standalone']
    if family in SIGNATURE_PROFILES:meta.update(profile=family,standard_name=profile['standard_name'],implementation_algorithm=profile['implementation_algorithm'],security_level=profile['security_level'],merkle_hash=TREE_HASH,mtc_modes=profile_modes)
    if metadata:
        if authenticated is not None and set(metadata)&set(meta):
            raise ValueError('Metadata must not override authenticated generation fields')
        meta.update(metadata)
    (out/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n');return meta
