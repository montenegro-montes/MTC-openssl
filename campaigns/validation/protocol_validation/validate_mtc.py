#!/usr/bin/env python3
"""Offline validation of the implemented MTC subset; never launches TLS/Docker."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from semantics import timestamp_checks

REPO=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(REPO/'src/mtc'))
import core
from config_formats import decode_mca2, decode_mtb2
from crypto_profiles import crypto_profile, SIGNATURE_PROFILES, LEGACY_PROFILES


def require(ok,reason):
    if not ok:raise ValueError(reason)
def sha(data):return hashlib.sha256(data).hexdigest()
def save(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x') as f:json.dump(data,f,indent=2);f.write('\n')
class Reader:
    def __init__(self,data):self.data=data;self.pos=0
    def take(self,n):
        require(0<=n<=len(self.data)-self.pos,'truncated field')
        b=self.data[self.pos:self.pos+n];self.pos+=n;return b
    def number(self,n):return int.from_bytes(self.take(n),'big')
    def vector(self,n=2):return self.take(self.number(n))
    def end(self):require(self.pos==len(self.data),'trailing bytes')

def signatures(data):
    r=Reader(data);out=[];previous=None
    while r.pos<len(data):
        ident=r.vector(1);sig=r.vector();require(ident,'empty signer')
        order=(len(ident),ident);require(previous is None or previous<order,'unordered/duplicate signer')
        # Canonical base-128 relative OID, with no unfinished component.
        q=Reader(ident)
        while q.pos<len(ident):
            v=q.number(1);require(v!=128,'noncanonical signer ID')
            while v&128:v=q.number(1)
        out.append((ident,sig));previous=order
    r.end();return out

def trust(data,p):
    require(len(data)<=65536,'trust exceeds local MTC_MAX')
    if data.startswith(b'MCA2'):
        authority=decode_mca2(data);checkpoint=None;landmark=None
    elif data.startswith(b'MTB2'):
        bundle=decode_mtb2(data)
        authority=bundle.authority;checkpoint=bundle.checkpoint
        landmark=bundle.signaling_landmark
    else:raise ValueError('unknown trust storage format')
    ca=authority.ca_id;require(ca==p['ca_id'],'wrong issuer/profile')
    require(len(authority.signers)==2,'local policy requires two signers');keys={}
    for expected,(ident,spki) in zip(p['cosigner_ids'],authority.signers):
        require(ident==expected,'wrong cosigner identity')
        keys[core.relid(ident)]=(ident,spki)
    log=authority.log_number;lo=authority.min_serial;hi=authority.max_serial;n=hi-lo+1
    require(log==1 and lo==1<<48 and 1<=n<=1024,'invalid log/serial limits')
    state=dict(ca=ca,keys=keys,log=log,n=n,subs=[],checkpoint=None)
    if checkpoint is not None:
        require(checkpoint.tree_size==n and checkpoint.timestamp>0,
                'invalid checkpoint state')
        sigs=[(core.relid(ident),signature)
              for ident,signature in checkpoint.signatures]
        require(all(signature for _,signature in sigs),'empty checkpoint signature')
        subs=list(checkpoint.subtrees)
        require([(a,b) for a,b,_ in subs]==core.cover(0,n),'wrong landmark cover')
        state.update(subs=subs,checkpoint=(checkpoint.timestamp,
                     checkpoint.root_hash,sigs),landmark=landmark)
    return state

def openssl(executable,*args,data=None):
    r=subprocess.run([executable,*map(str,args)],input=data,capture_output=True)
    if r.returncode:
        diagnostic=(r.stdout+r.stderr).decode(errors='replace')
        if args[0]=='pkeyutl' and '-verify' in args and 'signature verification failure' in diagnostic.lower():
            raise ValueError('OpenSSL signature verification failed')
        raise RuntimeError('OpenSSL operation failed: '+str(args[0])+': '+diagnostic.strip())
    return r.stdout

def key_check(executable,der,p,tmp,label):
    core.content(der,48);path=tmp/(label+'.spki');path.write_bytes(der)
    encoded=openssl(executable,'pkey','-pubin','-inform','DER','-in',path,'-pubout','-outform','DER')
    require(encoded==der,'noncanonical SPKI')
    text=openssl(executable,'pkey','-pubin','-inform','DER','-in',path,'-text_pub','-noout').decode()
    normalized=re.sub('[^a-z0-9]','',text.lower())
    aliases={'P-256':['prime256v1','secp256r1','p256'],'P-384':['secp384r1','p384'],'P-521':['secp521r1','p521']}
    names=aliases[p['curve']] if p['curve'] else [re.sub('[^a-z0-9]','',v.lower()) for v in (p['standard_name'],p['implementation_algorithm'])]
    require(any(v in normalized for v in names),'SPKI profile not recognized in OpenSSL public-key description')
    return path

def verify_sigs(executable,sigs,state,p,start,end,root,timestamp,tmp):
    valid=set()
    for index,(ident,sig) in enumerate(sigs):
        if ident not in state['keys']:continue  # draft 7.2: ignore unknown cosigners
        name,key=state['keys'][ident];keyfile=key_check(executable,key,p,tmp,'signer-'+str(index))
        message=tmp/'message';signature=tmp/'signature'
        message.write_bytes(core.message(name,state['ca'],start,end,root,timestamp,state['log']));signature.write_bytes(sig)
        openssl(executable,'pkeyutl','-verify','-rawin','-pubin','-keyform','DER','-inkey',keyfile,
                '-in',message,'-sigfile',signature,*(['-digest',p['digest']] if p['digest'] else []))
        valid.add(ident)
    require(valid==set(state['keys']),'both configured cosigners must verify')

def trace(entry,index,start,end,path):
    # Same fold as core.evaluate(), recording intermediate hashes; primitives reused.
    require(0<=start<=index<end<1<<48 and start%(1<<(end-start-1).bit_length())==0,'invalid subtree/index')
    fn=index-start;sn=end-start-1;value=core.H(b'\0'+entry);values=[value.hex()]
    expected=0;a=fn;b=sn
    while b:
        if a&1 or a==b:
            while not a&1:a>>=1;b>>=1
        a>>=1;b>>=1;expected+=1
    require(len(path)==expected,'wrong inclusion proof hash count')
    for sibling in path:
        if fn&1 or fn==sn:
            value=core.H(b'\1'+sibling+value)
            while not fn&1:fn>>=1;sn>>=1
        else:value=core.H(b'\1'+value+sibling)
        fn>>=1;sn>>=1;values.append(value.hex())
    require(value==core.evaluate(entry,index,start,end,path),'trace/core disagreement')
    return value,values,expected

def validate(args):
    p=crypto_profile(args.profile);raw=args.object.read_bytes()
    require(len(raw)<=65536,'object exceeds local MTC_MAX; provide DER, not PEM')
    outer,t=core.certificate_parts(raw)
    require(outer[0][0]==48 and outer[1][2]==core.ALG and outer[2][0]==3 and t[2][2]==core.ALG,'wrong proof algorithm/wrapping')
    require(t[0][2]==core.der(160,core.integer(2)) and t[1][0]==2,'wrong version/serial')
    serial=int.from_bytes(t[1][1],'big');require(0<serial<1<<64 and core.integer(serial)==t[1][2],'noncanonical serial')
    require(t[3][2]==core.name(p['ca_id']),'wrong issuer')
    require(outer[2][1][:1]==b'\0','unused signatureValue bits')
    q=Reader(outer[2][1][1:]);extensions=q.vector();require(not extensions,'unsupported entry extensions')
    start=q.number(6);end=q.number(6);siblings=q.vector();sigs=signatures(q.vector(3));q.end()
    require(len(siblings)%32==0,'hash vector not multiple of SHA-256 size')
    state=trust(args.trust.read_bytes(),p);index=serial&((1<<48)-1)
    require(serial>>48==state['log'] and index<state['n'],'leaf outside configured log')
    require((start,end) in core.cover(0,state['n']),'outside initial-issuance subset cover')
    if args.mode=='landmark':require(state['checkpoint'] is not None
            and state.get('landmark') is not None,
            'landmark requires signaled trust checkpoint')
    else:require(bool(sigs),'standalone lacks subtree signatures')
    entry=core.entry(outer[0][2],extensions)
    if args.entry:require(args.entry.read_bytes()==entry,'log entry differs from certificate/SPKI')
    computed,values,expected_count=trace(entry,index,start,end,[siblings[i:i+32] for i in range(0,len(siblings),32)])
    expected=next((h for a,b,h in state['subs'] if (a,b)==(start,end)),None)
    if expected is not None:require(computed==expected,'Merkle root mismatch')
    with tempfile.TemporaryDirectory(prefix='mtc-offline-') as directory:
        tmp=Path(directory)
        # OpenSSL parses the whole X.509 envelope and all SPKIs; no TLS involved.
        require(openssl(args.openssl,'x509','-inform','DER','-outform','DER',data=raw)==raw,'noncanonical X.509 DER')
        key_check(args.openssl,t[6][2],p,tmp,'leaf')
        for i,(_,key) in enumerate(state['keys'].values()):key_check(args.openssl,key,p,tmp,'trust-'+str(i))
        if state['checkpoint']:
            timestamp,root,checkpoint_sigs=state['checkpoint']
            verify_sigs(args.openssl,checkpoint_sigs,state,p,0,state['n'],root,timestamp,tmp)
        if args.mode=='standalone':verify_sigs(args.openssl,sigs,state,p,start,end,computed,0,tmp)
    sender_match=None
    if args.sender:
        sender_match=args.sender.read_bytes()==raw;require(sender_match,'sender/wire DER mismatch')
    revoked_ranges_status='NOT_EXECUTED'
    if args.revocation_checker:
        require(args.revocation_trust is not None,'revocation checker requires --revocation-trust')
        revocation_mode='1' if args.mode=='landmark' else '0'
        result=subprocess.run(
            [str(args.revocation_checker),str(args.revocation_trust),
             revocation_mode,str(args.object)],
            capture_output=True,text=True)
        require(result.returncode==0,'revoked-range checker failed: '+(result.stdout+result.stderr).strip())
        revoked_ranges_status='PASS'
    checks=[dict(section=s,rule=r,status='PASS') for s,r in [
        ('6.2','DER/proof complete parse and canonical lengths'),
        ('6.2','MTCProof directly encoded in signatureValue'),
        ('6.2','uint48 subtree interval and uint24 signatures-vector encoding'),
        ('5.1','MTC-07 id-rdna-trustAnchorID issuer name'),
        ('6.2','serial/log/index and proof algorithm'),
        ('5.2.1 / 7.2','SPKI-bound reconstructed entry'),
        ('4.3.2','inclusion proof fold'),
        ('5.3.1 / 5.3.3','required signatures verified'),
        ('6.3' if args.mode=='standalone' else '6.4.4','mode-specific trust')]]
    checks.append(dict(
        section='6.2',
        rule='MTCProof extensions match supplied log entry',
        status='PASS' if args.entry else 'NOT_EXECUTED'))
    checks.append(dict(section='7.5',rule='relying-party revoked serial-number ranges',status=revoked_ranges_status))
    checks += [dict(section=s,rule=r,status='NOT_IMPLEMENTED') for s,r in [('6.4','evolving multi-landmark distribution'),('5.3 / 7.3','public independent cosigner ecosystem')]]
    timestamps=timestamp_checks(args.mode,state['checkpoint'])
    checks += [dict(section='8',rule='trust_anchors mapping requires captured transport evidence',status='NOT_EXECUTED'),
               dict(section='6.2 / 7.2',rule='MTCProof signatures use timestamp zero',status=timestamps['mtcproof']['status']),
               dict(section='5.3.1',rule='checkpoint timestamp encoding and authenticated range',status=timestamps['checkpoint']['status']),
               dict(section='5.3.1 / 5.3.2',rule='actual signing time and largest observed tree are signer assertions',status='UNRESOLVED' if state['checkpoint'] else 'NOT_APPLICABLE'),
               dict(section='local',rule='native checkpoint nonfuture policy, no maximum age',status='LOCAL_POLICY'),
               dict(section='8',rule='TLS transport (offline object only)',status='NOT_APPLICABLE')]
    return dict(draft=core.DRAFT,claim='implemented-subset conformance',scope='offline object; not full IETF compliance',
        overall='PASS',mode=args.mode,profile=args.profile,parse_complete=True,trailing_bytes=0,length_fields_valid=True,
        tree_size=state['n'],leaf_index=index,log_number=state['log'],subtree=[start,end],proof_hash_count=len(siblings)//32,
        expected_proof_hash_count=expected_count,leaf_hash=values[0],intermediate_hashes=values[1:],computed_root=computed.hex(),
        expected_root=expected.hex() if expected else None,root_match=computed==expected if expected else None,
        proof_valid=True,merkle_proof_valid=True,signature_valid=True,spki_valid=True,
        landmark_id=(f"{p['ca_id']}.1.{state['log']}.{state['landmark']}"
                     if args.mode=='landmark' else None),
        landmark_id_location='TLS signal and local trust configuration; absent from MTCProof' if args.mode=='landmark' else None,
        mtc_wire_sha256=sha(raw),trust_sha256=sha(args.trust.read_bytes()),sender_wire_match=sender_match,
        receiver_sha256=None,receiver_limitation='native verifier does not retain original DER bytes',
        timestamp_draft_requirement=timestamps, timestamp_local_policy=timestamps['local_policy'],
        draft_checks=dict(implemented_rules=sum(x['status']=='PASS' for x in checks),passed=sum(x['status']=='PASS' for x in checks),failed=sum(x['status']=='FAIL' for x in checks),not_implemented=sum(x['status']=='NOT_IMPLEMENTED' for x in checks),unresolved=sum(x['status']=='UNRESOLVED' for x in checks),checks=checks),
        limits=['initial issuance log=1, N<=1024, SHA-256, two configured signers',
                'Certificate validity/hostname and TLS CertificateVerify/Finished require the separate TLS validation',
                'standalone with authority.bin has no independent expected root; signatures authenticate computed root'])

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('object',type=Path);p.add_argument('--trust',type=Path,required=True)
    p.add_argument('--mode',choices=['landmark','standalone'],required=True)
    p.add_argument('--profile',choices=[*LEGACY_PROFILES,*SIGNATURE_PROFILES],default='pq')
    p.add_argument('--openssl',default='/opt/mtc/openssl.sh');p.add_argument('--entry',type=Path);p.add_argument('--sender',type=Path)
    p.add_argument('--revocation-checker',type=Path)
    p.add_argument('--revocation-trust',type=Path)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('Output exists; choose a new report')
    try:report=validate(a)
    except Exception as error:report=dict(draft=core.DRAFT,claim='implemented-subset conformance',overall='FAIL',mode=a.mode,profile=a.profile,error=str(error),failure_kind='INVALID_OBJECT' if isinstance(error,ValueError) else 'VALIDATOR_ERROR',parse_complete=None)
    save(a.output,report);print(report['overall'],a.output)
    return 0 if report['overall']=='PASS' else 1
if __name__=='__main__':sys.exit(main())
