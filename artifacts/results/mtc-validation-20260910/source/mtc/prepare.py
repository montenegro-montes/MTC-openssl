"""Create immutable initial issuance snapshots from the SAME compact population."""
import argparse,json,os,subprocess,time
from pathlib import Path
from core import *
OPENSSL='/opt/openssl/bin/openssl'
def command(*args,data=None):return subprocess.run([OPENSSL,*map(str,args)],input=data,capture_output=True,check=True).stdout
def keygen(path,family):
    command('genpkey','-algorithm','EC' if family=='classic' else 'ML-DSA-65',*(['-pkeyopt','ec_paramgen_curve:P-256'] if family=='classic' else []),'-out',path)
def sign(path,data,family):
    tmp=path.parent/'sign-input.tmp';tmp.write_bytes(data)
    try:return command('pkeyutl','-sign','-rawin','-inkey',path,'-in',tmp,*(['-digest','sha256'] if family=='classic' else []))
    finally:tmp.unlink()
def prepare(out,batch,family,n):
    begin=time.perf_counter();out.mkdir();caid='32473.'+('1' if family=='classic' else '2');ids=[caid,'32473.'+('3' if family=='classic' else '4')]
    keys=[];public=[]
    for i in range(2):
        key=out/f'cosigner-{i}.key';keygen(key,family);keys.append(key)
        public.append(command('pkey','-in',key,'-pubout','-outform','DER'))
        (out/f'cosigner-{i}.spki').write_bytes(public[-1])
    originals=[Path('/work/certs')/family/'server.pem']+[batch/family/'issued'/f'{i}.pem' for i in range(1,n)]
    certs=[from_pem(p.read_bytes()) for p in originals]
    tbs=[mtc_tbs(c,caid,i) for i,c in enumerate(certs)];entries=[entry(t) for t in tbs]
    log=out/'log';log.mkdir()
    for i,e in enumerate(entries):(log/f'{i:06d}.entry').write_bytes(e)
    checkpoint=root(entries);timestamp=int(time.time());subtrees=cover(0,n)
    # Each local cosigner independently reconstructs its entire initial view.
    cp_sigs=[];sub_sigs={}
    for ident,key in zip(ids,keys):
        mirror=[(log/f'{i:06d}.entry').read_bytes() for i in range(n)]
        assert root(mirror)==checkpoint
        cp_sigs.append((ident,sign(key,message(ident,caid,0,n,checkpoint,timestamp),family)))
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
    config=b'MCF1'+vec(caid.encode(),1)+bytes([len(ids)])
    for ident,spki in zip(ids,public):config+=vec(ident.encode(),1)+vec(spki)
    config+=uint(1,2)+uint(1<<48,8)+uint((1<<48)+n-1,8)
    (out/'authority.bin').write_bytes(config)
    config+=uint(1,4)
    config+=uint(n,6)+uint(timestamp,8)+checkpoint+signatures(cp_sigs)+bytes([len(subtrees)])
    for start,end in subtrees:config+=uint(start,6)+uint(end,6)+root(entries[start:end])
    (out/'trust.bin').write_bytes(config)
    (out/'landmarks.txt').write_text(f'1 1\n{n}\n0\n')
    sizes={}
    for mode in ['standalone','landmark']:
        cert=(out/f'{mode}-0000.der').read_bytes();outer,t=certificate_parts(cert)
        start,end=next(x for x in subtrees if x[0]==0);path=inclusion(entries[start:end],0)
        ss=sub_sigs[start,end] if mode=='standalone' else []
        sizes[mode]={'mtc_certificate_bytes':len(cert),'mtc_tbs_bytes':len(outer[0][2]),'mtc_inclusion_proof_bytes':32*len(path),
            'mtc_proof_encoded_bytes':len(outer[2][1])-1,'mtc_signature_bytes':len(ss[0][1]) if ss else 0,
            'mtc_cosignature_bytes':sum(len(s) for _,s in ss[1:]),'mtc_checkpoint_bytes':0,'mtc_landmark_reference_bytes':12,
            'mtc_predistributed_bytes':len(config) if mode=='landmark' else 0}
    meta={'draft':DRAFT,'trust_anchor_draft':TA_DRAFT,'status':'MTC-experimental','tree_size':n,'crypto_family':family,'ca_id':caid,
        'cosigner_ids':ids,'cosigner_policy':'CA AND one additional local cosigner; no public transparency claim',
        'subtrees':subtrees,'landmarks':[0,n],'checkpoint':{'tree_size':n,'timestamp':timestamp,'hash':checkpoint.hex()},
        'ca_spki_sha256':H(public[0]).hex(),'cosigner_spki_sha256':H(public[1]).hex(),
        'input_sha256':{str(p):H(p.read_bytes()).hex() for p in originals},'compact_batch':str(batch),
        'setup_ms':(time.perf_counter()-begin)*1000,'sizes':sizes,'trust_file_bytes':len(config),
        'ca_key_note':'Separate from directly-signing X509 CA as required by MTC -05 section 5.4',
        'changed_fields':['issuer','serialNumber','signature algorithm','signatureValue','old authorityKeyIdentifier omitted']}
    (out/'manifest.json').write_text(json.dumps(meta,indent=2)+'\n');return meta
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--batch',type=Path,default=Path('/work/compact/batch16'));p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();os.umask(0o077)
    if a.output.exists():p.error('Output exists; choose a new directory')
    sizes=[json.loads((a.batch/f/'manifest.json').read_text())['leaves'] for f in ['classic','pq']]
    if sizes[0]!=sizes[1] or not 1<=sizes[0]<=1024:p.error('Mismatched/unsupported population')
    a.output.mkdir(parents=True)
    for family in ['classic','pq']:prepare(a.output/family,a.batch,family,sizes[0])
    print(a.output)
