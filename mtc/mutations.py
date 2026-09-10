"""Deliberately invalid credentials for tests; never used by issuance/benchmark."""
import shutil
from pathlib import Path
from core import *
from prepare import sign

def signed_bad_constraints(directory,family,temp):
    original=(directory/'standalone-0000.der').read_bytes();outer,t=certificate_parts(original)
    variants={}
    for label,a,b in [('expired','000101000000Z','010101000000Z'),('not-yet-valid','400101000000Z','410101000000Z')]:
        fields=[v[2] for v in t];fields[4]=seq(der(23,a.encode()),der(23,b.encode()));variants[label]=seq(*fields)
    fields=[v[2] for v in t]
    for i in range(7,len(t)):
        if t[i][0]!=163:continue
        exts=[]
        for e in items(content(t[i][1],48)):
            ef=items(e[1])
            if ef[0][2]==oid('2.5.29.37'):exts.append(seq(ef[0][2],der(4,seq(oid('1.3.6.1.5.5.7.3.2')))))
            else:exts.append(e[2])
        fields[i]=der(163,seq(*exts))
    variants['clientAuth-only']=seq(*fields)
    meta=__import__('json').loads((directory/'manifest.json').read_text());caid=meta['ca_id']
    keys=[]
    for i in range(2):
        key=temp/f'{family}-cosigner-{i}.key';shutil.copyfile(directory/f'cosigner-{i}.key',key);keys.append(key)
    output={}
    for label,tbs in variants.items():
        r=root([entry(tbs)])
        sigs=[(ident,sign(key,message(ident,caid,0,1,r),family)) for ident,key in zip(meta['cosigner_ids'],keys)]
        output[label]=certificate(tbs,proof(0,1,[],sigs))
    return output

def malformed_proofs(cert):
    outer,t=certificate_parts(cert);tbs=outer[0][2];p=outer[2][1][1:]
    out={'missing':certificate(tbs,b''),'truncated':certificate(tbs,p[:-1]),'trailing':certificate(tbs,p+b'\0'),
         'malformed-length':certificate(tbs,b'\xff\xff'+p[2:]),'wrong-subtree':certificate(tbs,p[:2]+b'\xff'*6+p[8:])}
    v=bytearray(p);v[16]^=1;out['modified-proof']=certificate(tbs,bytes(v))
    if len(p)>200:
        v=bytearray(p);v[-1]^=1;out['bad-cosignature']=certificate(tbs,bytes(v))
        off=16+int.from_bytes(p[14:16],'big')+2;off+=1+p[off]+2
        v=bytearray(p);v[off]^=1;out['bad-CA-signature']=certificate(tbs,bytes(v))
    return out
