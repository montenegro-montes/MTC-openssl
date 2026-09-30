"""Independent MTC -06 wire and DER construction, SHA-256 profile.
No code or wire formats imported from the older experimental Merkle protocol.
"""
import base64
import hashlib
import struct
DRAFT='draft-ietf-plants-merkle-tree-certs-06'
TA_DRAFT='draft-ietf-tls-trust-anchor-ids-04'
PROOF_OID='1.3.6.1.4.1.44363.47.0'
NAME_OID='1.3.6.1.4.1.44363.47.3'
H=lambda x:hashlib.sha256(x).digest()
def uint(n,size):return n.to_bytes(size,'big')
def vec(x,size=2):return uint(len(x),size)+x
def der(tag,x):
    n=len(x);length=bytes([n]) if n<128 else bytes([128+(n.bit_length()+7)//8])+uint(n,(n.bit_length()+7)//8)
    return bytes([tag])+length+x
def items(data):
    out=[];i=0
    while i<len(data):
        start=i;tag=data[i];i+=1
        if tag&31==31:raise ValueError('high tag unsupported')
        if i==len(data):raise ValueError('missing length')
        n=data[i];i+=1
        if n&128:
            k=n&127
            if not 1<=k<=4 or i+k>len(data) or data[i]==0:raise ValueError('length')
            n=int.from_bytes(data[i:i+k],'big');i+=k
            if n<128:raise ValueError('noncanonical length')
        if i+n>len(data):raise ValueError('truncated')
        out.append((tag,data[i:i+n],data[start:i+n]));i+=n
    return out
def content(data,tag):
    xs=items(data)
    if len(xs)!=1 or xs[0][0]!=tag:raise ValueError('DER type')
    return xs[0][1]
def relid(s):
    output=b''
    for part in s.split('.'):
        n=int(part);b=bytes([n&127]);n>>=7
        while n:b=bytes([(n&127)|128])+b;n>>=7
        output+=b
    return output
def oid(s):
    ns=list(map(int,s.split('.')))
    return der(6,relid('.'.join(map(str,[40*ns[0]+ns[1]]+ns[2:]))))
def integer(n):
    x=uint(n,max(1,(n.bit_length()+7)//8))
    return der(2,(b'\0' if x[0]&128 else b'')+x)
def seq(*x):return der(0x30,b''.join(x))
ALG=seq(oid(PROOF_OID))
def name(caid):return seq(der(0x31,seq(oid(NAME_OID),der(13,relid(caid)))))
def from_pem(data):return base64.b64decode(b''.join(data.splitlines()[1:-1]))
def pem(data):
    b=base64.b64encode(data)
    return b'-----BEGIN CERTIFICATE-----\n'+b'\n'.join(b[i:i+64] for i in range(0,len(b),64))+b'\n-----END CERTIFICATE-----\n'
def certificate_parts(cert):
    outer=items(content(cert,0x30))
    if len(outer)!=3:raise ValueError('certificate fields')
    tbs=items(content(outer[0][2],0x30))
    if len(tbs)<7 or tbs[0][0]!=0xa0:raise ValueError('only v3 fixtures')
    return outer,tbs

def mtc_tbs(original,caid,index,log=1):
    _,t=certificate_parts(original)
    fields=[x[2] for x in t]
    fields[1]=integer((log<<48)|index);fields[2]=ALG;fields[3]=name(caid)
    # Old authorityKeyIdentifier references a different CA; omit it.
    for i in range(7,len(fields)):
        if t[i][0]==0xa3:
            exts=items(content(t[i][1],0x30))
            exts=[e[2] for e in exts if items(e[1])[0][2]!=oid('2.5.29.35')]
            fields[i]=der(0xa3,seq(*exts))
    return seq(*fields)
def entry(tbs,extensions=b''):
    t=items(content(tbs,0x30));spki=items(content(t[6][2],0x30))
    return vec(extensions)+b'\0\1'+b''.join(t[i][2] for i in [0,3,4,5])+spki[0][2]+der(4,H(t[6][2]))+b''.join(x[2] for x in t[7:])
def root(entries):
    if not entries:return H(b'')
    if len(entries)==1:return H(b'\0'+entries[0])
    k=1<<((len(entries)-1).bit_length()-1)
    return H(b'\1'+root(entries[:k])+root(entries[k:]))
def inclusion(entries,index):
    if not 0<=index<len(entries):raise ValueError('index')
    if len(entries)==1:return []
    k=1<<((len(entries)-1).bit_length()-1)
    return inclusion(entries[:k],index)+[root(entries[k:])] if index<k else inclusion(entries[k:],index-k)+[root(entries[:k])]
def evaluate(leaf,index,start,end,proof):
    if not 0<=start<=index<end<1<<48 or start%(1<<(end-start-1).bit_length()):raise ValueError('subtree')
    fn=index-start;sn=end-start-1;r=H(b'\0'+leaf)
    for p in proof:
        if len(p)!=32 or sn==0:raise ValueError('proof')
        if fn&1 or fn==sn:
            r=H(b'\1'+p+r)
            while not fn&1:fn>>=1;sn>>=1
        else:r=H(b'\1'+r+p)
        fn>>=1;sn>>=1
    if sn:raise ValueError('short proof')
    return r
def cover(start,end):
    if not 0<=start<=end<1<<48:raise ValueError('interval')
    if end-start<=1:return [(start,end),(end,end)]
    last=end-1;mask=(1<<((start^last).bit_length()-1))-1;mid=last&~mask
    left=start&~((1<<(~start&mask).bit_length())-1)
    return [(left,mid),(mid,end)]
def message(cosigner,caid,start,end,r,timestamp=0,log=1):
    return b'subtree/v1\n\0'+vec(('oid/1.3.6.1.4.1.'+cosigner).encode(),1)+uint(timestamp,8)+vec(('oid/1.3.6.1.4.1.'+caid+'.0.'+str(log)).encode(),1)+uint(start,8)+uint(end,8)+r
def signatures(values,outer_width=2):
    # MCF1 retains uint16; only MTCProof uses a uint24 outer vector.
    return vec(b''.join(vec(relid(i),1)+vec(s) for i,s in sorted(values,key=lambda x:(len(relid(x[0])),relid(x[0])))),outer_width)
def proof(start,end,path,sigs=(),extensions=b''):
    return vec(extensions)+uint(start,6)+uint(end,6)+vec(b''.join(path))+signatures(sigs,3)
def certificate(tbs,p):return seq(tbs,ALG,der(3,b'\0'+p))
