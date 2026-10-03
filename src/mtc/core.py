"""Independent MTC -06 wire and DER construction, SHA-256 profile.
No code or wire formats imported from the older experimental Merkle protocol.
"""
import base64
import hashlib
import struct
from dataclasses import dataclass
from trust_anchor_ids import decode_identifier, encode_identifier
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
def relid(s):return encode_identifier(s)
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

NULL_ENTRY=0
TBS_CERT_ENTRY=1

def parse_mtc_extensions(data):
    """Parse MTCLogEntryExtension vector *contents* (without uint16 length).

    Received encodings are never reordered or repaired.  Draft-06 Section
    5.2.1 requires strictly increasing extension_type values and no duplicates.
    Unknown, well-formed extensions remain opaque and byte-exact.
    """
    if not isinstance(data,bytes) or len(data)>0xffff:
        raise ValueError('MTC extensions')
    out=[];offset=0;previous=-1
    while offset<len(data):
        if len(data)-offset<4:raise ValueError('truncated MTC extension')
        extension_type=int.from_bytes(data[offset:offset+2],'big')
        length=int.from_bytes(data[offset+2:offset+4],'big');offset+=4
        if extension_type<=previous:raise ValueError('unordered or duplicate MTC extension')
        if length>len(data)-offset:raise ValueError('truncated MTC extension data')
        value=data[offset:offset+length];offset+=length
        out.append((extension_type,value));previous=extension_type
    return tuple(out)

def encode_mtc_extensions(extensions=()):
    """Encode structured ``(uint16 type, bytes value)`` pairs as vector contents.

    This returns the bytes inside the TLS ``extensions<0..2^16-1>`` vector,
    not its two-byte length prefix.  Structured input is canonically sorted;
    duplicate types are rejected.  Bytes input is already-encoded vector
    content and is strictly validated without normalization.
    """
    if isinstance(extensions,bytes):
        parse_mtc_extensions(extensions)
        return extensions
    values=[];seen=set()
    try:
        for extension_type,value in extensions:
            if (not isinstance(extension_type,int) or isinstance(extension_type,bool)
                    or not 0<=extension_type<=0xffff or not isinstance(value,bytes)
                    or len(value)>0xffff):
                raise ValueError('MTC extension')
            if extension_type in seen:raise ValueError('duplicate MTC extension')
            seen.add(extension_type);values.append((extension_type,value))
    except (TypeError,ValueError):
        raise ValueError('MTC extensions') from None
    values.sort()
    encoded=b''.join(uint(t,2)+vec(value) for t,value in values)
    if len(encoded)>0xffff:raise ValueError('MTC extensions too long')
    return encoded

def _validate_der(data):
    """Validate the DER properties needed by TBSCertificateLogEntry."""
    values=items(data)
    if len(values)!=1 or values[0][2]!=data:raise ValueError('DER value')
    tag,body,_=values[0]
    if not tag or (tag&0xc0)==0 and bool(tag&0x20)!=(tag in (0x30,0x31)):
        raise ValueError('invalid DER form')
    if tag in (2,10):
        if not body or (len(body)>1 and ((body[0]==0 and not body[1]&0x80)
                                        or (body[0]==0xff and body[1]&0x80))):
            raise ValueError('noncanonical integer')
    elif tag==1 and body not in (b'\0',b'\xff'):
        raise ValueError('noncanonical boolean')
    elif tag==3:
        if not body or body[0]>7 or (body[0] and body[-1]&((1<<body[0])-1)):
            raise ValueError('invalid bit string')
    elif tag==5 and body:
        raise ValueError('invalid NULL')
    elif tag==23 and (len(body)!=13 or body[-1:]!=b'Z' or not body[:-1].isdigit()):
        raise ValueError('noncanonical UTCTime')
    elif tag==24 and (len(body)!=15 or body[-1:]!=b'Z' or not body[:-1].isdigit()):
        raise ValueError('noncanonical GeneralizedTime')
    elif tag in (6,13):
        if not body:raise ValueError('invalid object identifier')
        i=0
        while i<len(body):
            if body[i]==0x80:raise ValueError('noncanonical object identifier')
            while True:
                if i>=len(body):raise ValueError('truncated object identifier')
                last=not body[i]&0x80;i+=1
                if last:break
    if tag&0x20:
        children=items(body)
        if tag==0x31 and [x[2] for x in children]!=sorted(x[2] for x in children):
            raise ValueError('noncanonical SET')
        for child in children:_validate_der(child[2])
    return data

@dataclass(frozen=True)
class TBSCertificateLogEntry:
    """Draft-06 Section 5.2.1 ASN.1 value, stored as exact DER fields."""
    version: bytes|None
    issuer: bytes
    validity: bytes
    subject: bytes
    subject_public_key_algorithm: bytes
    subject_public_key_info_hash: bytes
    issuer_unique_id: bytes|None=None
    subject_unique_id: bytes|None=None
    extensions: bytes|None=None

    def encode(self):
        fields=[self.version] if self.version is not None else []
        fields += [self.issuer,self.validity,self.subject,
                   self.subject_public_key_algorithm,self.subject_public_key_info_hash]
        fields += [x for x in (self.issuer_unique_id,self.subject_unique_id,self.extensions)
                   if x is not None]
        data=b''.join(fields)
        return self.decode(data)._unchecked_encode()

    def _unchecked_encode(self):
        fields=[self.version] if self.version is not None else []
        fields += [self.issuer,self.validity,self.subject,
                   self.subject_public_key_algorithm,self.subject_public_key_info_hash]
        fields += [x for x in (self.issuer_unique_id,self.subject_unique_id,self.extensions)
                   if x is not None]
        return b''.join(fields)

    def der(self):return der(0x30,self.encode())

    @classmethod
    def decode(cls,data):
        if not isinstance(data,bytes):raise ValueError('TBSCertificateLogEntry')
        fields=items(data)
        for field in fields:_validate_der(field[2])
        i=0;version=None
        if i<len(fields) and fields[i][0]==0xa0:
            version=fields[i][2]
            encoded_version=items(content(version,0xa0))
            if (len(encoded_version)!=1 or encoded_version[0][0]!=2 or
                    not 0<=int.from_bytes(encoded_version[0][1],'big',signed=True)<=2):
                raise ValueError('TBSCertificateLogEntry version')
            i+=1
        required=(0x30,0x30,0x30,0x30,0x04)
        if len(fields)-i<5 or tuple(x[0] for x in fields[i:i+5])!=required:
            raise ValueError('TBSCertificateLogEntry fields')
        base=[x[2] for x in fields[i:i+5]];i+=5
        optional={0x81:None,0x82:None,0xa3:None};last=0x80
        while i<len(fields):
            tag=fields[i][0]
            if tag not in optional or optional[tag] is not None or tag<=last:
                raise ValueError('TBSCertificateLogEntry optional fields')
            if tag in (0x81,0x82):
                body=fields[i][1]
                if not body or body[0]>7 or (body[0] and body[-1]&((1<<body[0])-1)):
                    raise ValueError('invalid unique identifier')
            optional[tag]=fields[i][2];last=tag;i+=1
        return cls(version,*base,optional[0x81],optional[0x82],optional[0xa3])

    @classmethod
    def from_tbs_certificate(cls,tbs):
        fields=items(content(tbs,0x30))
        if len(fields)<7:raise ValueError('TBSCertificate fields')
        i=1 if fields[0][0]==0xa0 else 0
        if len(fields)-i<6 or tuple(x[0] for x in fields[i:i+6])!=(2,0x30,0x30,0x30,0x30,0x30):
            raise ValueError('TBSCertificate fields')
        spki=items(content(fields[i+5][2],0x30))
        if len(spki)!=2 or spki[0][0]!=0x30 or spki[1][0]!=3:
            raise ValueError('SubjectPublicKeyInfo')
        # version is copied; serialNumber and signature are deliberately omitted.
        contents=((fields[0][2] if i else b'')+fields[i+2][2]+fields[i+3][2]+
                  fields[i+4][2]+spki[0][2]+der(4,H(fields[i+5][2]))+
                  b''.join(x[2] for x in fields[i+6:]))
        return cls.decode(contents)

@dataclass(frozen=True)
class MTCLogEntry:
    """Canonical Draft-06 Section 5.2.1 log entry."""
    extensions: bytes
    entry_type: int
    entry_data: bytes=b''

    def encode(self):
        extensions=encode_mtc_extensions(self.extensions)
        if not isinstance(self.entry_type,int) or not 0<=self.entry_type<=0xffff:
            raise ValueError('MTC log entry type')
        if not isinstance(self.entry_data,bytes):raise ValueError('MTC log entry data')
        if self.entry_type==NULL_ENTRY and self.entry_data:
            raise ValueError('null_entry payload')
        if self.entry_type==TBS_CERT_ENTRY:
            TBSCertificateLogEntry.decode(self.entry_data)
        value=vec(extensions)+uint(self.entry_type,2)+self.entry_data
        if len(value)>0xffff:raise ValueError('MTC log entry too long')
        return value

    @classmethod
    def decode(cls,data):
        if not isinstance(data,bytes) or len(data)>0xffff or len(data)<4:
            raise ValueError('MTC log entry')
        length=int.from_bytes(data[:2],'big')
        if length>len(data)-2:raise ValueError('truncated MTC extensions')
        extensions=data[2:2+length];parse_mtc_extensions(extensions)
        offset=2+length
        if len(data)-offset<2:raise ValueError('missing MTC log entry type')
        entry_type=int.from_bytes(data[offset:offset+2],'big');entry_data=data[offset+2:]
        value=cls(extensions,entry_type,entry_data)
        value.encode()
        return value

    @classmethod
    def null(cls,extensions=()):return cls(encode_mtc_extensions(extensions),NULL_ENTRY)

    @classmethod
    def from_tbs_certificate(cls,tbs,extensions=()):
        value=TBSCertificateLogEntry.from_tbs_certificate(tbs)
        return cls(encode_mtc_extensions(extensions),TBS_CERT_ENTRY,value.encode())

    def tbs_certificate_log_entry(self):
        if self.entry_type!=TBS_CERT_ENTRY:raise ValueError('not a tbs_cert_entry')
        return TBSCertificateLogEntry.decode(self.entry_data)

def null_entry(extensions=()):return MTCLogEntry.null(extensions).encode()

def entry_extensions(encoded_entry):
    """Return the exact canonical extension-vector contents from a log entry."""
    return MTCLogEntry.decode(encoded_entry).extensions

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
    """Encode a tbs_cert_entry; extensions are MTC vector contents, not X.509."""
    return MTCLogEntry.from_tbs_certificate(tbs,extensions).encode()
def root(entries):
    if not entries:return H(b'')
    if len(entries)==1:return H(b'\0'+entries[0])
    k=1<<((len(entries)-1).bit_length()-1)
    return H(b'\1'+root(entries[:k])+root(entries[k:]))
def consistency(entries,m):
    """RFC 9162 §2.1.4.1 PROOF(m, entries); n = len(entries).

    Empty prefixes use the empty proof (MTC draft-06 §4.4.1).
    Sizes are bounded by the existing MTC uint48 tree-size limit.
    """
    if not isinstance(m,int) or not 0<=m<=len(entries)<1<<48:raise ValueError('tree sizes')
    def subproof(data,size,complete):
        if size==len(data):return [] if complete else [root(data)]
        k=1<<((len(data)-1).bit_length()-1)
        if size<=k:return subproof(data[:k],size,complete)+[root(data[k:])]
        return subproof(data[k:],size-k,False)+[root(data[:k])]
    return subproof(entries,m,True) if m else []
def valid_subtree(start,end):
    """MTC draft-06 Section 4.1 subtree validity, within uint48."""
    if (not isinstance(start,int) or not isinstance(end,int)
            or not 0<=start<=end<1<<48):
        return False
    size=end-start
    alignment=1 if size==0 else 1<<(size-1).bit_length()
    return start%alignment==0


def subtree_consistency(entries,start,end):
    """MTC draft-06 Section 4.4.1 SUBTREE_PROOF(start, end, D_n)."""
    n=len(entries)
    if not valid_subtree(start,end) or end>n:
        raise ValueError('subtree')

    if start==end:
        return []

    def subproof(data,first,last,complete):
        size=len(data)
        if first==0 and last==size:
            return [] if complete else [root(data)]

        k=1<<((size-1).bit_length()-1)

        if last<=k:
            return subproof(data[:k],first,last,complete)+[root(data[k:])]

        if k<=first:
            return subproof(data[k:],first-k,last-k,complete)+[root(data[:k])]

        # A valid subtree crossing k necessarily begins at zero.
        if first!=0:
            raise ValueError('invalid subtree')

        return subproof(data[k:],0,last-k,False)+[root(data[:k])]

    return subproof(entries,start,end,True)


def verify_subtree_consistency(start,end,n,node_hash,root_hash,path):
    """MTC draft-06 Section 4.4.3 subtree consistency verification."""
    if (not isinstance(n,int) or not 0<=n<1<<48
            or not valid_subtree(start,end) or end>n):
        return False
    if (len(node_hash)!=32 or len(root_hash)!=32
            or any(len(p)!=32 for p in path)):
        return False

    if start==end:
        return not path and node_hash==H(b'')

    fn,sn,tn=start,end-1,n-1

    if sn==tn:
        while fn!=sn:
            fn>>=1
            sn>>=1
            tn>>=1
    else:
        while fn!=sn and sn&1:
            fn>>=1
            sn>>=1
            tn>>=1

    if fn==sn:
        fr=sr=node_hash
        offset=0
    else:
        if not path:
            return False
        fr=sr=path[0]
        offset=1

    for c in path[offset:]:
        if tn==0:
            return False

        if sn&1 or sn==tn:
            if fn<sn:
                fr=H(b'\1'+c+fr)
            sr=H(b'\1'+c+sr)

            while not sn&1:
                fn>>=1
                sn>>=1
                tn>>=1
        else:
            sr=H(b'\1'+sr+c)

        fn>>=1
        sn>>=1
        tn>>=1

    return tn==0 and fr==node_hash and sr==root_hash


def verify_consistency(m,n,old_root,new_root,path):
    """RFC 9162 §2.1.4.2; return False for invalid sizes/hashes/proofs.

    An empty prefix proves no property of a nonempty new root. Roots must
    be authenticated by the caller; this function does not authenticate them.
    """
    if not isinstance(m,int) or not isinstance(n,int) or not 0<=m<=n<1<<48:return False
    if len(old_root)!=32 or len(new_root)!=32 or any(len(p)!=32 for p in path):return False
    if m==0:return not path and old_root==H(b'') and (n!=0 or new_root==old_root)
    if m==n:return not path and old_root==new_root
    fn,sn=m-1,n-1
    while fn&1:fn>>=1;sn>>=1
    if fn==0:fr=sr=old_root;offset=0
    else:
        if not path:return False
        fr=sr=path[0];offset=1
    for p in path[offset:]:
        if sn==0:return False
        if fn&1 or fn==sn:
            fr=H(b'\1'+p+fr);sr=H(b'\1'+p+sr)
            while fn and not fn&1:fn>>=1;sn>>=1
        else:sr=H(b'\1'+sr+p)
        fn>>=1;sn>>=1
    return sn==0 and fr==old_root and sr==new_root
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
def encode_subtree_signature_block(values):
    """Encode canonical SubtreeSignature records without an outer length."""
    encoded=[];seen=set()
    try:
        for identity,signature in values:
            binary=relid(identity)
            if (not 1<=len(binary)<=0xff or binary in seen
                    or not isinstance(signature,bytes) or len(signature)>0xffff):
                raise ValueError('SubtreeSignature')
            seen.add(binary);encoded.append((binary,signature))
    except (TypeError,ValueError,OverflowError):
        raise ValueError('SubtreeSignature') from None
    encoded.sort(key=lambda value:(len(value[0]),value[0]))
    return b''.join(vec(identity,1)+vec(signature) for identity,signature in encoded)

def decode_subtree_signature_block(block):
    """Decode exact, canonically ordered SubtreeSignature records."""
    if not isinstance(block,bytes):raise ValueError('SubtreeSignature')
    values=[];position=0;previous=None
    while position<len(block):
        if len(block)-position<1:raise ValueError('SubtreeSignature')
        length=block[position];position+=1
        if not length or length>len(block)-position:raise ValueError('SubtreeSignature signer')
        binary=block[position:position+length];position+=length
        identity=decode_identifier(binary)
        key=(len(binary),binary)
        if previous is not None and key<=previous:raise ValueError('SubtreeSignature order')
        previous=key
        if len(block)-position<2:raise ValueError('SubtreeSignature')
        length=int.from_bytes(block[position:position+2],'big');position+=2
        if length>len(block)-position:raise ValueError('SubtreeSignature')
        signature=block[position:position+length];position+=length
        values.append((identity,signature))
    return tuple(values)

def encode_subtree_signatures(values,outer_width=2):
    return vec(encode_subtree_signature_block(values),outer_width)

def decode_subtree_signatures(encoded,outer_width=2):
    if (not isinstance(encoded,bytes) or not 1<=outer_width<=8
            or len(encoded)<outer_width):raise ValueError('SubtreeSignature vector')
    length=int.from_bytes(encoded[:outer_width],'big')
    if length!=len(encoded)-outer_width:raise ValueError('SubtreeSignature vector')
    return decode_subtree_signature_block(encoded[outer_width:])

def signatures(values,outer_width=2):
    # Compatibility wrapper. MCF1 uses uint16; MTCProof uses uint24.
    return encode_subtree_signatures(values,outer_width)
def proof(start,end,path,sigs=(),extensions=b''):
    """Encode MTCProof; extensions are canonical MTC vector contents."""
    extensions=encode_mtc_extensions(extensions)
    return vec(extensions)+uint(start,6)+uint(end,6)+vec(b''.join(path))+signatures(sigs,3)

def proof_extensions(encoded_proof):
    """Validate an MTCProof framing and return exact extension-vector contents."""
    if not isinstance(encoded_proof,bytes) or len(encoded_proof)<19:
        raise ValueError('MTCProof')
    offset=0
    def vector(width):
        nonlocal offset
        if len(encoded_proof)-offset<width:raise ValueError('truncated MTCProof vector')
        length=int.from_bytes(encoded_proof[offset:offset+width],'big');offset+=width
        if length>len(encoded_proof)-offset:raise ValueError('truncated MTCProof vector')
        value=encoded_proof[offset:offset+length];offset+=length
        return value
    extensions=vector(2);parse_mtc_extensions(extensions)
    if len(encoded_proof)-offset<12:raise ValueError('truncated MTCProof interval')
    offset+=12
    inclusion_proof=vector(2)
    if len(inclusion_proof)%32:raise ValueError('MTCProof inclusion proof')
    signature_block=vector(3)
    if offset!=len(encoded_proof):raise ValueError('trailing MTCProof data')
    decode_subtree_signature_block(signature_block)
    return extensions
def certificate(tbs,p):return seq(tbs,ALG,der(3,b'\0'+p))
