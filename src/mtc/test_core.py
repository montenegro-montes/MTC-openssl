from core import *
import core
D=[bytes([i]) for i in range(130)];h=hashlib.sha256();p=hashlib.sha256();count=0
for end in range(131):
    for start in range(end+1):
        if end>start and start%(1<<(end-start-1).bit_length()):continue
        r=root(D[start:end]);h.update(f'[{start}, {end}) {r.hex()}\n'.encode())
        for index in range(start,end):
            proof=inclusion(D[start:end],index-start)
            assert evaluate(D[index],index,start,end,proof)==r
            p.update((f'{index} [{start}, {end})'+''.join(' '+v.hex() for v in proof)+'\n').encode());count+=1
assert h.hexdigest()=='b82806ad4265bb151c1119c0f4db437bb4d1a1f887b3a7fba1cd4ebf552e3e81'
assert p.hexdigest()=='ac2a8f989e44d99e399db448050ff5f19757df53cfb716aa81015d3955d8163f'
for n in [1,4,16,64,256,1024]:
    cs=cover(0,n)
    assert cs[0][0]==0 and cs[-1][1]==n
assert relid('32473.1')==bytes.fromhex('81fd5901')
for invalid in [b'\x30\x80',b'\x30\x81\x01\x00',b'\x30\x02\x00',b'\x30\x82\x00\x80']:
    try:items(invalid)
    except ValueError:pass
    else:raise AssertionError('Accepted malformed DER')
print('MTC draft C.1/C.2 rolling vectors PASS;',count,'inclusion evaluations')
h=hashlib.sha256()
for end in range(131):
    for start in range(end+1):
        chosen=cover(start,end)
        h.update((' '.join(f'[{a}, {b})' for a,b in chosen)+'\n').encode())
assert h.hexdigest()=='7fd9c8b926e9d2b5cf831560e8ce295a5ef97ad5c5ede4ea0dea28a8c8fc8bb0'
print('MTC draft C.4 covering vectors PASS')

for a,b,expected in [(0,0,[(0,0),(0,0)]),(0,1,[(0,1),(1,1)]),
                     (1,1,[(1,1),(1,1)]),(1,2,[(1,2),(2,2)]),
                     (0,8,[(0,4),(4,8)]),(7,9,[(7,8),(8,9)]),
                     (0,1<<47,[(0,1<<46),(1<<46,1<<47)]),
                     ((1<<48)-2,(1<<48)-1,[((1<<48)-2,(1<<48)-1),((1<<48)-1,(1<<48)-1)])]:
    assert cover(a,b)==expected
assert cover((1<<48)-1,(1<<48)-1)==[((1<<48)-1,(1<<48)-1)]*2
for a,b in [(-1,0),(2,1),(0,1<<48)]:
    try:cover(a,b)
    except ValueError:pass
    else:raise AssertionError('invalid interval')
for a in [0,1,(1<<48)-1]:
    try:evaluate(b'x',a,a,a,[])
    except ValueError:pass
    else:raise AssertionError('inclusion in empty subtree')
leaf=root([b'x'])
assert evaluate(b'x',0,0,1,[])==leaf
assert leaf!=H(b'\1'+leaf+root([]))
assert core.proof(0,1,[])[16:]==b'\0\0\0'
sigs=[('32473.101',b'abc')]
block=bytes.fromhex('0481fd59650003')+b'abc'
assert signatures(sigs)==uint(len(block),2)+block  # Default wrapper width remains uint16.
assert core.proof(0,1,[],sigs)[16:]==uint(len(block),3)+block
large=core.proof(0,1,[],[('1',b'x'*40000),('2',b'y'*40000)])[16:]
assert int.from_bytes(large[:3],'big')==len(large)-3>65535
expected=bytes.fromhex('301631143012060a2b0601040182da4b2f030d0481fd5965')
assert name('32473.101')==expected
# Minimal structural input; the original bytes must remain unchanged.
original=certificate(seq(der(160,integer(2)),integer(1),ALG,seq(),seq(),seq(),
                         seq(ALG,der(3,b'\0x'))),b'')
before=bytes(original);new=mtc_tbs(original,'32473.101',0)
fields=[v[2] for v in items(content(new,48))]
fields[3]=seq(der(49,seq(oid('1.3.6.1.4.1.44363.47.1'),der(12,b'32473.101'))))
old=seq(*fields)
assert original==before and old!=new and entry(old)!=entry(new)
assert root([entry(old)])!=root([entry(new)])
assert root([entry(old),b'x'])!=root([entry(new),b'x'])
print('draft-06 wire/issuer/empty/singleton/boundary tests PASS; issuer DER:',expected.hex())

# Draft-06 Section 6.2 certificate-format/MTCProof encoding.
# Keep this byte-level and deterministic: no OpenSSL or generated fixtures.
exts = b'\x12\x34\x00\x00'
path = [b'a' * 32, b'b' * 32]
sigs = [('32473.101', b'ca-signature'), ('32473.102', b'cosigner-signature')]
start, end = 0x010203040506, 0x01020304050a

p = core.proof(start, end, path, sigs, exts)
off = 0

ext_len = int.from_bytes(p[off:off+2], 'big')
assert ext_len == len(exts)
off += 2
assert p[off:off+ext_len] == exts
off += ext_len

assert int.from_bytes(p[off:off+6], 'big') == start
off += 6
assert int.from_bytes(p[off:off+6], 'big') == end
off += 6

proof_len = int.from_bytes(p[off:off+2], 'big')
off += 2
assert proof_len == 64
assert p[off:off+proof_len] == b''.join(path)
off += proof_len

sig_len = int.from_bytes(p[off:off+3], 'big')
off += 3
assert sig_len == len(p) - off
assert sig_len > 0

# The outer signatures vector is uint24; each SubtreeSignature signature is uint16.
sig_block = p[off:]
q = 0
seen = []
while q < len(sig_block):
    id_len = sig_block[q]
    q += 1
    ident = sig_block[q:q+id_len]
    q += id_len
    individual_len = int.from_bytes(sig_block[q:q+2], 'big')
    q += 2
    individual = sig_block[q:q+individual_len]
    q += individual_len
    assert individual
    seen.append(ident)
assert q == len(sig_block)
assert seen == sorted(seen, key=lambda x: (len(x), x))
assert len(seen) == len(set(seen))

try:core.proof(start,end,path,sigs,b'\x12\x34')
except ValueError:pass
else:raise AssertionError('accepted legacy incomplete MTC extension')

# Landmark-relative MTCProof has no subtree signatures.
landmark = core.proof(0, 1, [], (), b'')
assert landmark[16:] == b'\0\0\0'

# Log-entry extensions and MTCProof extensions match for the implemented empty case.
assert entry(new)[:2] == b'\0\0'
empty_proof = core.proof(0, 1, [])
assert empty_proof[:2] == b'\0\0'

# signatureValue contains the MTCProof directly as the BIT STRING payload.
cert = certificate(new, p)
outer, cert_tbs = certificate_parts(cert)
assert outer[2][0] == 3
bit_string = outer[2][1]
assert bit_string[0] == 0
assert bit_string[1:] == p

# Draft-06 serial construction and proof AlgorithmIdentifier.
assert cert_tbs[1][2] == integer((1 << 48) | 0)
assert cert_tbs[2][2] == ALG
assert outer[1][2] == ALG

print('draft-06 certificate-format/MTCProof encoding tests PASS')

# RFC 9162 prefix consistency; deterministic entries, no generated fixtures.
history=[bytes([i]) for i in range(16)]
old_root,new_root=root(history[:8]),root(history)
path=consistency(history,8)
assert path==[root(history[8:])]  # Independent expected proof for 8 -> 16.
assert verify_consistency(8,16,old_root,new_root,path)
def flipped(value):return bytes([value[0]^1])+value[1:]
assert not verify_consistency(8,16,flipped(old_root),new_root,path)
assert not verify_consistency(8,16,old_root,flipped(new_root),path)
assert not verify_consistency(8,16,old_root,new_root,[flipped(path[0])])
assert not verify_consistency(8,16,old_root,new_root,path[:-1])
assert not verify_consistency(8,16,old_root,new_root,path+[root([])])
assert not verify_consistency(8,16,old_root,new_root,[path[0][:-1]])
incompatible=list(history);incompatible[3]=b'changed prefix entry'
assert not verify_consistency(8,16,old_root,root(incompatible),consistency(incompatible,8))
# Non-power-of-two prefix exercises the SUBPROOF(..., false) branch.
assert consistency(history[:7],3)==[root(history[2:3]),root(history[3:4]),
                                    root(history[:2]),root(history[4:7])]
for m,n in [(1,2),(3,7),(5,8),(7,9),(8,9),(15,16),(1,1),(8,8),(16,16)]:
    a,b=root(history[:m]),root(history[:n]);path=consistency(history[:n],m)
    assert verify_consistency(m,n,a,b,path)
    assert not verify_consistency(m,n,flipped(a),b,path)
    if m==n:assert path==[]
    if path:assert not verify_consistency(m,n,a,b,path[:-1])
assert not verify_consistency(8,8,old_root,old_root,[root([])])
assert consistency([],0)==[] and consistency(history,0)==[]
assert verify_consistency(0,0,root([]),root([]),[])
assert verify_consistency(0,16,root([]),new_root,[])
assert not verify_consistency(0,0,root([]),new_root,[])
assert not verify_consistency(0,16,old_root,new_root,[])
assert not verify_consistency(0,16,root([]),new_root,[root([])])
assert not verify_consistency(8,16,old_root[:-1],new_root,[])
assert not verify_consistency(8,16,old_root,new_root[:-1],[])
for m,n in [(-1,16),(9,8),(0,1<<48)]:
    assert not verify_consistency(m,n,old_root,new_root,[])
for m in [-1,17]:
    try:consistency(history,m)
    except ValueError:pass
    else:raise AssertionError('invalid consistency sizes')
print('RFC 9162 consistency 8 -> 16, negatives, prefix violation and boundaries PASS')
