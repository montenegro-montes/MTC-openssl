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
assert signatures(sigs)==uint(len(block),2)+block  # MCF1 remains uint16
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
