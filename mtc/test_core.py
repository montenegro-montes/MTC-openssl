from core import *
D=[bytes([i]) for i in range(130)];h=hashlib.sha256();p=hashlib.sha256();count=0
for end in range(1,131):
    for start in range(end):
        if start%(1<<(end-start-1).bit_length()):continue
        r=root(D[start:end]);h.update(f'[{start}, {end}) {r.hex()}\n'.encode())
        for index in range(start,end):
            proof=inclusion(D[start:end],index-start)
            assert evaluate(D[index],index,start,end,proof)==r
            p.update((f'{index} [{start}, {end})'+''.join(' '+v.hex() for v in proof)+'\n').encode());count+=1
assert h.hexdigest()=='94a95384a8c69acea9b50d035a58285b3a777cb7a724005faa5e1f1e1190007f'
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
for end in range(1,131):
    for start in range(end):
        chosen=[(start,end)] if start%(1<<(end-start-1).bit_length())==0 else cover(start,end)
        h.update((' '.join(f'[{a}, {b})' for a,b in chosen)+'\n').encode())
assert h.hexdigest()=='e0aecb912a10c57d753b6ecc64db73217f9bc4ed10fcb4e9062be3b6fbe1ebfd'
print('MTC draft C.4 covering vectors PASS')
