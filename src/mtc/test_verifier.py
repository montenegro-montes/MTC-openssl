import json,os,subprocess,tempfile
from pathlib import Path
from core import *
import core
from mutations import malformed_proofs
if 'MTC_BATCH' not in os.environ:
    raise SystemExit('ERROR: MTC_BATCH must point to the verifier fixture batch')
BATCH=Path(os.environ['MTC_BATCH'])
CHECK=os.environ.get('MTC_CHECK','/tmp/mtc-check')
FAMILIES=os.environ.get('MTC_TEST_FAMILIES','classic,pq').split(',')
assert len(FAMILIES)==2
count=0

def check(name,trust,mode,cert,ok):
    global count
    r=subprocess.run([CHECK,str(trust),str(int(mode=='landmark')),str(cert)],capture_output=True)
    assert r.returncode in [0,1],name+': crash '+r.stderr.decode()
    assert (r.returncode==0)==ok,name+': unexpected verification '+r.stderr.decode()
    count+=1

with tempfile.TemporaryDirectory() as temp:
    temp=Path(temp)
    for family in FAMILIES:
        b=BATCH/family;trust=b/'trust.bin'
        for mode in ['standalone','landmark']:
            trust=b/('trust.bin' if mode=='landmark' else 'authority.bin')
            cert=(b/f'{mode}-0000.der').read_bytes();outer,t=certificate_parts(cert);tbs=outer[0][2];p=outer[2][1][1:]
            check(family+mode,trust,mode,b/f'{mode}-0000.der',True)
            check('wrong mode',trust,'landmark' if mode=='standalone' else 'standalone',b/f'{mode}-0000.der',False)
            # Every truncation of the MTCProof exercises the parser, including empty path for N=1.
            variants={'leaf':certificate(mtc_tbs(cert,'32473.9',0),p),'no proof':certificate(tbs,b''),
                      'extra proof':certificate(tbs,p+b'\0'),'trailing DER':cert+b'\0',
                      'subtree':certificate(tbs,p[:2]+b'\xff'*6+p[8:]),'length':certificate(tbs,b'\xff\xff'+p[2:])}
            # Draft-06 Section 5.2.1 extension-vector framing and canonical order.
            variants.update({
                'valid different extensions':certificate(tbs,b'\0\4\x12\x34\0\0'+p[2:]),
                'incomplete extension':certificate(tbs,b'\0\2\x12\x34'+p[2:]),
                'truncated extension data':certificate(tbs,b'\0\5\0\1\0\2x'+p[2:]),
                'duplicate extensions':certificate(tbs,b'\0\10\0\1\0\0\0\1\0\0'+p[2:]),
                'unordered extensions':certificate(tbs,b'\0\10\0\2\0\0\0\1\0\0'+p[2:]),
            })
            variants.update(malformed_proofs(cert))
            if int.from_bytes(p[14:16],'big'):
                v=bytearray(p);v[16]^=1;variants['inclusion mutation']=certificate(tbs,bytes(v))
            fields=[v[2] for v in t];fields[6]=certificate_parts((BATCH/FAMILIES[1-FAMILIES.index(family)]/f'{mode}-0000.der').read_bytes())[1][6][2]
            variants['wrong public key']=certificate(seq(*fields),p)
            sigoff=16+int.from_bytes(p[14:16],'big')
            for width in [0,1,2]:
                variants['truncated uint24 '+str(width)]=certificate(tbs,p[:sigoff+width])
            variants['wrong signatures length']=certificate(tbs,p[:sigoff]+b'\xff'*3+p[sigoff+3:])
            variants['old uint16 signatures']=certificate(tbs,p[:sigoff]+p[sigoff+1:])
            for label,value in [
                ('old issuer',seq(der(49,seq(oid('1.3.6.1.4.1.44363.47.1'),der(12,b'32473.101'))))),
                ('wrong issuer',core.name('32473.999')),
                ('wrong issuer tag',seq(der(49,seq(oid(NAME_OID),der(12,relid('32473.101')))))),
                ('noncanonical relative OID',seq(der(49,seq(oid(NAME_OID),der(13,b'\x80'+relid('32473.101')))))),
                ('malformed issuer DER',b'\x30\x02\x31')]:
                fields=[v[2] for v in t];fields[3]=value
                variants[label]=certificate(seq(*fields),p)
            if mode=='standalone':
                v=bytearray(p);v[-1]^=1;variants['wrong cosignature']=certificate(tbs,bytes(v))
                # First signature begins after extensions/start/end/path/vector/id.
                off=16+int.from_bytes(p[14:16],'big')+3;off+=1+p[off]+2
                v=bytearray(p);v[off]^=1;variants['wrong CA signature']=certificate(tbs,bytes(v))
            if mode=='standalone':
                off=16+int.from_bytes(p[14:16],'big')
                block=p[off+3:];end=1+block[0];end+=2+int.from_bytes(block[end:end+2],'big')
                first,second=block[:end],block[end:]
                variants['duplicate cosigner']=certificate(tbs,p[:off]+vec(first+first+second,3))
                variants['unordered cosigners']=certificate(tbs,p[:off]+vec(second+first,3))
            for name,value in variants.items():
                target=temp/'case.der';target.write_bytes(value);check(name,trust,mode,target,False)
            for length in sorted(set([0,1,2,3,8,13,14,15,16,17,18,len(p)//2,len(p)-1])):
                target=temp/'case.der';target.write_bytes(certificate(tbs,p[:length]));check('truncation',trust,mode,target,False)
        config=(b/'trust.bin').read_bytes()
        assert config.startswith(b'MTB2')
        authority_length=int.from_bytes(config[4:8],'big')
        checkpoint_offset=8+authority_length+4
        checkpoint_hash_offset=checkpoint_offset+4+6+8
        v=bytearray(config);v[checkpoint_hash_offset]^=1;target=temp/'checkpoint.bin';target.write_bytes(v)
        check('modified checkpoint hash',target,'landmark',b/'landmark-0000.der',False)

        for label,pos in [('wrong checkpoint',-1),('bad encoding',0)]:
            v=bytearray(config);v[pos]^=1;target=temp/'trust.bin';target.write_bytes(v)
            check(label,target,'landmark',b/'landmark-0000.der',False)
        check('untrusted landmark',BATCH/FAMILIES[1-FAMILIES.index(family)]/'trust.bin','landmark',b/'landmark-0000.der',False)
print('MTC standalone/landmark parser/verifier:',count,'PASS')
