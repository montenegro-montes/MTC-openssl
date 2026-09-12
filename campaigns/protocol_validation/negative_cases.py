#!/usr/bin/env python3
"""Manual deterministic negative checks; use existing fixtures, never regenerate them."""
import argparse
import subprocess
import sys
from pathlib import Path
from validate_mtc import core,save,sha

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--profile',default='pq');p.add_argument('--openssl',default='/opt/mtc/openssl.sh');a=p.parse_args()
    if a.output.exists():p.error('Output exists')
    a.output.mkdir(parents=True);base=a.fixtures/'standalone-0000.der';raw=base.read_bytes()
    outer,t=core.certificate_parts(raw);proof=outer[2][1][1:];trust=(a.fixtures/'trust.bin').read_bytes()
    def envelope(fields,payload=proof):return core.certificate(core.seq(*fields),payload)
    fields=[x[2] for x in t];wrong_index=fields.copy();wrong_index[1]=core.integer((1<<48)+1024)
    wrong_issuer=fields.copy();wrong_issuer[3]=core.name('32473.999')
    proof_hash=bytearray(proof)
    # N=16 leaf 0 proof: empty extensions(2), start(6), end(6), vector length(2).
    if len(proof_hash)<=16:raise ValueError('N=16 proof required')
    proof_hash[16]^=1
    sig=bytearray(proof);sig[-1]^=1
    landmark=bytearray(trust)
    # Locate local landmark number after dynamic CA/signers and fixed log/limits.
    from validate_mtc import Reader
    r=Reader(trust);r.take(4);r.vector(1);count=r.number(1)
    for _ in range(count):r.vector(1);r.vector()
    r.take(18);number_at=r.pos;landmark[number_at+3]^=2
    root=bytearray(trust);root[number_at+4+6+8]^=1
    length=bytearray(proof);length[14:16]=b'\xff\xff'
    cases={'truncated':(raw[:-1],trust),'trailing':(raw+b'\0',trust),
           'length':(core.certificate(outer[0][2],bytes(length)),trust),
           'leaf-index':(envelope(wrong_index),trust),'issuer':(envelope(wrong_issuer),trust),
           'proof-hash':(core.certificate(outer[0][2],bytes(proof_hash)),trust),
           'signature':(core.certificate(outer[0][2],bytes(sig)),trust),
           'landmark-id':(raw,bytes(landmark)),'checkpoint-root':(raw,bytes(root))}
    rows=[]
    # Positive control prevents a missing provider/OpenSSL executable from making every mutation look successful.
    command=[sys.executable,str(Path(__file__).with_name('validate_mtc.py'))]
    baseline=a.output/'positive.json'
    subprocess.run(command+[str(base),'--trust',str(a.fixtures/'trust.bin'),'--mode','standalone','--profile',a.profile,'--openssl',a.openssl,'--output',str(baseline)],check=True)
    for name,(cert,config) in cases.items():
        directory=a.output/name;directory.mkdir();(directory/'object.der').write_bytes(cert);(directory/'trust.bin').write_bytes(config)
        result=subprocess.run(command+[str(directory/'object.der'),'--trust',str(directory/'trust.bin'),'--mode','standalone','--profile',a.profile,'--openssl',a.openssl,'--output',str(directory/'report.json')])
        import json
        report=json.loads((directory/'report.json').read_text())
        rows.append(dict(case=name,rejected=result.returncode==1 and report['overall']=='FAIL',error=report.get('error')))
    save(a.output/'negative-summary.json',dict(passed=all(r['rejected'] for r in rows),source_sha256=sha(raw),cases=rows))
    raise SystemExit(0 if all(r['rejected'] for r in rows) else 1)
if __name__=='__main__':main()
