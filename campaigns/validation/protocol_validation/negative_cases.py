#!/usr/bin/env python3
"""Invalid-input stress checks: deterministic cases, not a load test or fuzzing campaign."""
import argparse
from dataclasses import replace
import json
import subprocess
import sys
from pathlib import Path
from validate_mtc import core,save,sha
from config_formats import decode_mtb2, encode_mtb2

def classify_validator(returncode, report):
    if returncode == 0 and report.get('overall') == 'PASS':
        return 'ACCEPT', 'PASS', None
    if returncode == 1 and report.get('overall') == 'FAIL' and report.get('failure_kind') == 'INVALID_OBJECT':
        return 'REJECT', 'FAIL', report.get('error')
    return 'ERROR', report.get('overall'), report.get('error', 'Validator process/report inconsistency')

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
    bundle=decode_mtb2(trust)
    # Structurally valid authority/checkpoint disagreement.
    serial_range=encode_mtb2(replace(
        bundle,authority=replace(
            bundle.authority,max_serial=bundle.authority.max_serial+1)))
    # Structurally valid checkpoint/root change with the original signatures:
    # decoding succeeds, but independent checkpoint authentication must fail.
    subtrees=list(bundle.checkpoint.subtrees)
    start,end,digest=subtrees[0]
    changed=bytes([digest[0]^1])+digest[1:]
    subtrees[0]=(start,end,changed)
    changed_root=(changed if bundle.checkpoint.tree_size==1 else
                  core.H(b'\1'+changed+subtrees[1][2]))
    checkpoint_root=encode_mtb2(replace(
        bundle,checkpoint=replace(bundle.checkpoint,
            root_hash=changed_root,subtrees=tuple(subtrees))))
    malformed_kind=trust[:-7]+b'\x02'
    length=bytearray(proof);length[14:16]=b'\xff\xff'
    cases={'truncated':(raw[:-1],trust),'trailing':(raw+b'\0',trust),
           'length':(core.certificate(outer[0][2],bytes(length)),trust),
           'leaf-index':(envelope(wrong_index),trust),'issuer':(envelope(wrong_issuer),trust),
           'proof-hash':(core.certificate(outer[0][2],bytes(proof_hash)),trust),
           'signature':(core.certificate(outer[0][2],bytes(sig)),trust),
           'trust-kind':(raw,malformed_kind),
           'serial-range':(raw,serial_range),
           'checkpoint-root':(raw,checkpoint_root)}
    rows=[]
    # Positive control prevents a missing provider/OpenSSL executable from making every mutation look successful.
    command=[sys.executable,str(Path(__file__).with_name('validate_mtc.py'))]
    baseline=a.output/'positive.json'
    def invoke(arguments,report_path,log_dir):
        result=subprocess.run(command+arguments,capture_output=True,text=True)
        (log_dir/'validator.stdout.log').write_text(result.stdout)
        (log_dir/'validator.stderr.log').write_text(result.stderr)
        try:report=json.loads(report_path.read_text())
        except (OSError,ValueError):return 'ERROR',None,'Validator did not produce a readable JSON report'
        return classify_validator(result.returncode,report)
    observed,validator_result,reason=invoke([str(base),'--trust',str(a.fixtures/'trust.bin'),'--mode','standalone','--profile',a.profile,'--openssl',a.openssl,'--output',str(baseline)],baseline,a.output)
    control=dict(case='positive-control',expected='ACCEPT',observed=observed,test_result='PASS' if observed=='ACCEPT' else 'FAIL',validator_result=validator_result,reason=reason)
    if observed!='ACCEPT':
        save(a.output/'stress-checks-summary.json',dict(passed=False,test_result='FAIL',positive_control=control,cases=[]))
        print('FAIL positive-control - valid object was not accepted; invalid-input checks were not run',flush=True)
        raise SystemExit(1)
    print('PASS positive-control - valid object correctly accepted',flush=True)
    for name,(cert,config) in cases.items():
        directory=a.output/name;directory.mkdir();(directory/'object.der').write_bytes(cert);(directory/'trust.bin').write_bytes(config)
        observed,validator_result,reason=invoke([str(directory/'object.der'),'--trust',str(directory/'trust.bin'),'--mode','standalone','--profile',a.profile,'--openssl',a.openssl,'--output',str(directory/'report.json')],directory/'report.json',directory)
        passed=observed=='REJECT'
        row=dict(case=name,expected='REJECT',observed=observed,test_result='PASS' if passed else 'FAIL',validator_result=validator_result,reason=reason if reason else ('Invalid object was unexpectedly accepted' if observed=='ACCEPT' else None))
        rows.append(row);save(directory/'test-result.json',row)
        message='invalid object correctly rejected' if passed else ('invalid object was unexpectedly accepted' if observed=='ACCEPT' else 'validator could not complete the check')
        print(f"{row['test_result']} {name} - {message}",flush=True)
    passed=all(r['test_result']=='PASS' for r in rows)
    save(a.output/'stress-checks-summary.json',dict(passed=passed,test_result='PASS' if passed else 'FAIL',source_sha256=sha(raw),positive_control=control,cases=rows))
    print(('PASS' if passed else 'FAIL')+' invalid-input stress checks',flush=True)
    raise SystemExit(0 if passed else 1)
if __name__=='__main__':main()
