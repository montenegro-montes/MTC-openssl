#!/usr/bin/env python3
"""Join capture, extraction and offline evidence without asserting full compliance."""
import argparse
import json
from pathlib import Path
from validate_mtc import require,save,sha

def main():
    p=argparse.ArgumentParser();p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--extraction',type=Path,required=True);p.add_argument('--object-report',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():p.error('Report exists')
    meta=json.loads((a.capture/'metadata.json').read_text());wire=json.loads((a.extraction/'extraction.json').read_text())
    obj=json.loads(a.object_report.read_text())
    try:
        require(wire['overall']=='PASS' and obj['overall']=='PASS','validation incomplete')
        require(meta['status']=='CAPTURED_NOT_PROTOCOL_VALIDATED','capture failed')
        digest=sha((a.extraction/'mtc-wire.bin').read_bytes())
        require(digest==wire['mtc_wire_sha256']==obj['mtc_wire_sha256']==meta['fixture_sha256'],'inconsistent object evidence')
        require(sha((a.capture/'handshake.pcap').read_bytes())==meta['pcap_sha256']==wire['pcap_sha256'],'PCAP changed')
        require(obj['profile']==meta['profile'] and obj['mode']==meta['mode'] and obj['tree_size']==meta['tree_size'],'profile/mode/N mismatch')
        for name,digest in meta['evidence_sha256'].items():require(sha((a.capture/name).read_bytes())==digest,'endpoint evidence changed')
        report=dict(obj,scenario=meta['scenario'],tls_version=wire['tls_version'],cipher=wire['cipher'],key_exchange=wire['key_exchange'],
            sender_wire_match=wire['sender_wire_match'],receiver_reserialized_wire_match=wire['receiver_reserialized_wire_match'],
            pcap_sha256=meta['pcap_sha256'],fixture_sha256=meta['fixture_sha256'],git_commit=meta['git_commit'],image_id=meta['image_id'],
            openssl_version=meta['openssl_version'],liboqs_version=meta['liboqs_version'],oqs_provider_commit=meta['oqs_provider_commit'],
            timestamp=meta['timestamp'],transport_checks=wire,scope='one handshake, implemented subset only; unresolved mappings retained')
        report['evidence_reports_sha256']={str(path):sha(path.read_bytes()) for path in (a.object_report,a.extraction/'extraction.json',a.capture/'metadata.json')}
    except Exception as error:report=dict(overall='FAIL',error=str(error))
    save(a.output,report);print(report['overall'],a.output)
    raise SystemExit(0 if report['overall']=='PASS' else 1)
if __name__=='__main__':main()
