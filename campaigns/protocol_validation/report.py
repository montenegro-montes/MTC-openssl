#!/usr/bin/env python3
"""Join capture, extraction and offline evidence without asserting full compliance."""
import argparse
import json
from pathlib import Path
from validate_mtc import require,save,sha

def layers(wire, obj, independent=None):
    absent = dict(status='NOT_EXECUTED', verified=None, reason='No supplemental independent transcript report supplied')
    independent = independent or {}
    mapping = independent.get('trust_anchors_semantic_mapping', wire.get('trust_anchors_semantic_mapping', dict(status='NOT_EXECUTED', reason='Historical extraction has no structural semantic-mapping evidence')))
    endpoint = dict(status='PASS' if wire.get('endpoint_authentication') is True else 'NOT_EXECUTED', evidence='endpoint acceptance, not independent cryptographic verification')
    return dict(
        object_validation=dict(status=obj.get('overall', 'NOT_EXECUTED')),
        transport_structure_validation=dict(status=wire.get('overall', 'NOT_EXECUTED')),
        endpoint_authentication=endpoint,
        trust_anchors_semantic_mapping=mapping,
        trust_anchors_structure=dict(status='PASS' if mapping.get('wire_structure_match') is True else mapping['status']),
        trust_anchors_semantics=dict(status='PASS_EXPERIMENTAL_CODEPOINT' if mapping.get('message_semantics_match') is True else mapping['status']),
        trust_anchors_codepoint_status=dict(extension_codepoint='0xffa7', codepoint_status='experimental/private', draft_extension_type='TBD', draft_revision='draft-ietf-tls-trust-anchor-ids-04'),
        timestamp_draft_requirement=obj.get('timestamp_draft_requirement', dict(status='NOT_EXECUTED', reason='Historical object report; no new timestamp evidence')),
        timestamp_local_policy=obj.get('timestamp_local_policy', dict(status='LOCAL_POLICY', execution_status='NOT_EXECUTED', reason='Source policy is separate from historical evidence')),
        certificate_verify_endpoint_acceptance=endpoint,
        finished_endpoint_acceptance=endpoint,
        certificate_verify_independent_verification=independent.get('certificate_verify_independent_verification', absent),
        server_finished_independent_verification=independent.get('server_finished_independent_verification', absent),
        client_finished_independent_verification=independent.get('client_finished_independent_verification', absent))

def main():
    p=argparse.ArgumentParser();p.add_argument('--capture',type=Path,required=True)
    p.add_argument('--extraction',type=Path,required=True);p.add_argument('--object-report',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--independent-report',type=Path);a=p.parse_args()
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
        independent=None
        if a.independent_report:
            independent=json.loads(a.independent_report.read_text())
            require(independent.get('pcap_sha256')==meta['pcap_sha256'] and independent.get('keylog_sha256')==meta['keylog_sha256'], 'independent transcript report belongs to different capture/keylog')
            require(independent.get('metadata_sha256')==sha((a.capture/'metadata.json').read_bytes()), 'independent metadata mismatch')
            if independent.get('exact_transcript_status')=='AVAILABLE':
                require(independent.get('mtc_wire_sha256')==wire['mtc_wire_sha256'], 'independent wire certificate mismatch')
        report['validation_layers']=layers(wire,obj,independent)
        report['scope']='PASS covers object, transport structure and endpoint evidence only; independent cryptographic statuses and draft limitations are separate'
        if independent and independent.get('overall')=='FAIL':
            report['overall']='FAIL'
        report['evidence_reports_sha256']={str(path):sha(path.read_bytes()) for path in (a.object_report,a.extraction/'extraction.json',a.capture/'metadata.json')}
        if a.independent_report:report['evidence_reports_sha256'][str(a.independent_report)]=sha(a.independent_report.read_bytes())
    except Exception as error:report=dict(overall='FAIL',error=str(error))
    save(a.output,report);print(report['overall'],a.output)
    raise SystemExit(0 if report['overall']=='PASS' else 1)
if __name__=='__main__':main()
