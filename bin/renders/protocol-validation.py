#!/usr/bin/env python3
"""Render plain-language English HTML reports for protocol validation."""
import argparse, html, json, re
from pathlib import Path
from host_info import collect_host_info, host_rows

def esc(x): return html.escape(str(x))
def read(path):
    try: return json.loads(Path(path).read_text())
    except (OSError, ValueError): return None
def status(value):
    if not isinstance(value,dict): return 'MISSING'
    raw=value.get('status',value.get('result',value.get('overall',value.get('passed'))))
    if raw is True:return 'PASS'
    if raw is False:return 'NO PASS'
    return 'PASS' if str(raw).upper() in ('PASS','SUCCESS','COMPLETED') else 'NO PASS'
def table(headers, rows, css_class=''):
    class_attr=f' class="{esc(css_class)}"' if css_class else ''
    return f'<div class="scroll"><table{class_attr}><thead><tr>'+''.join(f'<th>{esc(x)}</th>' for x in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join(f'<td>{esc(x)}</td>' for x in row)+'</tr>' for row in rows)+'</tbody></table></div>'
def draft_section_key(value):
    """Sort draft references numerically; local/non-section rules come last."""
    text=str(value or '').strip()
    references=re.findall(r'\d+(?:\.\d+)+|\d+',text)
    if not references:return (1,(),text.casefold())
    # Prefixes such as MTC-05 and TA-04 identify the document revision.  A
    # following dotted value is the actual section number.
    section=next((item for item in references if '.' in item),references[-1])
    return (0,tuple(int(part) for part in section.split('.')),text.casefold())
def shell(title, result, intro, sections):
    color='pass' if result=='PASS' else 'fail'; body=''.join(f'<section><h2>{esc(name)}</h2>{content}</section>' for name,content in sections)
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{esc(title)}</title><style>body{{font:16px system-ui;background:#f3f6fa;color:#172033;margin:0}}main{{max-width:1150px;margin:auto;padding:28px}}header,section{{background:#fff;border:1px solid #dbe3ed;border-radius:12px;padding:22px;margin:16px 0}}h1{{margin:.2em 0}}h2{{font-size:20px}}h3{{margin-top:25px}}.result{{font-size:26px;font-weight:800}}.pass{{color:#087443}}.fail{{color:#b42318}}.note{{background:#eef5ff;padding:14px;border-left:5px solid #3974c6}}table{{border-collapse:collapse;width:100%}}th,td{{padding:10px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top;overflow-wrap:anywhere}}th{{background:#edf2f7}}.draft-checks th:first-child,.draft-checks td:first-child{{width:150px;min-width:150px;white-space:nowrap}}.scroll{{overflow:auto}}code{{background:#edf2f7;padding:2px 5px}}</style></head><body><main><header><p>Explained validation report</p><h1>{esc(title)}</h1><p class="result {color}">{esc(result)}</p><p>{esc(intro)}</p></header>{body}</main></body></html>'''

def mutual(source):
    s=read(source/'summary.json') or {}; rows=[]; cfg=s.get('configuration') or {}
    descriptions={
      'x509_server_x509_client':'Classical X.509 server and classical X.509 client authenticate each other.',
      'pq_x509_server_pq_x509_client':'Post-quantum X.509 server and post-quantum X.509 client authenticate each other.',
      'mtc_server_x509_client':'The server uses MTC while the client uses a trusted X.509 credential.',
      'x509_server_mtc_client':'The server uses X.509 while the client uses a trusted MTC credential.',
      'mtc_server_mtc_client':'Both server and client use trusted MTC credentials.',
      'missing_client_credential':'The client presents no credential although mutual authentication is required.',
      'wrong_x509_client_ca':'The client presents an X.509 credential issued by an untrusted CA.',
      'untrusted_mtc_client_domain':'The client presents an MTC credential from a trust domain not accepted by the server.',
    }
    for kind,key in [('Expected success','positive_cases'),('Expected rejection','negative_cases')]:
        for case in s.get(key,[]):
            code=case.get('client_returncode'); expected='Handshake completes' if key=='positive_cases' else 'Handshake is rejected'; observed='Handshake completed' if code==0 else 'Handshake rejected'
            duration=case.get('elapsed_seconds'); duration_text='Not recorded' if duration is None else f'{duration:.3f} s'
            rows.append((kind,case.get('name'),descriptions.get(case.get('name'),'Mutual-authentication case.'),expected,observed,duration_text,code,case.get('result')))
    result=status(s); expected=s.get('case_count',8); passed=s.get('passed',0)
    config_rows=[('General protocol profile',cfg.get('general_protocol_profile','not recorded')),('General protocol leaf',cfg.get('general_protocol_leaf','not recorded')),('MTC mutual-authentication profile',cfg.get('mutual_auth_mtc_profile','ecdsa-p256')),('MTC mutual-authentication leaf',cfg.get('mutual_auth_mtc_leaf',0)),('Merkle tree size',cfg.get('tree_size',16)),('Classical X.509 profile',cfg.get('classical_x509_profile','ECDSA P-256')),('Post-quantum X.509 profile',cfg.get('post_quantum_x509_profile','ML-DSA-65')),('MTC server certificate',cfg.get('mtc_server_certificate','batch16/mtc/ecdsa-p256/landmark-0000.pem')),('MTC server key',cfg.get('mtc_server_key','population/ecdsa-p256/0.key')),('MTC client certificate',cfg.get('mtc_client_certificate','mtc-client-n16/ecdsa-p256/landmark-0000.pem')),('MTC client key',cfg.get('mtc_client_key','mtc-client-source/client-0000.key'))]
    sections=[('What was executed','<p>TLS 1.3 connections with server and client authentication were checked using classical X.509, post-quantum X.509, and MTC. The campaign also submitted missing or untrusted client credentials to confirm that the server rejects them. This is an eight-case mixed credential matrix; its MTC cases currently use the specific ECDSA P-256 identity at leaf 0 shown below.</p>'),('Configured identities and credentials',table(('Field','Value'),config_rows)),('Expected outcome',f'<p>Positive cases had to complete the handshake. Negative cases had to be rejected. A negative case reports PASS when the unsafe connection was correctly rejected. Observed result: <strong>{passed} of {expected}</strong> cases behaved as expected.</p>'),('Result by case',table(('Case type','Case identifier','What this case checks','Expected behavior','Observed behavior','Case duration','Client exit code','Validation result'),rows)),('How to interpret the exit code','<p>Client exit code <strong>0</strong> means the TLS connection completed. A nonzero code means it was rejected or failed. For the three negative cases, exit code 1 is therefore the expected observation and produces a validation result of PASS.</p>'),('How to interpret timing','<p class="note">Case duration is monotonic wall-clock time for the complete functional case, including container cleanup, server startup wait, client execution, log collection and final cleanup. It is useful for identifying a slow test, but it is not TLS handshake performance. Handshake comparisons require the performance campaign with warmups, repetitions and statistical analysis.</p>'),('Execution',table(('Field','Value'),[(k,v) for k,v in (s.get('execution') or {}).items() if k!='host']+host_rows((s.get('execution') or {}).get('host'))))]
    return shell('TLS mutual authentication',result,'Checks that both peers present and verify the expected credential.',sections)

def retry(source):
    design=read(source/'design.json') or {}; summary=read(source/'summary.json') or {}; state=read(source/'status.json') or {}; result='PASS' if status(state)=='PASS' and summary else 'NO PASS'
    mode=design.get('mode','unknown'); measured=design.get('measured_rounds_per_scenario')
    rows=[(name,cfg.get('initial_id'),cfg.get('expected_attempts'),cfg.get('expected_retries')) for name,cfg in design.get('scenarios',{}).items()]; metrics=[]; observations=[]
    for name,data in (summary.get('scenarios') or {}).items():
        for metric,value in (data.get('metrics') or {}).items():
            if isinstance(value,dict):
                ci='—' if value.get('mean_95_ci_low') is None else f"[{value['mean_95_ci_low']:.3f}, {value['mean_95_ci_high']:.3f}]"
                fmt=lambda x:'—' if x is None else f'{x:.3f}'
                unit='bytes' if 'bytes' in metric else 'ms'
                metrics.append((name,metric,value.get('n'),fmt(value.get('mean')),fmt(value.get('sample_stdev')),fmt(value.get('median')),ci,unit))
                observations.append((name,metric,fmt(value.get('mean')),unit))
    if mode=='preflight':
        timing=table(('Scenario','Metric','Observed time','Unit'),observations) if observations else '<p>No complete timing observation is available because execution did not finish successfully.</p>'
        timing_note='<p class="note">Preflight mode records one measured observation per scenario. It reports that observation only and does not calculate a mean, standard deviation, median or confidence interval. Time is diagnostic and cannot support a performance conclusion. Byte counters come from the client TLS BIO; retry totals include both connections and exclude Ethernet, IP and TCP headers.</p>'
    else:
        timing=table(('Scenario','Metric','n','Mean','Sample SD','Median','95% CI of mean','Unit'),metrics) if metrics else '<p>No complete timing summary is available because execution did not finish successfully.</p>'
        timing_note=f'<p class="note">Full mode contains {esc(measured)} measured rounds per scenario. Every row reports the happy or retry result directly, without subtracting a baseline. The 95% interval estimates uncertainty around the mean. Byte counters come from the client TLS BIO; retry totals include both connections and exclude Ethernet, IP and TCP headers. Review raw observations and system load before drawing conclusions.</p>'
    kem=design.get('key_establishment') or {}
    recorded_host=(summary.get('execution') or {}).get('host') or collect_host_info()
    sections=[('What was executed',f'<p>Profile: <strong>{esc(design.get("profile","not recorded"))}</strong>, leaf: <strong>{esc(design.get("leaf","not recorded"))}</strong>, mode: <strong>{esc(mode)}</strong>. Key establishment: <strong>{esc(kem.get("label","X25519"))}</strong> using OpenSSL group <code>{esc(kem.get("openssl_group","X25519"))}</code>. These values are taken automatically from the active configuration. Two transactions were tested: <strong>happy</strong>, which must authenticate over one connection, and <strong>retry</strong>, whose first connection must fail because of an incompatible Trust Anchor ID and whose second, fresh connection must authenticate with the selected ID.</p>'),('Expected outcome',table(('Scenario','Initial ID','Attempts','Retries'),rows)),('Observed result',f'<p>Final status: <strong>{result}</strong>. PASS requires happy to use one connection, retry to use exactly two distinct connections, the first failure to be <code>trust_anchor_mismatch</code>, the second attempt to authenticate, and no session resumption.</p>'),('Observed timing',timing),('Timing interpretation',timing_note),('Configured identity and inputs',table(('Field','Value'),[('kem_label',kem.get('label','X25519')),('openssl_group',kem.get('openssl_group','X25519'))]+[(k,design.get(k)) for k in ('profile','leaf','mode','peer','trust','cert','key','hostname')])),('Time and computer',table(('Field','Value'),host_rows(recorded_host)))]
    return shell('MTC Trust Anchor Retry performance' if mode=='full' else 'MTC Trust Anchor Retry preflight',result,'Measures a bounded external retry over a fresh TLS connection.',sections)

STAGES=(('05','Draft core vectors C.1, C.2 and C.4'),('10','Existing MTC object'),('20','Offline landmark validation'),('30','Offline standalone validation'),('40–70','Landmark capture, extraction, transcript, and report'),('80–110','Standalone capture, extraction, transcript, and report'),('120','Invalid inputs and negative checks'))

def draft_vector_details(source):
    data=read(source/'05.draft-core-vectors.json') or {}
    checks=data.get('checks') or []
    rows=[('Draft',data.get('draft','MISSING')),('Scope',data.get('scope','MISSING')),('Result',data.get('overall','MISSING')),('Inclusion evaluations',data.get('inclusion_evaluations','—')),('Source',data.get('source','—'))]
    check_rows=[('C.1 and C.2','Tree hashes and inclusion proofs',checks[0] if len(checks)>0 else 'MISSING'),('C.4','Covering-subtree selection',checks[1] if len(checks)>1 else 'MISSING')]
    return '<p><strong>C.1</strong> checks reference Merkle tree hashes. <strong>C.2</strong> checks that inclusion proofs reconstruct the expected root. <strong>C.4</strong> checks the covering subtrees used to represent authenticated ranges. These are core algorithm vectors, not a complete protocol-conformance claim.</p>'+table(('Field','Observed value'),rows)+table(('Draft vectors','What they validate','Observed result'),check_rows)

def offline_details(source, filename, stage, explanation):
    data=read(source/filename) or {}
    if not data:return '<p>No stage evidence is available.</p>'
    subtree=data.get('subtree')
    observed=[('Result',data.get('overall')),('Draft',data.get('draft')),('Claim',data.get('claim')),('Scope',data.get('scope')),('Profile',data.get('profile')),('Mode',data.get('mode')),('Complete DER parse',data.get('parse_complete')),('Trailing bytes',data.get('trailing_bytes')),('Canonical length fields',data.get('length_fields_valid')),('Tree size',data.get('tree_size')),('Leaf index',data.get('leaf_index')),('Log number',data.get('log_number')),('Authenticated subtree',f'[{subtree[0]}, {subtree[1]})' if isinstance(subtree,list) and len(subtree)==2 else subtree),('Proof hashes',f"{data.get('proof_hash_count')} observed / {data.get('expected_proof_hash_count')} expected"),('Merkle proof valid',data.get('merkle_proof_valid')),('Required signatures valid',data.get('signature_valid')),('SPKI encodings valid',data.get('spki_valid')),('Computed root',data.get('computed_root')),('Expected root',data.get('expected_root','not independently supplied')),('Root matches',data.get('root_match','not independently compared')),('Landmark ID',data.get('landmark_id','not applicable')),('MTC object SHA-256',data.get('mtc_wire_sha256')),('Trust configuration SHA-256',data.get('trust_sha256'))]
    checks=(data.get('draft_checks') or {}).get('checks') or []
    later_mode=data.get('mode'); later=read(source/later_mode/'protocol-report.json') if later_mode in ('landmark','standalone') else None
    later_layers=(later or {}).get('validation_layers') or {}
    later_mapping=later_layers.get('trust_anchors_semantic_mapping') or {}
    later_transport=later_layers.get('transport_structure_validation') or {}
    later_stages='50–70' if later_mode=='landmark' else '90–110'
    check_rows=[]
    ordered_checks=sorted(enumerate(checks),key=lambda pair:(draft_section_key(pair[1].get('section')),pair[0]))
    for _,item in ordered_checks:
        observed_status=item.get('status'); final_evidence='—'
        if item.get('rule')=='trust_anchors mapping requires captured transport evidence':
            if later_mapping:
                observed_status='NOT EVALUATED HERE — this is an offline object stage'
                final_evidence=f"VALIDATED in stages {later_stages}: {later_mapping.get('status','UNKNOWN')}"
            else:
                observed_status='DEFERRED — requires captured TLS transport'
                final_evidence=f'PENDING — stages {later_stages}'
        elif item.get('rule')=='TLS transport (offline object only)':
            if later_transport:
                observed_status='NOT EVALUATED HERE — this is an offline object stage'
                final_evidence=f"VALIDATED in stages {later_stages}: {later_transport.get('status','UNKNOWN')}"
            else:
                observed_status='NOT APPLICABLE TO OFFLINE OBJECT VALIDATION'
                final_evidence=f'PENDING — stages {later_stages}'
        elif item.get('rule')=='actual signing time and largest observed tree are signer assertions':
            final_evidence='DOCUMENTED LIMITATION — the signature authenticates the checkpoint assertion, but this laboratory has no independent cosigner/log observation proving the real signing time or that this was the largest tree observed.'
        elif item.get('rule')=='native checkpoint nonfuture policy, no maximum age':
            policy=data.get('timestamp_local_policy') or {}
            final_evidence=f"LOCAL POLICY — {policy.get('rule','checkpoint must not be in the future; no maximum-age rule')}"
        check_rows.append((item.get('section'),item.get('rule'),observed_status,final_evidence))
    counts=data.get('draft_checks') or {}
    count_rows=[('Implemented rules passed',counts.get('passed','—')),('Failed',counts.get('failed','—')),('Not implemented',counts.get('not_implemented','—')),('Unresolved',counts.get('unresolved','—'))]
    limits=''.join(f'<li>{esc(value)}</li>' for value in data.get('limits') or []) or '<li>None recorded</li>'
    return f'<p>{esc(explanation)}</p><h3>Observed object and proof</h3>'+table(('Element','Observed value'),observed)+'<h3>Draft-rule checks</h3>'+table(('Draft section','Requirement checked','Offline-stage status','Final campaign evidence'),check_rows,'draft-checks')+'<h3>Check counts</h3>'+table(('Category','Count'),count_rows)+f'<h3>Recorded limits</h3><ul>{limits}</ul>'

def transport_mapping_details(source):
    rows=[]
    for mode,stages in (('landmark','50, 55 and 70'),('standalone','90, 95 and 110')):
        report=read(source/mode/'protocol-report.json') or {}
        layers=report.get('validation_layers') or {}
        mapping=layers.get('trust_anchors_semantic_mapping') or {}
        if not mapping:
            rows.append((mode,stages,'PENDING','—','—','—','Captured transport evidence is not available yet.'))
            continue
        rows.append((mode,stages,mapping.get('status','UNKNOWN'),mapping.get('extension_codepoint','—'),mapping.get('wire_structure_match','—'),mapping.get('message_semantics_match','—'),mapping.get('reason','—')))
    details=[]
    for mode in ('landmark','standalone'):
        report=read(source/mode/'protocol-report.json') or {}; mapping=((report.get('validation_layers') or {}).get('trust_anchors_semantic_mapping') or {})
        if mapping:
            details.extend([(mode,'Requested IDs',', '.join(map(str,mapping.get('requested_ids') or [])) or '—'),(mode,'Available IDs',', '.join(map(str,mapping.get('available_ids') or [])) or '—'),(mode,'Scope',mapping.get('scope','—'))])
    intro='<p>The offline object stages cannot observe TLS extensions. Stages 50/90 extract the captured extension, stages 55/95 verify it independently, and stages 70/110 consolidate the final result shown here. <strong>PASS_EXPERIMENTAL_CODEPOINT</strong> means that the captured structure and message semantics passed for the implemented profile, with the codepoint recorded in each evidence: historical private <code>0xffa7</code> or current provisional <code>0xca34</code>. Neither label implies a final IANA assignment.</p>'
    result=intro+table(('Mode','Evidence stages','Final mapping status','Codepoint','Wire structure match','Message semantics match','Explanation'),rows)
    if details:result+='<h3>Observed identifiers and scope</h3>'+table(('Mode','Element','Observed value'),details)
    return result

def protocol(source):
    paths=[source/'05.draft-core-vectors.json',source/'10.offline-existing.json',source/'20.offline-landmark.json',source/'30.offline-standalone.json',source/'landmark/protocol-report.json',source/'standalone/protocol-report.json',source/'invalid-input-stress/stress-checks-summary.json']
    checks=[(number,label,status(read(path)),str(path.relative_to(source))) for (number,label),path in zip(STAGES,paths)]; result='PASS' if all(row[2]=='PASS' for row in checks) else 'NO PASS'; execution=read(source/'execution.json') or {}; config=execution.get('configuration') or {}
    config_rows=[('Cryptographic profile',config.get('profile','not recorded')),('Selected leaf',config.get('leaf','not recorded')),('Merkle tree size (N)',config.get('tree_size','not recorded')),('MTC modes',', '.join(config.get('modes') or []) or 'not recorded'),('Fixture directory',config.get('fixture_directory','not recorded')),('Server key',config.get('server_key','not recorded'))]
    execution_rows=[(k,v) for k,v in execution.items() if k not in ('host','configuration')]+host_rows(execution.get('host'))
    raw_profile=config.get('profile','not recorded'); profile_names={'mldsa44':'ML-DSA-44','mldsa65':'ML-DSA-65','mldsa87':'ML-DSA-87','slhdsa128s':'SLH-DSA-128s','slhdsa192s':'SLH-DSA-192s','slhdsa256s':'SLH-DSA-256s','ecdsa-p256':'ECDSA P-256','ecdsa-p384':'ECDSA P-384','ecdsa-p521':'ECDSA P-521'}
    profile=esc(f"{profile_names.get(raw_profile, raw_profile)} ({raw_profile})" if raw_profile in profile_names else raw_profile); leaf=esc(config.get('leaf','not recorded')); tree_size=esc(config.get('tree_size','not recorded'))
    case_explanation=f'<p>This execution checks one specific cryptographic identity: profile <strong>{profile}</strong>, leaf <strong>{leaf}</strong> in a Merkle tree with <strong>N={tree_size}</strong> leaves. For this leaf, the campaign validates the existing MTC objects, exercises both landmark and standalone encodings over TLS, captures the two handshakes, independently verifies their transcripts and on-wire objects, and finally runs malformed-input and negative checks for the configured profile.</p>'
    sections=[('What was executed',case_explanation),('Stage 05 — draft core vectors',draft_vector_details(source)),('Stage 10 — existing standalone object',offline_details(source,'10.offline-existing.json','10','Validates the pre-existing standalone object against the authority configuration. It checks that the DER object, issuer, serial and proof can be parsed and authenticated before newly generated landmark and standalone evidence is considered.')),('Stage 20 — landmark object',offline_details(source,'20.offline-landmark.json','20','Validates the landmark representation. The proof carries no wire cosignatures; authentication is anchored in the configured signed checkpoint and covering subtree. The computed Merkle root must match that trusted subtree.')),('Stage 30 — standalone object',offline_details(source,'30.offline-standalone.json','30','Validates the standalone representation. The object carries the required subtree signatures, reconstructs the log entry bound to the leaf SPKI, verifies the inclusion proof and checks the computed root against the configured trust information.')),('Deferred Section 8 check — trust_anchors transport mapping',transport_mapping_details(source)),('Cryptographic case under test',table(('Field','Value'),config_rows)),('All stages and results',table(('Stage','What it checks','Result','Evidence'),checks)),('Final criterion',f'<p><strong>{result}</strong>: every required validation layer must report PASS. NOT_IMPLEMENTED, UNRESOLVED, LOCAL_POLICY and NOT_APPLICABLE entries remain visible above so that PASS is not mistaken for complete IETF conformance. A capture or output file does not count as successful validation by itself.</p>'),('Time and computer',table(('Field','Value'),execution_rows)),('Is the timing conclusive?','<p class="note">Not as a performance comparison. This duration includes Docker, capture, analysis, and evidence writing; it is useful for planning the test battery and recording where it ran.</p>')]
    return shell('MTC protocol validation — configured identity',result,'Explains the execution started by menu option 7.',sections)

def matrix(source):
    s=read(source/'matrix-summary.json') or {}; result=status(s); cfg=s.get('configuration',{}); res=s.get('results',{}); exe=s.get('execution',{})
    draft=res.get('draft_core_vectors') or {}; rows=[('Draft core vectors',draft.get('overall','MISSING')),('Draft inclusion evaluations',draft.get('inclusion_evaluations','—')),('Profiles',cfg.get('profile_count')),('Leaves per profile',cfg.get('leaf_count')),('Expected identities',cfg.get('expected_identities')),('PASS identities',(res.get('identities') or {}).get('pass')),('Expected handshakes',cfg.get('expected_handshakes')),('Non-empty captures',(res.get('captures') or {}).get('nonempty'))]
    sections=[('What was executed','<p>Menu option 8 first evaluates the pinned draft core vectors once, then repeats the complete option 7 validation for nine cryptographic profiles and all 16 leaves in each N=16 population. It checks landmark and standalone modes, giving two handshakes per identity.</p>'),('Draft evaluation scope','<p>Core-vector PASS covers C.1, C.2 and C.4 of <code>draft-ietf-plants-merkle-tree-certs-05</code>. The remaining stages provide object and TLS evidence for the implemented profile; the combined report does not claim full IETF conformance.</p>'),('Coverage',table(('Item','Value'),rows)),('Final result',f'<p><strong>{result}</strong>. PASS requires the draft core vectors and every identity, capture, independent verification, CertificateVerify, and Finished check to satisfy their validation gates.</p>'),('Time and computer',table(('Field','Value'),[(k,v) for k,v in exe.items() if k!='host']+host_rows(exe.get('host')))),('Timing interpretation','<p class="note">Total time helps estimate how long this battery takes on this computer. It does not establish performance differences between algorithms because it includes Docker, capture, analysis, and evidence writing.</p>')]
    return shell('Complete MTC validation matrix',result,'Explains the execution started by menu option 8.',sections)

def main():
    p=argparse.ArgumentParser();p.add_argument('kind',choices=('mutual','retry','protocol','matrix'));p.add_argument('source',type=Path);p.add_argument('--output',type=Path,required=True);p.add_argument('--replace',action='store_true',help='atomically replace an earlier derived report when resuming the same campaign');a=p.parse_args(); source=a.source.resolve(); output=a.output.resolve()
    if not source.is_dir():p.error('source directory does not exist')
    if output.exists() and not a.replace:p.error('output exists')
    content={'mutual':mutual,'retry':retry,'protocol':protocol,'matrix':matrix}[a.kind](source); output.parent.mkdir(parents=True,exist_ok=True)
    temporary=output.with_name(output.name+'.tmp'); temporary.write_text(content); temporary.replace(output); print(output)
if __name__=='__main__':main()
