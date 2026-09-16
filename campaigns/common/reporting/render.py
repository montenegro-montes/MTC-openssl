"""Self-contained HTML presentation; no JavaScript, network, or inference engine."""
import base64
import html
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from .adapters import VERSION, SUMMARY_NAMES, RAW_NAMES, leaves

NOTICE='This HTML report is a derived presentation artifact. JSON/JSONL/CSV experiment outputs remain the canonical scientific records.'
NATIVE=['tcp_connect_wall_ms_native','handshake_wall_ms','connection_establishment_wall_ms_native']
PCAP=['tcp_connect_wall_ms','tls_from_pcap_wall_ms','connection_handshake_wall_ms']
WIRE=['connection_handshake_packets','connection_handshake_tcp_payload_bytes','connection_handshake_ip_bytes','connection_handshake_frame_bytes','connection_handshake_retransmission_frames']
BIO=['transport_read_bytes','transport_written_bytes','transport_total_bytes','tls_bio_read_bytes','tls_bio_written_bytes']

def esc(value): return html.escape(str(value),quote=True)
def number(value):
    if value is None or value=='' or isinstance(value,bool): return None
    try:
        result=float(value)
        return result if math.isfinite(result) else None
    except (ValueError,TypeError): return None

def fmt(value, key=''):
    if value is None or value=='': return 'unavailable'
    if isinstance(value,bool): return 'true' if value else 'false'
    if ('ms' in key or 'wall' in key) and number(value) is not None:
        return f'{number(value):.6f}'
    return str(value)

def table(rows, columns=None, limit=100):
    if not rows: return '<p class="muted">Not recorded.</p>'
    columns=columns or list(dict.fromkeys(k for r in rows for k in r))
    output='<div class="scroll"><table><thead><tr>'+''.join('<th>'+esc(k)+'</th>' for k in columns)+'</tr></thead><tbody>'
    output+=''.join('<tr>'+''.join('<td>'+esc(fmt(r.get(k),k))+'</td>' for k in columns)+'</tr>' for r in rows[:limit])+'</tbody></table></div>'
    if len(rows)>limit: output+=f'<p class="muted">Showing {limit} of {len(rows)} source rows; full data remains in the canonical artifact.</p>'
    return output

def details(label,value):
    return '<details><summary>'+esc(label)+'</summary><pre>'+esc(json.dumps(value,indent=2,ensure_ascii=False))+'</pre></details>'

def panel(title,body): return '<section><h2>'+esc(title)+'</h2>'+body+'</section>'

def timing(model, keys, title, boundaries):
    rows=[{'source':name,'scenario':r.get('scenario'),'side':r.get('side'),
           **{k:r.get(k) for k in ('tls_status','capture_status','analysis_status','pcap_analysis_status') if k in r},
           **{k:r.get(k) for k in keys}} for name,r in model['metrics'] if any(k in r for k in keys)]
    if not rows: return ''
    # Boundary diagram is conceptual, never a synthetic duration decomposition.
    diagram='<div class="timeline">'+''.join('<span>'+esc(text)+'</span>'+(' <b>→</b> ' if i<len(boundaries)-1 else '') for i,text in enumerate(boundaries))+'</div>'
    complete=[r for r in rows if all(number(r[k]) is not None for k in keys)
              and r.get('analysis_status')!='PARTIAL' and r.get('pcap_analysis_status')!='PARTIAL']
    incomplete=[r for r in rows if r not in complete]
    body=''
    if complete:
        body+='<h3>Recorded complete timing</h3>'+diagram+'<p>Intermediate application/packet gaps may exist. Full elapsed time is a directly measured interval, not a sum.</p>'+table(complete)
    if incomplete:
        body+='<h3>Incomplete / unavailable observations</h3><p>Incomplete or unavailable timing: no completed TLS timeline is asserted. Missing boundaries remain unavailable.</p>'+table(incomplete)
    return panel(title,body)

def crossover_report(model):
    """Present existing certificate-size crossover artifacts without recomputation."""
    analysis=model['documents'].get('analysis_extended.json',{})
    tables=model['tables']

    crossover=next(
        (rows for name,rows in tables.items()
         if Path(name).name=='crossover_extended.csv'),
        []
    )
    validation=next(
        (rows for name,rows in tables.items()
         if Path(name).name=='x509_reference_validation.csv'),
        []
    )
    serialization=next(
        (rows for name,rows in tables.items()
         if Path(name).name=='serialization_breakdown.csv'),
        []
    )
    size_model=next(
        (rows for name,rows in tables.items()
         if Path(name).name=='mtc_size_model.csv'),
        []
    )

    out=[]

    scope_fields=(
        'result_domain','draft','merkle_hash','boundary',
        'leaf_index','log_number','landmark_policy',
        'implementation_limit','maximum_supported_N',
        'draft_limit','draft_limit_definition',
        'draft_endpoint_limit','limiting_field','limiting_reason',
        'tls_campaign_executed','baseline_preserved'
    )
    scope=[
        {'field':key,'recorded value':analysis.get(key)}
        for key in scope_fields if key in analysis
    ]
    out.append(panel(
        'Certificate-size crossover scope',
        '<p>This section presents the existing exact landmark-MTC / X.509 '
        'Certificate-message size analysis. It does not recompute crossover '
        'thresholds, statistics, serialization sizes, or TLS measurements.</p>'
        +table(scope)
    ))

    if validation:
        out.append(panel(
            'Empirical X.509 reference validation',
            '<p>Rows are reproduced from x509_reference_validation.csv. '
            'Compatibility and selected reference sources are existing scientific '
            'results and are not inferred by this report.</p>'
            +table(validation,limit=len(validation))
        ))

    if serialization:
        out.append(panel(
            'MTC serialization anchors / breakdown',
            '<p>Existing serialized landmark-MTC evidence; no sizes are '
            'reconstructed by the HTML renderer.</p>'
            +table(serialization,limit=len(serialization))
        ))

    if crossover:
        depths={}
        for row in crossover:
            depth=row.get('x509_depth')
            depths.setdefault(str(depth),[]).append(row)

        body=(
            '<p>Exact crossover rows are reproduced from crossover_extended.csv. '
            'Depth D includes the trusted root. D=3 is the representative '
            'configuration in the existing analysis; D=2 and D=4–5 are retained '
            'as sensitivity cases.</p>'
        )
        for depth in ('2','3','4','5'):
            rows=depths.get(depth,[])
            if rows:
                label='D='+depth
                if depth=='3':
                    label+=' — representative'
                body+='<h3>'+esc(label)+'</h3>'+table(rows,limit=len(rows))
        remaining=[
            row for depth,rows in depths.items()
            if depth not in ('2','3','4','5')
            for row in rows
        ]
        if remaining:
            body+='<h3>Other recorded depths</h3>'+table(
                remaining,limit=len(remaining)
            )
        out.append(panel('Exact crossover results',body))

    if size_model:
        out.append(panel(
            'Existing MTC size-model output',
            '<p>Recorded model output only. The HTML renderer does not execute '
            'the serializer or evaluate the size model.</p>'
            +table(size_model,limit=min(len(size_model),200))
        ))

    limits=[]
    for key in (
        'implementation_limit','maximum_supported_N','draft_limit',
        'draft_endpoint_limit','limiting_field','limiting_reason'
    ):
        if key in analysis:
            limits.append({'field':key,'recorded value':analysis[key]})
    if limits:
        out.append(panel(
            'Implementation and analytical domain',
            '<p>Implementation support and analytical/model range are distinct. '
            'Values below are copied from analysis_extended.json.</p>'
            +table(limits)
        ))

    figures=[]
    for name in ('crossover-by-depth.png','crossover-curves.png'):
        path=model['source']/name
        if path.is_file():
            encoded=base64.b64encode(path.read_bytes()).decode('ascii')
            figures.append(
                '<figure><figcaption><strong>'+esc(name)+'</strong></figcaption>'
                '<img alt="'+esc(name)+'" '
                'style="max-width:100%;height:auto" '
                'src="data:image/png;base64,'+encoded+'"></figure>'
            )
    if figures:
        out.append(panel(
            'Existing crossover figures',
            '<p>Figures are embedded byte-for-byte from the existing PNG '
            'artifacts; they are not regenerated by this report.</p>'
            +''.join(figures)
        ))

    provenance=[]
    for key in (
        'existing_n16_validation','measured_anchor_count',
        'tls_campaign_executed','baseline_preserved'
    ):
        if key in analysis:
            provenance.append({'field':key,'recorded value':analysis[key]})
    if provenance:
        out.append(panel(
            'Crossover provenance',
            table(provenance)
            +details('Recorded source hashes',analysis.get('source_hashes',{}))
            +details('Recorded draft source hashes',
                     analysis.get('draft_source_hashes',{}))
            +details('Recorded fixture provenance',
                     analysis.get('fixture_provenance',{}))
            +details('Recorded limitations',analysis.get('limitations',[]))
        ))

    return ''.join(out)


def render(model):
    out=['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:; base-uri \'none\'; form-action \'none\'"><title>Experiment evidence report</title><style>body{font:15px system-ui,sans-serif;background:#f1f5f9;color:#172b4d;margin:0}main{max-width:1240px;margin:auto;padding:32px}header,section{background:white;border:1px solid #dbe3ed;border-radius:12px;padding:24px;margin:18px 0}h1{font-size:28px;margin:8px 0}h2{font-size:20px}p{line-height:1.6}.banner{background:#fff0cc;border-left:6px solid #bd6200;padding:18px;font-weight:700}.warning{background:#ffe6e6;color:#8d1515;padding:16px}.status{font-weight:700;color:#185b65}.muted{color:#53647c}.scroll{overflow:auto}table{border-collapse:collapse;min-width:100%;font-size:13px}th,td{padding:10px;border-bottom:1px solid #dde4ee;text-align:left;white-space:nowrap}th{background:#edf3f8}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}details{margin:12px 0}summary{cursor:pointer;font-weight:600}.timeline{display:flex;align-items:center;flex-wrap:wrap;gap:10px}.timeline span{padding:12px;background:#edf3f8;border-radius:8px}a{color:#175c99}</style></head><body><main>']
    out+=['<header><p class="muted">EVIDENCE PRESENTATION · '+esc(model['adapter'])+'</p><h1>'+esc(model['source'].name)+'</h1><p class="status">'+esc(model['status'])+'</p><p>'+NOTICE+'</p>']
    if model['smoke']: out+=['<div class="banner">INTEGRATION SMOKE — NOT SCIENTIFIC PERFORMANCE DATA</div>']
    out+=[table([model['flags']]),'<p>TLS keylog file present (contents never read): '+fmt(model['keylog_available'])+'.</p>','<p>PCAP-derived data present: '+fmt(model['pcap_present'])+'. Missing flags are not inferred.</p><p>Captured and uncaptured observations are separate measurement populations. This report never pools them or computes statistical inference.</p></header>']
    if model['warnings']: out += [panel('Warnings / integrity failures','<div class="warning">'+ '<br>'.join(esc(w) for w in model['warnings'])+'</div>')]
    if model['adapter']=='certificate-size-crossover':
        out += [crossover_report(model)]
    # Counts use one existing population file hierarchy only, avoiding aggregate/per-campaign duplicates.
    tables=model['tables']
    measured=[n for n in tables if Path(n).name=='all-samples.csv'] or [n for n in tables if Path(n).name in ('samples.csv','observations.csv')]
    warms=[n for n in tables if Path(n).name=='all-warmups.csv'] or [n for n in tables if Path(n).name=='warmups.csv']
    failures=[n for n in tables if n=='failures.csv'] or [n for n in tables if Path(n).name=='failures.csv']
    rows=[r for n in measured for r in tables[n]]
    if measured or warms or failures:
        counts={'recorded measured rows':sum(1 for r in rows if str(r.get('is_warmup','0'))=='0'),'recorded warmup rows':sum(len(tables[n]) for n in warms)+sum(1 for r in rows if str(r.get('is_warmup','0'))=='1'),'recorded failure rows':sum(len(tables[n]) for n in failures)+sum(1 for r in rows if str(r.get('success','')).lower() in ('0','false')),'successful measured rows (samples CSV contract)':sum(len(tables[n]) for n in measured if Path(n).name in ('samples.csv','all-samples.csv')) if any(Path(n).name in ('samples.csv','all-samples.csv') for n in measured) else None,'scenarios':', '.join(sorted({r['scenario'] for r in rows if r.get('scenario')})) or None,'seeds':', '.join(sorted({r['seed'] for r in rows if r.get('seed')})) or None,'campaign IDs':len({r.get('campaign_id',r.get('campaign')) for r in rows if r.get('campaign_id',r.get('campaign'))}) or None}
        out += [panel('Campaign / observation overview',table([counts])+'<p>Counts describe recorded rows only; failures and warmups retain their source classification.</p>')]
    outcomes=[{'source':name,'scenario':r.get('scenario'),**{k:r.get(k) for k in (
        'tls_status','capture_status','analysis_status','pcap_analysis_status',
        'tcp_established_observed','client_hello_observed','client_finished_observed',
        'capture_packet_count','capture_retransmission_frames','association_confidence')}}
        for name,r in model['metrics'] if any(k in r for k in ('tls_status','capture_status','analysis_status'))]
    if outcomes:
        out += [panel('Independent TLS / capture / analysis outcomes',
            '<p>A failed TLS attempt can have a valid capture and partial analysis. These are independent outcomes. Partial retransmission counts cover the entire selected captured TCP attempt; successful-handshake counts retain SYN → client Finished boundaries.</p>'+table(outcomes))]
    out += [timing(model,NATIVE,'Native timing',['Native connect start','Native connect complete','TLS handshake start','TLS handshake done'])]
    if any(any(k in r for k in NATIVE) for _,r in model['metrics']): out += [panel('Native boundaries','<p>Current OpenSSL s_client uses init_client: resolver work, address selection and socket connection may be included. TCP native timing ends at successful connection return. handshake_wall_ms remains SSL_CB_HANDSHAKE_START → SSL_CB_HANDSHAKE_DONE. Full native establishment starts at original connect entry and ends at that same handshake-done timestamp.</p>')]
    out += [timing(model,PCAP,'PCAP timing',['SYN','TCP established','ClientHello','Client Finished'])]
    comparisons=[]
    # Only compare values present in the same explicitly associated source record.
    for name,r in model['metrics']:
        for native,pcap in zip(NATIVE,PCAP):
            a,b=number(r.get(native)),number(r.get(pcap))
            if a is not None and b is not None: comparisons.append({'source':name,'native metric':native,'native ms':a,'PCAP metric':pcap,'PCAP ms':b,'native minus PCAP ms':a-b,'absolute difference ms':abs(a-b),'relative difference % (PCAP denominator)':abs(a-b)/abs(b)*100 if b else None})
    # Cross-artifact pairing requires the explicit TLS ClientHello random.
    natives=[(name,r) for name,r in model['metrics'] if r.get('client_random') and any(k in r for k in NATIVE)]
    pcaps=[(name,r) for name,r in model['metrics'] if r.get('client_random') and any(k in r for k in PCAP)]
    for name,r in natives:
        matches=[(other,p) for other,p in pcaps if p['client_random']==r['client_random']]
        if len(matches)!=1: continue
        other,p=matches[0]
        for native,pcap in zip(NATIVE,PCAP):
            a,b=number(r.get(native)),number(p.get(pcap))
            if a is not None and b is not None:
                comparisons.append({'source':name+' ↔ '+other,'association':'client_random','native metric':native,'native ms':a,'PCAP metric':pcap,'PCAP ms':b,'native minus PCAP ms':a-b,'absolute difference ms':abs(a-b),'relative difference % (PCAP denominator)':abs(a-b)/abs(b)*100 if b else None})
    if comparisons: out += [panel('Diagnostic cross-validation','<p>Equality is not expected because measurement boundaries differ. Differences are diagnostic arithmetic, not scientific performance conclusions.</p>'+table(comparisons))]
    wire=[{'source':name,**{k:r.get(k) for k in WIRE}} for name,r in model['metrics'] if any(k in r for k in WIRE)]
    if wire:
        warning=[]
        for row in wire:
            p,i,f=[number(row.get(k)) for k in WIRE[1:4]]
            if all(v is not None for v in (p,i,f)) and not(p<i<=f): warning.append('Byte hierarchy warning: '+row['source'])
        out += [panel('Observed network communication','<p>TCP payload → IP bytes → frame bytes. Representations include different headers; capture behavior can affect inequalities.</p>'+''.join('<p class="warning">'+esc(w)+'</p>' for w in warning)+table(wire))]
    bio=[{'source':name,**{k:r.get(k) for k in BIO}} for name,r in model['metrics'] if any(k in r for k in BIO)]
    if bio: out += [panel('OpenSSL / BIO bytes','<p>BIO counters exclude TCP/IP/frame headers and are distinct from observed wire payload and retransmissions.</p>'+table(bio))]
    fields=[{'source':name,'field':key,'recorded value':value} for name,data in model['documents'].items() for key,value in leaves(data)]
    for title,terms in [('TLS / scenario configuration',('tls','cipher','group','authentication','signature','scenario','resumption','tickets','hrr','tree_size','depth')),('Configured network condition',('target','configured','qdisc','bandwidth','jitter','network_profile','rtt_ms','rate_mbit','loss_percent')),('TCP namespace counter evidence',('tcpretrans','tcpout','tcpin','tcp_retrans','tcp_segments','nstat')),('Measured / validated network condition',('measured_rtt','rtt_measured','measured_loss','loss_measured','goodput','bandwidth_measured','bandwidth_forward','bandwidth_reverse','measured_bandwidth')),('Validation and integrity',('status','passed','hash','sha256','client_random','association','keylog','capture','readable')),('Reproducibility',('commit','dirty','version','image','seed','campaign_id','timestamp','platform','fixture'))]:
        selected=[r for r in fields if any(term in r['field'].lower() for term in terms)]
        if title=='Configured network condition':
            selected += [r for r in fields if r['field'].rsplit('.',1)[-1]=='profile' and r not in selected]
            selected=[r for r in selected if not any(term in r['field'].lower() for term in ('measured','goodput','bandwidth_forward','bandwidth_reverse'))]
        if selected: out += [panel(title,table(selected,limit=150))]
    if model['integrity']: out += [panel('Read-only PCAP hash cross-check',table(model['integrity']))]
    for name,rows in tables.items():
        if Path(name).name in SUMMARY_NAMES: out += [panel('Existing analysis: '+name,'<p>Existing source statistics, formatted without recomputation.</p>'+table(rows))]
    ordered=sorted(model['documents'].items(),key=lambda pair:('/' in pair[0], 'server-metrics/' in pair[0], pair[0]))
    raw=''.join(details(name,data) for name,data in ordered[:100])
    if len(ordered)>100: raw+='<p>First 100 JSON artifacts displayed; all source names and hashes remain in the inventory.</p>'
    raw+=''.join(details(name+' (first 20 source rows)',rows[:20]) for name,rows in list(tables.items())[:100] if Path(name).name not in SUMMARY_NAMES)
    out += [panel('Raw evidence / metadata',raw),panel('Source artifact inventory',table(model['inventory'],limit=len(model['inventory'])))]
    provenance={'report_generator_version':VERSION,'generated_utc':datetime.now(timezone.utc).isoformat(),'source_directory':str(model['source']),'source_artifact_count':len(model['inventory'])}
    out += [panel('Report provenance',details('Generation record',provenance)),'</main></body></html>']
    return ''.join(out)
