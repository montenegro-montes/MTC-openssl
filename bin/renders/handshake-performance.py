#!/usr/bin/env python3
"""Render an explained English report for handshake-performance results."""
import argparse
import datetime as dt
import html
import json
from pathlib import Path
from host_info import collect_host_info, host_rows


def esc(value): return html.escape(str(value))


def table(headers, rows):
    head = ''.join(f'<th>{esc(value)}</th>' for value in headers)
    body = ''.join('<tr>' + ''.join(f'<td>{esc(value)}</td>' for value in row) + '</tr>' for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


METRICS = {
    'native': (
        ('tcp_connect_wall_ms_native', 'TCP connect', 'ms'),
        ('handshake_wall_ms', 'TLS handshake', 'ms'),
        ('connection_establishment_wall_ms_native', 'Complete connection', 'ms'),
        ('process_wall_ms', 'Client process', 'ms'),
        ('tls_bytes_total', 'TLS handshake size', 'bytes'),
    ),
    'pcap': (
        ('tcp_handshake_ms', 'TCP three-way handshake', 'ms'),
        ('tcp_syn_to_clienthello_ms', 'Time to TLS ClientHello', 'ms'),
        ('tls_clienthello_to_client_finished_ms', 'ClientHello to client Finished', 'ms'),
        ('tcp_syn_to_first_application_request_ms', 'Time to first HTTP request', 'ms'),
        ('tls_client_handshake_bytes', 'Client logical TLS handshake size', 'bytes'),
        ('tls_server_handshake_bytes', 'Server logical TLS handshake size', 'bytes'),
        ('tls_handshake_bytes', 'Total logical TLS handshake size', 'bytes'),
        ('tls_client_handshake_wire_bytes', 'Client handshake wire size', 'bytes'),
        ('tls_server_handshake_wire_bytes', 'Server handshake wire size', 'bytes'),
        ('tls_handshake_wire_bytes', 'Total handshake wire size', 'bytes'),
        ('tls_client_handshake_packets', 'Client handshake packets', 'packets'),
        ('tls_server_handshake_packets', 'Server handshake packets', 'packets'),
        ('tls_handshake_packets', 'Total handshake packets', 'packets'),
        ('tls_client_certificate_bytes', 'Client Certificate message', 'bytes'),
        ('tls_server_certificate_bytes', 'Server Certificate message', 'bytes'),
        ('tls_client_certificate_verify_bytes', 'Client CertificateVerify message', 'bytes'),
        ('tls_server_certificate_verify_bytes', 'Server CertificateVerify message', 'bytes'),
        ('tls_client_certificate_verify_signature_bytes', 'Client CertificateVerify signature', 'bytes'),
        ('tls_server_certificate_verify_signature_bytes', 'Server CertificateVerify signature', 'bytes'),
        ('tls_client_mtc_proof_bytes', 'Client MTCProof', 'bytes'),
        ('tls_server_mtc_proof_bytes', 'Server MTCProof', 'bytes'),
        ('tls_client_mtc_merkle_path_bytes', 'Client MTC Merkle path', 'bytes'),
        ('tls_server_mtc_merkle_path_bytes', 'Server MTC Merkle path', 'bytes'),
        ('tls_client_mtc_merkle_path_hashes', 'Client MTC Merkle path', 'hashes'),
        ('tls_server_mtc_merkle_path_hashes', 'Server MTC Merkle path', 'hashes'),
        ('tls_client_sct_bytes', 'Client SCT list', 'bytes'),
        ('tls_server_sct_bytes', 'Server SCT list', 'bytes'),
        ('tls_client_authentication_bytes', 'Client authentication messages', 'bytes'),
        ('tls_server_authentication_bytes', 'Server authentication messages', 'bytes'),
        ('tls_authentication_bytes', 'Total authentication messages', 'bytes'),
        ('tcp_retransmission_packets', 'TCP retransmission packets', 'packets'),
    ),
}


def number(value):
    return '—' if value is None else f'{value:.3f}'


def metric_table(section, metric, label, unit, default_key_establishment):
    rows=[]
    for profile, cases in section.items():
        for case, values in cases.items():
            stats=values.get(metric)
            # Read older summaries containing only <metric>_median.
            if stats is None and metric+'_median' in values:
                stats={'n':'—','mean':None,'sample_stdev':None,'median':values[metric+'_median'],'mean_95_ci_low':None,'mean_95_ci_high':None}
            if stats:
                key_establishment=values.get('key_establishment',default_key_establishment)
                ci='—' if stats.get('mean_95_ci_low') is None else f"[{stats['mean_95_ci_low']:.3f}, {stats['mean_95_ci_high']:.3f}]"
                rows.append((profile,case,key_establishment.get('label','—'),key_establishment.get('openssl_group','—'),stats.get('n','—'),number(stats.get('mean')),number(stats.get('sample_stdev')),number(stats.get('median')),ci,unit))
    return f'<h3>{esc(label)}</h3>'+table(('Profile','Case','Key establishment','OpenSSL group','n','Mean','Sample SD','Median','95% CI of mean','Unit'),rows)


def source_tables(summary, source):
    section=summary.get(source,{})
    if not section: return f'<p>{esc(source.upper())} measurements were not requested in this execution.</p>'
    return ''.join(metric_table(section,*spec,summary.get('key_establishment',{})) for spec in METRICS[source])


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('summary',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--mode',choices=('run-native','run-native-single','run-native-mutual','run-pcap','run-pcap-single','run-pcap-mutual','run-native-pcap','run-single','run-mutual'),required=True)
    parser.add_argument('--started-epoch',type=int,required=True)
    parser.add_argument('--ended-epoch',type=int,required=True)
    parser.add_argument('--kem-id',required=True)
    parser.add_argument('--kem-label',required=True)
    parser.add_argument('--kem-group',required=True)
    args=parser.parse_args()
    summary=json.loads(args.summary.read_text())
    if args.mode.endswith('-single') or args.mode == 'run-single':
        cases='X.509 simple and MTC simple landmark and standalone'
    elif args.mode.endswith('-mutual') or args.mode == 'run-mutual':
        cases='X.509 mutual authentication and MTC mutual landmark and standalone'
    else:
        cases='X.509 simple, MTC simple landmark and standalone, X.509 mutual authentication, and MTC mutual landmark and standalone'
    start=dt.datetime.fromtimestamp(args.started_epoch,dt.timezone.utc).isoformat(); end=dt.datetime.fromtimestamp(args.ended_epoch,dt.timezone.utc).isoformat()
    sections=[
      ('What was executed',f'<p><strong>{esc(args.mode)}</strong> measured {cases}. Key establishment was <strong>{esc(args.kem_label)}</strong> using OpenSSL group <code>{esc(args.kem_group)}</code>. In every mutual-authentication row, client and server use the same signature profile shown in the Profile column. Native measurements use repeated client executions; PCAP measurements use independent packet captures from ClientHello through the last decrypted Finished.</p>'),
      ('Native TCP, TLS, complete connection, process, and size measurements',source_tables(summary,'native')),
      ('Packet-capture TCP, TLS, connection, and size measurements',source_tables(summary,'pcap')),
      ('How to read the statistics','<p>The mean is the arithmetic average. Sample SD describes observation-to-observation dispersion. The median is resistant to isolated long executions. The 95% confidence interval estimates uncertainty around the mean using a two-sided Student t interval; it is not a range containing 95% of individual handshakes.</p>'),
      ('Interpretation limits','<p class="note">Every row reports one profile and authentication case directly, without subtracting a baseline. Native and PCAP measurements use different boundaries and repetition counts and must be interpreted separately. Review raw CSV observations, system load, sample size and capture quality before drawing conclusions. A confidence interval describes sampling uncertainty; it does not establish protocol causality or equivalence.</p>'),
      ('Execution',table(('Field','Value'),[('KEM selection',args.kem_label),('OpenSSL TLS group',args.kem_group),('KEM configuration ID',args.kem_id),('Start UTC',start),('End UTC',end),('Elapsed seconds',max(0,args.ended_epoch-args.started_epoch)),('Summary source',args.summary)]+host_rows(collect_host_info()))),
    ]
    body=''.join(f'<section><h2>{esc(title)}</h2>{content}</section>' for title,content in sections)
    page=f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>TLS handshake performance</title><style>body{{font:16px system-ui;background:#f3f6fa;color:#172033;margin:0}}main{{max-width:1250px;margin:auto;padding:28px}}header,section{{background:#fff;border:1px solid #dbe3ed;border-radius:12px;padding:22px;margin:16px 0}}h1{{margin:.2em 0}}h2{{font-size:20px}}h3{{margin-top:28px}}.note{{background:#eef5ff;padding:14px;border-left:5px solid #3974c6}}table{{border-collapse:collapse;width:100%}}th,td{{padding:9px;border-bottom:1px solid #ddd;text-align:left;white-space:nowrap}}th{{background:#edf2f7}}.scroll{{overflow:auto}}</style></head><body><main><header><p>Explained performance report</p><h1>X.509 and MTC TLS handshake performance</h1><p>Absolute timing and size results for simple and mutual authentication.</p></header>{body}</main></body></html>'''
    args.output.parent.mkdir(parents=True,exist_ok=True)
    temporary=args.output.with_name(args.output.name+'.tmp'); temporary.write_text(page); temporary.replace(args.output)


if __name__=='__main__': main()
