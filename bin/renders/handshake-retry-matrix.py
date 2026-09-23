#!/usr/bin/env python3
"""Aggregate nine Trust Anchor Retry profiles and render an English HTML report."""
import argparse
import html
import json
import platform
from pathlib import Path

PROFILES = ('ecdsa-p256', 'ecdsa-p384', 'ecdsa-p521', 'mldsa44', 'mldsa65',
            'mldsa87', 'slhdsa128s', 'slhdsa192s', 'slhdsa256s')
METRICS = (
    ('retry_total_tcp_connect_wall_ms_native', 'Total TCP connection time'),
    ('retry_total_tls_attempt_wall_ms', 'Total TLS attempt time'),
    ('retry_total_attempt_wall_ms_native', 'Complete transaction time'),
    ('retry_total_tls_bytes_read', 'TLS bytes received'),
    ('retry_total_tls_bytes_written', 'TLS bytes sent'),
    ('retry_total_tls_bytes', 'Total TLS bytes transferred'),
)

def esc(value): return html.escape(str(value))
def table(headers, rows):
    head = ''.join(f'<th>{esc(value)}</th>' for value in headers)
    body = ''.join('<tr>' + ''.join(f'<td>{esc(value)}</td>' for value in row) + '</tr>' for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'
def fmt(value): return '—' if value is None else f'{value:.3f}'
def statistic_row(profile, state, scenario, stats, unit):
    interval = '—' if stats.get('mean_95_ci_low') is None else f"[{stats['mean_95_ci_low']:.3f}, {stats['mean_95_ci_high']:.3f}]"
    return (profile, state, scenario, stats.get('n', '—'), fmt(stats.get('mean')),
            fmt(stats.get('sample_stdev')), fmt(stats.get('median')), interval, unit)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--started-epoch', type=int, required=True)
    parser.add_argument('--ended-epoch', type=int, required=True)
    parser.add_argument('--kem-id', required=True)
    parser.add_argument('--kem-label', required=True)
    parser.add_argument('--kem-group', required=True)
    args = parser.parse_args()
    profiles = {}; tables = {metric: [] for metric, _ in METRICS}; passed = True
    for profile in PROFILES:
        folder = args.root / profile
        try:
            summary = json.loads((folder / 'summary.json').read_text())
            state = json.loads((folder / 'status.json').read_text())
            ok = state.get('status') == 'PASS' and state.get('measured_transactions') == 60
            values = {scenario: summary['scenarios'][scenario]['metrics'] for scenario in ('happy', 'retry')}
        except (OSError, ValueError, KeyError, TypeError):
            ok, values = False, {}
        label = 'PASS' if ok else 'NO PASS'; passed = passed and ok
        profiles[profile] = {'status': label, 'scenarios': values}
        for metric, _ in METRICS:
            unit = 'bytes' if 'bytes' in metric else 'ms'
            if values:
                for scenario in ('happy', 'retry'):
                    tables[metric].append(statistic_row(profile, label, scenario, values[scenario][metric], unit))
            else:
                tables[metric].append((profile, label, 'missing', '—', '—', '—', '—', '—', unit))
    result = {'campaign': 'mtc-trust-anchor-retry-performance', 'status': 'PASS' if passed else 'NO PASS',
              'profile_count': len(PROFILES), 'expected_transactions': 630, 'profiles': profiles,
              'key_establishment': {'id': args.kem_id, 'label': args.kem_label, 'openssl_group': args.kem_group},
              'execution': {'started_epoch': args.started_epoch, 'ended_epoch': args.ended_epoch,
                            'elapsed_seconds': max(0, args.ended_epoch - args.started_epoch),
                            'host': {'system': platform.system(), 'release': platform.release(), 'machine': platform.machine()}}}
    (args.root / 'matrix-summary.json').write_text(json.dumps(result, indent=2) + '\n')
    content = ''.join(f'<h3>{esc(label)}</h3>' + table(
        ('Profile', 'Status', 'Scenario', 'n', 'Mean', 'Sample SD', 'Median', '95% CI of mean', 'Unit'), tables[metric])
        for metric, label in METRICS)
    color = 'pass' if passed else 'fail'
    page = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>MTC Trust Anchor Retry performance matrix</title><style>body{{font:16px system-ui;background:#f3f6fa;color:#172033;margin:0}}main{{max-width:1250px;margin:auto;padding:28px}}header,section{{background:#fff;border:1px solid #dbe3ed;border-radius:12px;padding:22px;margin:16px 0}}h3{{margin-top:28px}}.result{{font-size:26px;font-weight:800}}.pass{{color:#087443}}.fail{{color:#b42318}}.note{{background:#eef5ff;padding:14px;border-left:5px solid #3974c6}}table{{border-collapse:collapse;width:100%}}th,td{{padding:9px;border-bottom:1px solid #ddd;text-align:left;white-space:nowrap}}th{{background:#edf2f7}}.scroll{{overflow:auto}}</style></head><body><main><header><p>Explained performance report</p><h1>MTC Trust Anchor Retry — nine-profile matrix</h1><p class="result {color}">{result['status']}</p><p>Absolute results for direct authentication and bounded Trust Anchor Retry over a fresh TLS connection.</p></header><section><h2>What was executed</h2><p>Nine cryptographic profiles were measured with simple server authentication using <strong>{esc(args.kem_label)}</strong> key establishment (OpenSSL group <code>{esc(args.kem_group)}</code>). Each profile contains 5 warmup and 30 measured rounds for both happy and retry: 70 transactions per profile and 630 in total.</p></section><section><h2>Absolute results by profile and scenario</h2>{content}</section><section><h2>PASS criterion</h2><p>Every happy transaction must authenticate in one connection. Every retry transaction must fail first with <code>trust_anchor_mismatch</code>, authenticate over a distinct second connection, and avoid session resumption.</p></section><section><h2>Interpretation</h2><p class="note">Each row reports one scenario directly, without subtracting a baseline. Sample SD describes dispersion. The two-sided Student t 95% confidence interval estimates uncertainty around the mean and is unavailable when only one observation exists. Byte counters are read from the client TLS BIO and include both retry connections when applicable; they exclude Ethernet, IP and TCP headers. Review raw observations and system load before drawing conclusions.</p></section><section><h2>Execution</h2>{table(('Field','Value'),[('KEM selection',args.kem_label),('OpenSSL TLS group',args.kem_group),('Profiles',9),('Transactions',630),('Elapsed seconds',result['execution']['elapsed_seconds']),('Computer',f"{platform.system()} {platform.release()} {platform.machine()}"),('JSON summary',args.root/'matrix-summary.json')])}</section></main></body></html>'''
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + '.tmp'); temporary.write_text(page); temporary.replace(args.output)
    print(args.output)

if __name__ == '__main__': main()
