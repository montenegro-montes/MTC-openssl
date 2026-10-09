#!/usr/bin/env python3
"""Render Chromium functional-validation or measurement JSON as HTML."""
import argparse
import html
import json
import os
from pathlib import Path


def esc(value):
    return html.escape(str(value))


def value(value):
    if value is None:
        return '—'
    if isinstance(value, bool):
        return 'YES' if value else 'NO'
    if isinstance(value, float):
        return f'{value:.3f}'
    if isinstance(value, (list, tuple)):
        return ', '.join(map(str, value)) or '—'
    return value


def table(headers, rows):
    head = ''.join(f'<th>{esc(item)}</th>' for item in headers)
    body = ''.join(
        '<tr>' + ''.join(f'<td>{esc(value(item))}</td>' for item in row) + '</tr>'
        for row in rows
    )
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def result(data):
    raw = data.get('overall_pass', data.get('pass', data.get('status')))
    return 'PASS' if raw is True or str(raw).upper() == 'PASS' else 'FAIL'


def relative_link(path, output):
    path = Path(path)
    try:
        target = os.path.relpath(path, output.parent)
    except ValueError:
        target = str(path)
    return f'<a href="{esc(target)}"><code>{esc(path.name)}</code></a>'


def evidence(source, output, extra=()):
    paths = [source]
    paths.extend(source.parent/name for name in ('measurements.csv', 'pairs.csv', 'warmups.csv', 'README.md') if (source.parent/name).is_file())
    paths.extend(Path(item) for item in extra if item)
    seen = set()
    rows = []
    for path in paths:
        key = str(path)
        if key not in seen:
            seen.add(key)
            rows.append((path.name, relative_link(path, output), key))
    # Links are the only intentionally pre-rendered table cells in this module.
    body = ''.join(f'<tr><td>{esc(name)}</td><td>{link}</td><td><code>{esc(path)}</code></td></tr>' for name, link, path in rows)
    return '<div class="scroll"><table><thead><tr><th>Evidence</th><th>Link</th><th>Recorded path</th></tr></thead><tbody>'+body+'</tbody></table></div>'


def shell(title, outcome, intro, sections):
    body = ''.join(f'<section><h2>{esc(name)}</h2>{content}</section>' for name, content in sections)
    css = 'pass' if outcome == 'PASS' else 'fail'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>{esc(title)}</title><style>
body{{font:16px system-ui;background:#f3f6fa;color:#172033;margin:0}}main{{max-width:1250px;margin:auto;padding:28px}}header,section{{background:#fff;border:1px solid #dbe3ed;border-radius:12px;padding:22px;margin:16px 0}}h1{{margin:.2em 0}}h2{{font-size:20px}}h3{{margin-top:28px}}.result{{font-size:26px;font-weight:800}}.pass{{color:#087443}}.fail{{color:#b42318}}.note{{background:#eef5ff;padding:14px;border-left:5px solid #3974c6}}table{{border-collapse:collapse;width:100%}}th,td{{padding:9px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}}th{{background:#edf2f7}}.scroll{{overflow:auto}}code{{background:#edf2f7;padding:2px 5px}}svg{{max-width:100%;height:auto}}.bar-label{{font:12px system-ui}}a{{color:#245ea8}}
</style></head><body><main><header><p>Chromium / MTC experimental report</p><h1>{esc(title)}</h1><p class="result {css}">{esc(outcome)}</p><p>{esc(intro)}</p></header>{body}</main></body></html>'''


def validation_report(data, source, output):
    cases = data.get('cases') or []
    config = [
        ('Hostname', data.get('hostname')), ('Key establishment', data.get('key_establishment')),
        ('MTC trust mode', data.get('mtc_trust_mode')), ('TLS version', (data.get('tls') or {}).get('version')),
        ('TLS group', (data.get('tls') or {}).get('group')), ('Chromium commit', (data.get('chromium') or {}).get('commit')),
        ('Chromium executable SHA-256', (data.get('chromium') or {}).get('sha256')),
    ]
    case_rows = [(case.get('name'), case.get('signature_profile'), case.get('mtc_trust_mode'),
                  case.get('expected_outcome'), case.get('observed_outcome'), case.get('pass'), case.get('reason')) for case in cases]
    tls_rows = [(case.get('name'), case.get('negotiated_canonical_tls'),
                 case.get('server_authentication_flight_observed'), case.get('server_finished_observed'),
                 case.get('client_finished_observed'), case.get('application_data_observed'),
                 case.get('requested_tai_observed'), case.get('selected_tai_observed')) for case in cases]
    extra = []
    for case in cases:
        extra.extend((case.get('evidence') or {}).values())
    sections = [
        ('Configuration', table(('Field', 'Value'), config)),
        ('Functional validation', table(('Case', 'Profile', 'MTC trust mode', 'Expected', 'Observed', 'PASS', 'Reason'), case_rows)),
        ('TLS authentication evidence', table(('Case', 'Canonical TLS', 'Server auth flight', 'Server Finished', 'Client Finished', 'Application data', 'Requested TAI', 'Selected TAI'), tls_rows)),
        ('Interpretation', '<p class="note">This is functional TLS authentication evidence, not a performance result. HTTP application data alone is not treated as proof of MTC verification; the recorded TLS and trust-anchor observations remain visible above.</p>'),
        ('Experimental evidence', evidence(source, output, extra)),
    ]
    return shell('Chromium functional validation', result(data), 'TLS, authentication, trust-anchor and application-level observations from the recorded validation cases.', sections)


def statistics_rows(section):
    rows = []
    for profile, scenarios in section.items():
        if not isinstance(scenarios, dict):
            continue
        for scenario, metrics in scenarios.items():
            if not isinstance(metrics, dict):
                continue
            for metric, stats in metrics.items():
                if isinstance(stats, dict) and 'n' in stats:
                    rows.append((profile, scenario, metric, stats.get('n'), stats.get('mean'), stats.get('sample_stdev'), stats.get('median'), stats.get('minimum'), stats.get('maximum')))
    return rows


def chart(data, metric):
    rows = []
    for profile, scenarios in (data.get('comparison_statistics') or {}).items():
        for scenario, metrics in scenarios.items():
            stats = metrics.get(metric) or {}
            if isinstance(stats.get('median'), (int, float)):
                rows.append((f'{profile} / {scenario}', stats['median']))
    if not rows:
        return ''
    maximum = max(abs(item[1]) for item in rows) or 1
    height = 28 * len(rows) + 20
    bars = []
    for index, (label, number) in enumerate(rows):
        y = 8 + index * 28
        width = 650 * abs(number) / maximum
        bars.append(f'<text class="bar-label" x="0" y="{y+13}">{esc(label)}</text><rect x="280" y="{y}" width="{width:.1f}" height="17" fill="#3974c6"><title>{esc(value(number))}</title></rect><text class="bar-label" x="{290+width:.1f}" y="{y+13}">{esc(value(number))}</text>')
    return f'<h3>Median {esc(metric)}</h3><svg role="img" aria-label="Median {esc(metric)} by profile and scenario" viewBox="0 0 1000 {height}">'+''.join(bars)+'</svg>'


def measurement_report(data, source, output):
    tls = data.get('tls') or {}
    config = [
        ('Run ID', data.get('run_id')), ('Profiles', data.get('profiles')), ('Scenarios', data.get('scenarios')),
        ('Key establishment', data.get('key_establishment')), ('TLS version', tls.get('version')), ('TLS group', tls.get('group')),
        ('X.509 depth', data.get('depth')), ('X.509 fixture set', data.get('fixture_set')),
        ('Measured pairs per profile', data.get('pairs_per_profile')), ('Warmup pairs per profile', data.get('warmups_per_profile')),
        ('Statistics scope', data.get('statistics_scope')), ('Order policy', data.get('order_policy')),
    ]
    validation = [
        ('Attempted measured runs', data.get('attempted_runs')), ('PASS measured runs', data.get('pass_runs')),
        ('Handshake-analysis PASS runs', data.get('handshake_analysis_ok_runs')),
        ('Failed or inconclusive runs', data.get('failed_or_inconclusive_runs')),
        ('Attempted warmup runs', data.get('attempted_warmup_runs')), ('PASS warmup runs', data.get('pass_warmup_runs')),
        ('Certificate verification bypass', data.get('certificate_verification_bypass')),
    ]
    absolute = statistics_rows(data.get('comparison_statistics') or {})
    descriptive = statistics_rows(data.get('descriptive_statistics') or {})
    deltas = statistics_rows(data.get('paired_delta_statistics') or {})
    headers = ('Profile', 'Scenario/comparison', 'Metric', 'n', 'Mean', 'Sample SD', 'Median', 'Minimum', 'Maximum')
    charts = chart(data, 'tls_clienthello_to_client_finished_ms') + chart(data, 'tls_server_certificate_bytes')
    if not charts:
        charts = '<p>No chartable median from the recorded comparison statistics is available.</p>'
    sections = [
        ('Campaign configuration', table(('Field', 'Value'), config)),
        ('TLS validation', table(('Check', 'Recorded value'), validation) + '<p class="note">These counters establish which executions supplied authenticated, analyzable evidence. They are validation gates, not performance metrics.</p>'),
        ('Performance statistics', table(headers, absolute)),
        ('Capture-wide descriptive statistics', table(headers, descriptive)),
        ('Paired differences', table(headers, deltas) + '<p>The comparison name records the subtraction direction. Only complete PASS pairs enter these statistics.</p>'),
        ('Selected visual summaries', charts),
        ('Interpretation limits', '<p class="note">Warmups are retained as evidence but excluded from measured statistics. Browser, NetLog, logical TLS, TCP payload and on-wire metrics have different boundaries; this report preserves the recorded metric names and does not treat them as interchangeable.</p>'),
        ('Experimental evidence', evidence(source, output)),
    ]
    return shell('Chromium paired browser measurements', result(data), 'Measured X.509, MTC landmark and MTC standalone executions, with validation gates reported separately from performance.', sections)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('summary', type=Path, help='Chromium summary.json')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--replace', action='store_true')
    args = parser.parse_args()
    source = args.summary.resolve()
    output = args.output.resolve()
    if not source.is_file():
        parser.error('summary JSON does not exist')
    if output.exists() and not args.replace:
        parser.error('output exists (use --replace to replace the derived report)')
    try:
        data = json.loads(source.read_text())
    except (OSError, ValueError) as error:
        parser.error(f'cannot read summary JSON: {error}')
    if not isinstance(data, dict):
        parser.error('summary JSON must be an object')
    if 'descriptive_statistics' in data or 'comparison_statistics' in data:
        content = measurement_report(data, source, output)
    elif 'cases' in data:
        content = validation_report(data, source, output)
    else:
        parser.error('unrecognized Chromium summary schema')
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name+'.tmp')
    temporary.write_text(content)
    temporary.replace(output)
    print(output)


if __name__ == '__main__':
    main()
