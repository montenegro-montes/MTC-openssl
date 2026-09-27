#!/usr/bin/env python3
"""Alternating paired browser pilot; reuse functional/PCAP validation unchanged."""
import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path
import socket
import statistics
import sys

sys.dont_write_bytecode = True
import browser_validation as bv
import browser_pcap as pcap

PREFIX = 'chromium-browser-measurements-'
CASES = ('mtc-positive', 'x509-positive')
PRIMARY = tuple('url_linked_'+name for name in pcap.METRICS)
SECONDARY = (*pcap.METRICS, 'connection_count', 'url_linked_connection_count',
             'auxiliary_tls_only_connection_count', 'aborted_before_tls_completion_connection_count')
METRICS = (*PRIMARY, *SECONDARY)
DECOMPOSITION = tuple('url_linked_'+name for name in pcap.DECOMPOSITION)
META = ('pair_index', 'execution_order', 'order_within_pair', 'case', 'run_id', 'timestamp',
        'result_directory', 'capture_sha256', 'status', 'pair_complete', 'fixture', 'reason')
PAIR_FIELDS = ('pair_index', 'execution_order', *(f'{metric}_{suffix}' for metric in (*PRIMARY, *DECOMPOSITION)
                                                 for suffix in ('mtc', 'x509', 'delta')))
BYTE_DEFINITION = 'Observed TCP payload bytes including retransmissions, excluding link/IP/TCP headers.'


def now():
    return datetime.now(timezone.utc).isoformat()


def order(pair):
    return CASES if pair % 2 else CASES[::-1]


def describe(values):
    return dict(n=len(values), minimum=min(values), maximum=max(values), mean=statistics.mean(values),
                median=statistics.median(values), sample_stdev=statistics.stdev(values) if len(values)>1 else None)


def save_outputs(root, summary, rows, pairs):
    for name, fields, data in [('measurements.csv', (*META, *METRICS, *DECOMPOSITION), rows), ('pairs.csv', PAIR_FIELDS, pairs)]:
        with (root/name).open('x', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader(); writer.writerows(data)
    summary.update(finished_at=now(), completed_pairs=len(pairs), attempted_runs=len(rows),
                   pass_runs=sum(row['status']=='PASS' for row in rows),
                   failed_or_inconclusive_runs=sum(row['status']!='PASS' for row in rows),
                   statistics_scope='Complete PASS pairs only', descriptive_statistics={})
    accepted = [row for row in rows if row['pair_complete']]
    if accepted:
        summary['descriptive_statistics'] = {
            case: {metric: describe([row[metric] for row in accepted if row['case']==case]) for metric in METRICS}
            for case in CASES}
        summary['paired_delta_statistics'] = {
            metric: describe([pair[metric+'_delta'] for pair in pairs]) for metric in PRIMARY}
    summary['decomposition_definitions'] = pcap.DECOMPOSITION_DEFINITIONS
    bv.write(root/'summary.json', summary)
    (root/'README.md').write_text(
        '# Chromium paired browser measurement pilot\n\n'
        f"Status: {summary['status']}. Complete pairs: {len(pairs)}/{summary['requested_pairs']}. "
        f"Attempted runs: {len(rows)}; PASS: {summary['pass_runs']}.\n\n"
        'TLS 1.3 / X25519 / TLS_AES_256_GCM_SHA384; ECDSA P-256; X.509 D=2 '
        '(local root plus server; one transmitted certificate); MTC N=16 landmark; server-only authentication.\n\n'
        'Odd pairs: MTC then X.509. Even pairs: X.509 then MTC. No warmups. '
        'Each run uses a fresh browser profile and the existing headless PCAP validation. '
        'Credentials and Chromium selection are fixed for the campaign.\n\n'
        'Primary metrics use connections linked by NetLog to the requested navigation. '
        'Secondary metrics include all target TLS connections correlated between PCAP and server.log. '
        +BYTE_DEFINITION+'\n\n'
        'measurements.csv retains every attempted run with explicit status; unsuccessful runs have no accepted metrics. '
        'pair_complete identifies rows usable for paired descriptions. pairs.csv contains only complete PASS pairs; '
        'each primary metric has mtc, x509 and delta (MTC - X509) columns. '
        'summary.json describes only complete PASS pairs. Raw evidence remains in pair-NNNN/<case>/.\n\n'
        'These are descriptive pilot results, with no bootstrap, hypothesis tests or statistical claims. '
        'There is no network emulation.\n\n'
        '## Optional URL-linked decomposition\n\n'
        'Each field below has a url_linked_ prefix in measurements.csv and additional '
        '_mtc, _x509 and _delta columns in pairs.csv. Deltas are available only when both values exist. '
        'Existing aggregate metrics are unchanged; these components are not an additive partition.\n\n'
        + '\n'.join('- '+key+': '+value for key, value in pcap.DECOMPOSITION_DEFINITIONS.items())
        + '\n\nUnavailable encrypted components (blank CSV / null JSON): '
        + ', '.join(pcap.DECOMPOSITION[1:6])+'\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'requirements', 'status', 'run'))
    parser.add_argument('--pairs', type=int, help='Required for run; no implicit large campaign')
    parser.add_argument('--chromium', type=Path)
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--image', default='mt-tls-mtc:local')
    args = parser.parse_args()
    bv.require(args.pairs is None or args.pairs > 0, '--pairs must be a positive integer')
    bv.require(5 <= args.timeout <= 300, 'Timeout must be between 5 and 300 seconds')
    if args.action == 'plan':
        print('PRINT ONLY: fixed TLS 1.3 / X25519 / TLS_AES_256_GCM_SHA384 / ECDSA P-256 / D=2 / MTC N=16 / server-only.')
        print('Odd pairs: mtc-positive -> x509-positive; even pairs: x509-positive -> mtc-positive. No warmups.')
        print(f"Pairs: {args.pairs if args.pairs is not None else 'explicit --pairs required for run'}")
        print('Each run must PASS existing browser/PCAP validation. Stop on any failure; preserve evidence.')
        print('Outputs: measurements.csv, pairs.csv, summary.json, README.md and per-run evidence.'); return 0
    if args.action == 'requirements':
        print(bv.json.dumps(pcap.requirements(), indent=2))
        print('tshark is required for measurement metrics. Existing trusted X.509 root and valid D=2 fixtures required.'); return 0
    if args.action == 'status':
        paths = sorted((bv.REPO/'artifacts/results').glob(PREFIX+'*/summary.json'))
        print(bv.json.dumps(bv.read(paths[-1]), indent=2) if paths else 'NO BROWSER MEASUREMENT RESULTS'); return 0
    bv.require(args.pairs is not None, 'Specify --pairs explicitly, for example run --pairs 3')
    tools = pcap.requirements()
    bv.require(tools['interface'] and (tools['dumpcap'] or tools['tcpdump']) and tools['tshark'],
               'Measurements require Darwin/Linux, dumpcap or tcpdump, and tshark. '+tools['instruction'])
    lock = bv.REPO/'.mt-state/chromium-browser-validation.lock'
    lock.parent.mkdir(exist_ok=True)
    try: lock.mkdir()
    except FileExistsError: raise ValueError('Browser validation locked; inspect active run before retrying')
    root = None; rows = []; pairs = []
    summary = dict(status='FAIL', overall_pass=False, started_at=now(), requested_pairs=args.pairs,
                   requested_runs=2*args.pairs, warmups=0, byte_definition=BYTE_DEFINITION,
                   profile=dict(tls=bv.TLS, signature='ecdsa-p256', depth_including_root=2,
                                transmitted_certificates=1, mtc_tree_size=16, authentication='server-only'),
                   capture_backend=tools, order='Odd: MTC -> X509; even: X509 -> MTC')
    try:
        root = bv.REPO/'artifacts/results'/(PREFIX+bv.stamp()); root.mkdir(parents=True, exist_ok=False)
        summary['run_id'] = root.name
        print('Result directory: '+str(root), flush=True)
        credentials = bv.prepare_credentials(bv.REPO, root, args.image)
        bv.require(credentials['x509']['root_trust']['status'] == 'TRUSTED', 'X509 root must already be trusted')
        bv.require(not credentials['x509'].get('intermediates'), 'This pilot requires X.509 D=2; intermediates are unsupported')
        x509 = bv.crypto()[0]
        leaf = x509.load_pem_x509_certificate(Path(credentials['x509']['cert']).read_bytes())
        ca = x509.load_pem_x509_certificate(Path(credentials['x509']['root']).read_bytes())
        bv.require(leaf.issuer == ca.subject and leaf.subject != ca.subject, 'X.509 must be root -> server (D=2)')
        bv.require(all(credentials[c]['profile']=='ecdsa-p256' for c in ('mtc','x509'))
                   and credentials['mtc']['tree_size']==16 and credentials['mtc']['mode']=='landmark', 'Pilot profile mismatch')
        bv.check_hostname()
        browser = bv.browser_executable(args.chromium)
        summary.update(credentials=credentials, chromium=browser)
        # Freeze existing evidence inputs once, then verify them before every run.
        inputs = {str(Path(data[key])): bv.sha(data[key]) for data, keys in (
            (credentials['mtc'], ('cert','key','trust','anchor')),
            (credentials['x509'], ('cert','key','root'))) for key in keys}
        inputs[browser['executable']] = browser['sha256']
        summary['input_sha256'] = inputs
        for pair_index in range(1, args.pairs+1):
            pair_root = root/f'pair-{pair_index:04d}'; pair_root.mkdir()
            pair_rows = []
            for position, case in enumerate(order(pair_index), 1):
                output = pair_root/case
                row = dict(pair_index=pair_index, execution_order=len(rows)+1, order_within_pair=position,
                           case=case, run_id=f'{root.name}/pair-{pair_index:04d}/{case}', timestamp=now(),
                           result_directory=str(output), capture_sha256='', status='INCONCLUSIVE', pair_complete=False,
                           fixture=credentials['mtc' if case=='mtc-positive' else 'x509']['fixture'], reason='')
                rows.append(row); pair_rows.append(row)
                capture = pcap.Capture(output, tools)
                try:
                    for path, digest in inputs.items(): bv.require(bv.sha(path)==digest, 'Input changed: '+path)
                    with socket.socket() as sock:
                        try: sock.bind(('127.0.0.1', 4433))
                        except OSError: raise ValueError('Port 4433 occupied; stop its owner explicitly')
                    browser_result = bv.run_case(case, credentials, browser, output, pair_root, args.timeout,
                                                 False, browser_mode='headless', capture=capture)
                    bv.write(output/'browser-result.json', browser_result)
                    result = pcap.analyze(output, capture, browser_result)
                    bv.write(output/'result.json', result); bv.write(output/'summary.json', result)
                    row.update(status=result['observed_outcome'], capture_sha256=result.get('capture_sha256',''))
                    bv.require(browser_result['pass'] is True and result['pass'] is True
                               and row['status']=='PASS', 'Individual run is not PASS: '+str(result.get('reasons', [])))
                    wire = result['wire_observed']
                    bv.require(all(type(wire.get(k)) is int and wire[k]>=0 for k in METRICS), 'Missing/invalid integer metrics')
                    row.update({key: wire[key] for key in METRICS})
                    row.update({key: wire.get(key) for key in DECOMPOSITION})
                except BaseException as error:
                    row.update(status='INCONCLUSIVE' if row['status']=='PASS' else row['status'], reason=str(error))
                    output.mkdir(exist_ok=True)
                    bv.write(output/'measurement-error.json', dict(error=str(error), status=row['status']))
                    raise
                finally:
                    capture.stop()
                print(f'Pair {pair_index}, order {position}, {case}: PASS', flush=True)
            by_case = {row['case']: row for row in pair_rows}
            paired = dict(pair_index=pair_index, execution_order=' -> '.join(order(pair_index)))
            for metric in (*PRIMARY, *DECOMPOSITION):
                mtc, classic = (by_case[case][metric] for case in CASES)
                paired.update({metric+'_mtc': mtc, metric+'_x509': classic,
                               metric+'_delta': mtc-classic if mtc is not None and classic is not None else None})
            for row in pair_rows: row['pair_complete'] = True
            pairs.append(paired)
        summary.update(status='PASS', overall_pass=True)
        return 0
    except BaseException as error:
        summary['reason'] = str(error) or type(error).__name__
        raise
    finally:
        try:
            if root is not None: save_outputs(root, summary, rows, pairs)
        finally:
            lock.rmdir()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, bv.subprocess.SubprocessError) as error:
        print('ERROR: '+str(error), file=sys.stderr); sys.exit(1)
