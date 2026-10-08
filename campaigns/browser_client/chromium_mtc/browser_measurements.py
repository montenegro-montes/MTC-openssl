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
FORMAL_X509_FIXTURE_SET = 'chromium-x509-depth-matrix-v1'
CAMPAIGN_PROFILES = ('ecdsa-p256', 'ecdsa-p384', 'mldsa44', 'mldsa65', 'mldsa87')
CASES = ('mtc-positive', 'x509-positive')
PRIMARY = tuple('url_linked_'+name for name in pcap.METRICS)
SECONDARY = (*pcap.METRICS, 'connection_count', 'url_linked_connection_count',
             'auxiliary_tls_only_connection_count', 'aborted_before_tls_completion_connection_count')
METRICS = (*PRIMARY, *SECONDARY)
DECOMPOSITION = tuple('url_linked_'+name for name in pcap.DECOMPOSITION)
COMPARISON = pcap.COMPARISON_FIELDS
COMPARISON_NUMERIC = tuple(key for key in COMPARISON
                           if key not in ('tcp_stream', 'client_random', 'analysis_status', 'analysis_error'))
CSV_OMITTED = {
    'url_linked_server_initial_flight_tcp_payload_bytes',
    'url_linked_client_post_server_flight_tls_payload_bytes',
    'url_linked_http_request_tcp_payload_bytes',
    'url_linked_http_response_tcp_payload_bytes',
    'browser_navigation_to_clienthello_ms',
}
CSV_DECOMPOSITION = tuple(key for key in DECOMPOSITION if key not in CSV_OMITTED)
CSV_COMPARISON = tuple(key for key in COMPARISON if key not in CSV_OMITTED)
CSV_COMPARISON_NUMERIC = tuple(key for key in COMPARISON_NUMERIC if key not in CSV_OMITTED)
META = ('pair', 'pair_index', 'execution_order', 'order_within_pair', 'case', 'signature_profile', 'key_establishment', 'key_exchange_group', 'depth', 'run_id', 'timestamp',
        'result_directory', 'capture_sha256', 'status', 'pair_complete', 'fixture', 'reason')
PAIR_FIELDS = ('pair', 'pair_index', 'execution_order', 'signature_profile', 'key_establishment', 'key_exchange_group', 'depth',
               *(f'{metric}_{suffix}' for metric in (*PRIMARY, *CSV_DECOMPOSITION, *CSV_COMPARISON_NUMERIC)
                                                 for suffix in ('mtc', 'x509', 'delta')))
BYTE_DEFINITION = 'Observed TCP payload bytes including retransmissions, excluding link/IP/TCP headers.'


def existing_mtc(repo, image, profile):
    try:
        selected, _ = bv.preselect_mtc_fixture(repo, profile)
    except ValueError as error:
        raise ValueError(
            f'profile={profile}: missing valid MTC N=16 landmark leaf 0 fixture; '
            'browser-measurements is reuse-only/fail-closed. Prepare it with: '
            f'bin/browser_client/mt-chromium-setup browser-validation credentials --profile {profile}. '
            f'Reason: {error}') from error
    with bv.DockerOpenSSLBatch(image) as openssl:
        validated = bv.validate_mtc(
            Path(selected['fixture']), profile, image, openssl=openssl)
    validated.update(anchor=selected['anchor'], anchor_sha256=selected['anchor_sha256'],
                     anchor_origin=selected['anchor_origin'], origin='reused-prechecked')
    return validated


def profile_run_preconditions(repo, image, profile, depth, fixture_set):
    mtc = existing_mtc(repo, image, profile)
    try:
        fixture = bv.precheck_formal_x509_fixture(
            repo, profile, depth, fixture_set)
    except ValueError as error:
        setup = (f'bin/browser_client/mt-chromium-setup x509-fixtures generate-matrix '
                 f'--fixture-set {fixture_set} --output NEW_PATH'
                 if fixture_set == FORMAL_X509_FIXTURE_SET else
                 f'bin/browser_client/mt-chromium-setup x509-fixtures generate '
                 f'--profile {profile} --fixture-set {fixture_set} --output NEW_PATH')
        raise ValueError(
            f'Missing valid X509 fixture: fixture_set={fixture_set}, '
            f'profile={profile}, depth={depth}. browser-measurements is '
            f'reuse-only/fail-closed; prepare it with: {setup}. Reason: {error}') from error
    with bv.DockerOpenSSLBatch(image) as openssl:
        selected = bv.validate_x509(
            fixture, profile=profile, depth=depth, image=image,
            fixture_set=fixture_set, openssl=openssl)
    selected['origin'] = 'reused-formal-fixture-set'
    policy = bv.chromium_ca_policy(selected['root'])
    return dict(mtc=mtc, x509=selected), policy


def campaign_preconditions(repo, image, profiles, depth, fixture_set):
    prepared = {}
    for profile in profiles:
        try:
            prepared[profile] = profile_run_preconditions(
                repo, image, profile, depth, fixture_set)
        except Exception as error:
            raise ValueError(f'profile={profile}: {error}') from error
    return prepared


def campaign_totals(profiles, pairs, warmups=0):
    total_pairs = len(profiles) * pairs
    total_warmup_pairs = len(profiles) * warmups
    return dict(pairs_per_profile=pairs, total_pairs=total_pairs,
                total_measurements=total_pairs * len(CASES), warmups_per_profile=warmups,
                total_warmup_pairs=total_warmup_pairs,
                total_warmup_runs=total_warmup_pairs * len(CASES))


def now():
    return datetime.now(timezone.utc).isoformat()


def order(pair):
    return CASES if pair % 2 else CASES[::-1]


def campaign_phases(warmups, pairs):
    return (('warmup', warmups), ('measured', pairs))


def record_measurement_error(output, row, error, phase, execution):
    row.update(status='INCONCLUSIVE' if row['status']=='PASS' else row['status'],
               reason=str(error))
    output.mkdir(exist_ok=True)
    if not (output/'measurement-metadata.json').exists():
        bv.write(output/'measurement-metadata.json', execution)
    bv.write(output/'measurement-error.json',
             dict(error=str(error), status=row['status'], phase=phase,
                  policy='fail-closed; failed executions are never replaced'))


def verify_measurement_inputs(inputs, chromium_executable):
    for path, digest in inputs.items():
        if path != chromium_executable:
            bv.require(bv.sha(path) == digest, 'Input changed: '+path)


def record_chromium_reference(output, browser, profile):
    bv.write(output/'chromium-integrity.json', dict(
        executable=browser['executable'], sha256=browser['sha256'],
        signature_profile=profile, verification='campaign-start reference; rechecked after profile'))


def verify_chromium_after_profile(browser, profile_root, profile):
    actual = bv.sha(browser['executable'])
    evidence = dict(executable=browser['executable'], expected_sha256=browser['sha256'],
                    actual_sha256=actual, signature_profile=profile,
                    status='PASS' if actual == browser['sha256'] else 'FAIL')
    bv.write(profile_root/'chromium-integrity.json', evidence)
    bv.require(actual == browser['sha256'],
               f'Chromium executable integrity changed during profile={profile}')


def describe(values):
    return dict(n=len(values), minimum=min(values), maximum=max(values), mean=statistics.mean(values),
                median=statistics.median(values), sample_stdev=statistics.stdev(values) if len(values)>1 else None)


def save_outputs(root, summary, rows, pairs, warmup_rows=()):
    for name, fields, data in [('measurements.csv', (*META, *METRICS, *CSV_DECOMPOSITION, *CSV_COMPARISON), rows), ('pairs.csv', PAIR_FIELDS, pairs)]:
        with (root/name).open('x', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields, extrasaction='ignore'); writer.writeheader(); writer.writerows(data)
    with (root/'warmups.csv').open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=('phase', *META, *METRICS, *CSV_DECOMPOSITION, *CSV_COMPARISON),
                                extrasaction='ignore')
        writer.writeheader(); writer.writerows(warmup_rows)
    summary.update(finished_at=now(), completed_pairs=len(pairs), attempted_runs=len(rows),
                   pass_runs=sum(row['status']=='PASS' for row in rows),
                   failed_or_inconclusive_runs=sum(row['status']!='PASS' for row in rows),
                   attempted_warmup_runs=len(warmup_rows),
                   pass_warmup_runs=sum(row['status']=='PASS' for row in warmup_rows),
                   failed_or_inconclusive_warmup_runs=sum(row['status']!='PASS' for row in warmup_rows),
                   warmup_results=[{key: row.get(key) for key in
                                    ('phase', 'signature_profile', 'case', 'pair_index',
                                     'execution_order', 'status', 'reason', 'result_directory')}
                                   for row in warmup_rows],
                   warmup_policy='Fail closed on first failed warmup; never replace or include warmups in measured statistics',
                   statistics_scope='Complete PASS pairs only', descriptive_statistics={})
    accepted = [row for row in rows if row['pair_complete']]
    if accepted:
        completed_profiles = sorted({row['signature_profile'] for row in accepted})
        summary['descriptive_statistics'] = {profile: {
            case: {metric: describe([row[metric] for row in accepted
                                     if row['signature_profile']==profile and row['case']==case])
                   for metric in METRICS}
            for case in CASES} for profile in completed_profiles}
        summary['paired_delta_statistics'] = {profile: {
            metric: describe([pair[metric+'_delta'] for pair in pairs
                              if pair['signature_profile']==profile])
            for metric in PRIMARY} for profile in completed_profiles}
    summary['decomposition_definitions'] = pcap.DECOMPOSITION_DEFINITIONS
    summary['comparison_definitions'] = pcap.COMPARISON_DEFINITIONS
    summary['handshake_analysis_ok_runs'] = sum(row.get('analysis_status') == 'OK' for row in accepted)
    summary['comparison_statistics'] = {profile: {
        case: {metric: describe(values) for metric in COMPARISON_NUMERIC
               if (values := [row[metric] for row in accepted
                              if row['signature_profile']==profile and row['case']==case
                              and row.get(metric) is not None])}
        for case in CASES} for profile in sorted({row['signature_profile'] for row in accepted})}
    bv.write(root/'summary.json', summary)
    (root/'README.md').write_text(
        '# Chromium paired browser measurement pilot\n\n'
        f"Status: {summary['status']}. Complete pairs: {len(pairs)}/{summary['requested_pairs']}. "
        f"Attempted runs: {len(rows)}; PASS: {summary['pass_runs']}.\n\n"
        f"{summary['tls']['version']} / {summary['key_establishment']} "
        f"(server group {summary['tls']['group']}) / {summary['tls']['cipher']}; "
        f"profiles={', '.join(summary['profiles'])}; "
        f"X.509 D={summary['depth']} (includes root); "
        f"{summary['depth']-1} transmitted certificates; "
        'MTC N=16 landmark; server-only authentication.\n\n'
        f"Warmups: {summary.get('warmups_per_profile', 0)} complete pairs/profile, retained only in warmups.csv. "
        'Odd pairs: MTC then X.509. Even pairs: X.509 then MTC in both phases. '
        'Each run uses a fresh browser profile and the existing headless PCAP validation. '
        'Credentials and Chromium selection are fixed for the campaign.\n'
        f"X.509 trust mode: {summary.get('x509_trust_mode', 'unspecified')}; "
        f"certificate verification bypass: {str(summary.get('certificate_verification_bypass', False)).lower()}.\n\n"
        'Primary metrics use connections linked by NetLog to the requested navigation. '
        'Secondary metrics include all target TLS connections correlated between PCAP and server.log. '
        +BYTE_DEFINITION+'\n\n'
        'measurements.csv retains every attempted measured run with explicit status; warmups.csv retains warmup evidence. '
        'Warmups are excluded from measurements.csv, pairs.csv and every statistic. '
        'pair_complete identifies rows usable for paired descriptions. pairs.csv contains only complete PASS pairs; '
        'each primary metric has mtc, x509 and delta (MTC - X509) columns. '
        'summary.json describes only complete PASS pairs. Raw evidence remains in profiles/PROFILE/pair-NNNN/<case>/.\n\n'
        'These are descriptive pilot results, with no bootstrap, hypothesis tests or statistical claims. '
        'There is no network emulation.\n\n'
        '## Optional URL-linked decomposition\n\n'
        'Each field below has a url_linked_ prefix in measurements.csv and additional '
        '_mtc, _x509 and _delta columns in pairs.csv. Deltas are available only when both values exist. '
        'Existing aggregate metrics are unchanged; these components are not an additive partition.\n\n'
        + '\n'.join('- '+key+': '+value for key, value in pcap.DECOMPOSITION_DEFINITIONS.items())
        + '\n\nUnavailable encrypted components (blank CSV / null JSON): '
        + ', '.join(pcap.DECOMPOSITION[1:6])+'\n\n'
        '## Comparable handshake and browser scope\n\n'
        'measurements.csv appends the shared s_client PCAP schema and separate browser timings. '
        'pairs.csv adds numeric MTC/X509 deltas only when both measurements exist. '
        'comparison_statistics reports the available sample count per metric. '
        'Per-stream values are in pair-NNNN/<case>/connection-metrics.csv. '
        'tls.keys contains session secrets (mode 0600); keep it private with the raw evidence.\n\n'
        + '\n'.join('- '+key+': '+value for key, value in pcap.COMPARISON_DEFINITIONS.items())
        + '\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'requirements', 'status', 'run'))
    parser.add_argument('--pairs', type=int, help='Required for run; no implicit large campaign')
    parser.add_argument('--warmups', type=int, default=0,
                        help='Complete paired warmups per profile, excluded from measured outputs (default: 0)')
    parser.add_argument('--profile', choices=bv.PROFILES, default=bv.PROFILE)
    parser.add_argument('--all-profiles', action='store_true',
                        help=argparse.SUPPRESS)
    parser.add_argument('--key-establishment', choices=tuple(bv.KEY_ESTABLISHMENTS), default='x25519',
                        help='Group restricted at the server and verified in NetLog (default: x25519)')
    parser.add_argument('--depth', type=int, choices=(2, 3, 4, 5), default=2)
    parser.add_argument('--x509-fixture-set')
    parser.add_argument('--chromium', type=Path)
    parser.add_argument('--x509-chromium-ca-policy', action='store_true',
                        help='Use an externally installed Chromium CACertificates policy as the X.509 trust anchor; no certificate bypass')
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--image', default='mt-tls-mtc:local')
    args = parser.parse_args()
    bv.require(args.pairs is None or args.pairs > 0, '--pairs must be a positive integer')
    bv.require(args.warmups >= 0, '--warmups must be a non-negative integer')
    bv.require(not args.x509_fixture_set or args.action == 'run',
               '--x509-fixture-set requires run')
    bv.require(not args.x509_chromium_ca_policy or args.action == 'run',
               '--x509-chromium-ca-policy requires run')
    bv.require(not args.all_profiles or args.action == 'run', '--all-profiles requires run')
    bv.require(5 <= args.timeout <= 300, 'Timeout must be between 5 and 300 seconds')
    if args.action == 'run' and args.x509_fixture_set is None:
        args.x509_fixture_set = FORMAL_X509_FIXTURE_SET
    if args.action == 'plan':
        tls = bv.key_establishment_config(args.key_establishment)
        print(f"PRINT ONLY: {tls['version']} / {tls['key_establishment_label']} (server group {tls['group']}) / "
              f"{tls['cipher']} / {args.profile} / D={args.depth} / MTC N=16 / server-only.")
        print('Chromium keeps its compiled group offer; the server is restricted to the selected group and NetLog checks negotiation.')
        print('Odd pairs: mtc-positive -> x509-positive; even pairs: x509-positive -> mtc-positive.')
        print(f'Warmups: {args.warmups} complete pairs/profile; executed first and excluded from measured outputs.')
        print(f"Pairs: {args.pairs if args.pairs is not None else 'explicit --pairs required for run'}")
        print('Each run must PASS existing browser/PCAP validation. Stop on any failure; preserve evidence.')
        print('Outputs: measurements.csv, pairs.csv, summary.json, README.md and per-run evidence.'); return 0
    if args.action == 'requirements':
        print(bv.json.dumps(pcap.requirements(), indent=2))
        print('tshark is required for measurement metrics. A trusted X.509 root or externally installed Chromium CACertificates policy, plus valid requested-profile/depth fixtures, is required.'); return 0
    if args.action == 'status':
        paths = sorted((bv.REPO/'artifacts/results').glob(PREFIX+'*/summary.json'))
        print(bv.json.dumps(bv.read(paths[-1]), indent=2) if paths else 'NO BROWSER MEASUREMENT RESULTS'); return 0
    bv.require(args.pairs is not None, 'Specify --pairs explicitly, for example run --pairs 3')
    profiles = CAMPAIGN_PROFILES if args.all_profiles else (args.profile,)
    prepared = campaign_preconditions(
        bv.REPO, args.image, profiles, args.depth, args.x509_fixture_set)
    args.x509_chromium_ca_policy = True
    tools = pcap.requirements()
    bv.require(tools['interface'] and (tools['dumpcap'] or tools['tcpdump']) and tools['tshark'],
               'Measurements require Darwin/Linux, dumpcap or tcpdump, and tshark. '+tools['instruction'])
    bv.check_hostname()
    browser = bv.browser_executable(args.chromium)
    chromium_executable = browser['executable']
    with socket.socket() as sock:
        try: sock.bind(('127.0.0.1', 4433))
        except OSError: raise ValueError('Port 4433 occupied; stop its owner explicitly')
    lock = bv.REPO/'.mt-state/chromium-browser-validation.lock'
    lock.parent.mkdir(exist_ok=True)
    try: lock.mkdir()
    except FileExistsError: raise ValueError('Browser validation locked; inspect active run before retrying')
    root = None; rows = []; pairs = []; warmup_rows = []
    totals = campaign_totals(profiles, args.pairs, args.warmups)
    summary = dict(status='FAIL', overall_pass=False, started_at=now(),
                   requested_pairs=totals['total_pairs'], requested_runs=totals['total_measurements'],
                   profiles=list(profiles), key_establishment=args.key_establishment,
                   depth=args.depth, fixture_set=args.x509_fixture_set, **totals,
                   warmups=args.warmups, byte_definition=BYTE_DEFINITION,
                   tls=bv.key_establishment_config(args.key_establishment),
                   x509_trust_mode='chromium-ca-policy', certificate_verification_bypass=False,
                   capture_backend=tools, order='Odd: MTC -> X509; even: X509 -> MTC')
    try:
        root = bv.REPO/'artifacts/results'/(PREFIX+bv.stamp()); root.mkdir(parents=True, exist_ok=False)
        summary['run_id'] = root.name
        print('Result directory: '+str(root), flush=True)
        summary.update(chromium=browser, credentials={}, x509_policies={}, input_sha256={})
        for profile in profiles:
            credentials, x509_trust_metadata = prepared[profile]
            bv.CA = credentials['mtc']['ca_id']
            bv.SELECTED = credentials['mtc']['selected_tai']
            bv.REQUESTED = credentials['mtc']['requested_tai']
            x509_trust_metadata = dict(x509_trust_metadata,
                fixture_root_pem_sha256=credentials['x509']['root_sha256'])
            profile_root = root/'profiles'/profile; profile_root.mkdir(parents=True)
            bv.write(profile_root/'credentials.json', credentials)
            summary['credentials'][profile] = credentials
            summary['x509_policies'][profile] = x509_trust_metadata
            inputs = {str(Path(data[key])): bv.sha(data[key]) for data, keys in (
                (credentials['mtc'], ('cert','key','trust','anchor')),
                (credentials['x509'], ('cert','key','root'))) for key in keys}
            if credentials['x509'].get('intermediates'):
                path = credentials['x509']['intermediates']; inputs[path] = bv.sha(path)
            inputs[browser['executable']] = browser['sha256']
            summary['input_sha256'][profile] = inputs
            for phase, pair_count in campaign_phases(args.warmups, args.pairs):
                phase_rows = warmup_rows if phase == 'warmup' else rows
                phase_root = profile_root/'warmups' if phase == 'warmup' else profile_root
                if pair_count and phase == 'warmup':
                    phase_root.mkdir()
                for pair_index in range(1, pair_count+1):
                    pair_root = phase_root/f'pair-{pair_index:04d}'; pair_root.mkdir()
                    pair_rows = []
                    for position, case in enumerate(order(pair_index), 1):
                        output = pair_root/case
                        relative_output = output.relative_to(root)
                        row = dict(pair=pair_index, pair_index=pair_index,
                                   execution_order=len(warmup_rows)+len(rows)+1,
                                   order_within_pair=position, case=case, signature_profile=profile,
                                   key_establishment=args.key_establishment,
                                   key_exchange_group=bv.KEY_ESTABLISHMENTS[args.key_establishment]['openssl_group'],
                                   depth=args.depth, run_id=f'{root.name}/{relative_output}',
                                   timestamp=now(), result_directory=str(output), capture_sha256='',
                                   status='INCONCLUSIVE', pair_complete=False,
                                   fixture=credentials['mtc' if case=='mtc-positive' else 'x509']['fixture'], reason='')
                        if phase == 'warmup':
                            row['phase'] = phase
                        phase_rows.append(row); pair_rows.append(row)
                        capture = pcap.Capture(output, tools)
                        execution = dict(phase=phase, profile=profile, case=case,
                                         pair_index=pair_index,
                                         execution_order=row['execution_order'])
                        try:
                            verify_measurement_inputs(inputs, chromium_executable)
                            with socket.socket() as sock:
                                try: sock.bind(('127.0.0.1', 4433))
                                except OSError: raise ValueError('Port 4433 occupied; stop its owner explicitly')
                            browser_result = bv.run_case(case, credentials, browser, output, pair_root, args.timeout,
                                                         False, browser_mode='headless', capture=capture,
                                                         key_establishment=args.key_establishment)
                            bv.write(output/'measurement-metadata.json', execution)
                            record_chromium_reference(output, browser, profile)
                            browser_result['signature_profile'] = profile
                            if case == 'x509-positive': browser_result.update(x509_trust_metadata)
                            bv.write(output/'browser-result.json', browser_result)
                            result = pcap.analyze(output, capture, browser_result)
                            if case == 'x509-positive': result.update(x509_trust_metadata)
                            bv.write(output/'result.json', result); bv.write(output/'summary.json', result)
                            row.update(status=result['observed_outcome'], capture_sha256=result.get('capture_sha256',''))
                            bv.require(browser_result['pass'] is True and result['pass'] is True
                                       and row['status']=='PASS', 'Individual run is not PASS: '+str(result.get('reasons', [])))
                            wire = result['wire_observed']
                            bv.require(all(type(wire.get(k)) is int and wire[k]>=0 for k in METRICS), 'Missing/invalid integer metrics')
                            row.update({key: wire[key] for key in METRICS})
                            row.update({key: wire.get(key) for key in DECOMPOSITION})
                            row.update({key: wire.get(key) for key in COMPARISON})
                        except BaseException as error:
                            record_measurement_error(output, row, error, phase, execution)
                            raise
                        finally: capture.stop()
                        print(f'{profile} {phase} pair {pair_index}, order {position}, {case}: PASS', flush=True)
                    for row in pair_rows: row['pair_complete'] = True
                    if phase == 'warmup':
                        continue
                    by_case = {row['case']: row for row in pair_rows}
                    paired = dict(pair=pair_index, pair_index=pair_index,
                                  execution_order=' -> '.join(order(pair_index)), signature_profile=profile,
                                  key_establishment=args.key_establishment,
                                  key_exchange_group=bv.KEY_ESTABLISHMENTS[args.key_establishment]['openssl_group'],
                                  depth=args.depth)
                    for metric in (*PRIMARY, *DECOMPOSITION, *COMPARISON_NUMERIC):
                        mtc, classic = (by_case[case][metric] for case in CASES)
                        paired.update({metric+'_mtc': mtc, metric+'_x509': classic,
                                       metric+'_delta': mtc-classic if mtc is not None and classic is not None else None})
                    pairs.append(paired)
            verify_chromium_after_profile(browser, profile_root, profile)
        summary.update(status='PASS', overall_pass=True)
        return 0
    except BaseException as error:
        summary['reason'] = str(error) or type(error).__name__
        raise
    finally:
        try:
            if root is not None: save_outputs(root, summary, rows, pairs, warmup_rows)
        finally:
            lock.rmdir()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, bv.subprocess.SubprocessError) as error:
        print('ERROR: '+str(error), file=sys.stderr); sys.exit(1)
