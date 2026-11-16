#!/usr/bin/env python3
"""Intermediate server-authentication files. Python 3.10+, standard library only.

python3 prepare_authentication.py --native native.csv \
    --chromium measurements.csv --out-dir intermediate
Reads summary.json beside each CSV for provenance/configuration only.
Does not reconstruct timings from historical metrics or PCAP.
"""
import argparse
import csv
import hashlib
import io
import json
import re
from collections import Counter, defaultdict
from decimal import Decimal, localcontext
from pathlib import Path

TIMES = ['handshake_total_ns', 'credential_validation_total_ns',
         'certificate_verify_crypto_ns', 'x509_signatures_ns', 'mtc_total_ns',
         'merkle_total_ns', 'merkle_leaf_hash_ns', 'merkle_path_ns',
         'landmark_trust_ns', 'standalone_signatures_ns']
DERIVED_RESIDUALS = ['credential_residual_ns', 'mtc_residual_ns', 'merkle_residual_ns']
METRICS = TIMES + ['auth_total_ns'] + DERIVED_RESIDUALS
CACHE = ['x509_signature_cache_ns', 'x509_signature_cache_hits',
         'x509_signature_cache_misses', 'standalone_signature_cache_ns',
         'standalone_signature_cache_hits', 'standalone_signature_cache_misses']
COUNTS = ['x509_signature_count', 'standalone_signature_count']
META = ['timing_schema_version', 'credential_type', 'mtc_verification_mode',
        'mtc_trust_mode', 'x509_signatures_scope', *COUNTS, *CACHE,
        'mtc_success', 'certificate_verify_algorithm', 'certificate_verify_success',
        'status', 'reason', 'pair_complete', 'netlog_timing_status',
        'netlog_timing_error', 'analysis_status', 'analysis_error',
        'authentication_components_status', 'authentication_components_error',
        'run_id', 'timestamp', 'result_directory', 'capture_sha256', 'pair',
        'pair_index', 'execution_order', 'order_within_pair', 'client_random',
        'tcp_stream', 'connection_count', 'url_linked_connection_count',
        'auxiliary_tls_only_connection_count',
        'aborted_before_tls_completion_connection_count', 'credential', 'anchor',
        'requested_tai', 'selected_tai', 'fixture', 'key_establishment',
        'openssl_group', 'key_exchange_group', 'depth']
CONFIG_FIELDS = ['client', 'source_sha256', 'summary_sha256', 'profile', 'case',
                 'case_original', 'timing_schema_version', 'credential_type',
                 'mtc_verification_mode', 'mtc_trust_mode', 'key_establishment',
                 'openssl_group', 'key_exchange_group', 'depth', 'campaign_depth',
                 'x509_signatures_scope', 'certificate_verify_algorithm',
                 'credential', 'anchor', 'fixture', 'requested_tai', 'selected_tai']
BASE = ['sample_id', 'client', 'source_file', 'source_sha256', 'source_record',
        'source_line', 'summary_file', 'summary_sha256', 'campaign_id',
        'campaign_depth', 'campaign_depth_source', 'phase', 'phase_source',
        'repetition', 'repetition_source', 'profile', 'profile_source', 'case',
        'case_original', 'configuration_id', 'configuration_json',
        'global_handshake_success_evidence', 'statistics_included',
        'statistics_exclusion_reasons', 'check_errors', 'check_warnings',
        'metric_applicability_json', 'absent_source_columns_json']
ALIASES = {'x509': 'x509', 'mtc-standalone': 'standalone',
           'mtc-landmark': 'landmark', 'mtc-simple-standalone': 'standalone',
           'mtc-simple-landmark': 'landmark'}
NULLS = {'', 'null', 'none', 'nan'}

# Internal provenance and validation are retained while calculating statistics.
# Only the anonymous projection below is written to the deliverable files.
REMOVE_COLUMNS = {
    'sample_id', 'source_file', 'source_sha256', 'source_line', 'summary_file',
    'summary_sha256', 'campaign_id', 'campaign_depth_source', 'phase_source',
    'repetition_source', 'profile_source', 'case', 'case_original',
    'configuration_id', 'configuration_json', 'global_handshake_success_evidence',
    'statistics_included', 'statistics_exclusion_reasons', 'check_errors',
    'check_warnings', 'metric_applicability_json', 'absent_source_columns_json',
    'timing_schema_version', 'x509_signatures_scope', 'key_exchange_group', 'depth',
    # Paths and additional identifiers can disclose the execution environment.
    'run_id', 'timestamp', 'result_directory', 'capture_sha256', 'client_random',
    'credential', 'anchor', 'requested_tai', 'selected_tai', 'fixture',
    # Free-text source diagnostics may contain paths or execution identifiers.
    'reason', 'netlog_timing_error', 'analysis_error', 'authentication_components_error',
    # Additional export simplification; validation still uses these internally.
    'mtc_trust_mode', 'standalone_signature_count',
    'x509_signature_cache_ns', 'x509_signature_cache_hits',
    'x509_signature_cache_misses', 'standalone_signature_cache_ns',
    'standalone_signature_cache_hits', 'standalone_signature_cache_misses',
    'mtc_success', 'certificate_verify_algorithm', 'certificate_verify_success',
    'status', 'pair_complete', 'netlog_timing_status', 'analysis_status',
    'authentication_components_status', 'pair', 'pair_index', 'execution_order',
    'order_within_pair', 'tcp_stream', 'connection_count',
    'url_linked_connection_count', 'auxiliary_tls_only_connection_count',
    'aborted_before_tls_completion_connection_count',
}
PUBLIC_CONFIG_FIELDS = [k for k in CONFIG_FIELDS if k not in REMOVE_COLUMNS]
CLIENT_ORDER = ['s_client', 'chromium']
PROFILE_ORDER = ['ecdsa-p256', 'ecdsa-p384', 'ecdsa-p521', 'mldsa44',
                 'mldsa65', 'mldsa87', 'slhdsa128s', 'slhdsa192s', 'slhdsa256s']
CASE_ORDER = ['x509', 'landmark', 'standalone']
STATISTIC_FIELDS = ['mean', 'median', 'stddev', 'min', 'q1', 'q3',
                    'iqr', 'p05', 'p95', 'max']


def statistics_sort_key(row):
    def rank(value, order):
        return (order.index(value) if value in order else len(order), value)
    case = 'x509' if row.get('credential_type') == 'x509' else row.get('mtc_verification_mode', '')
    return (rank(row['client'], CLIENT_ORDER), rank(row['profile'], PROFILE_ORDER),
            rank(case, CASE_ORDER), row.get('configuration_id', ''),
            rank(row['metric'], METRICS))


def public_projection(row):
    return {k: v for k, v in row.items() if k not in REMOVE_COLUMNS}


def missing(v):
    return v is None or str(v).strip().lower() in NULLS


def truth(v):
    return str(v).strip().lower() in {'true', '1'}


def digest(blob):
    return hashlib.sha256(blob).hexdigest()


def numeric(v, where):
    if missing(v):
        return None
    # A non-integer stops export rather than losing its literal original value.
    if not re.fullmatch(r'[+-]?\d+', str(v).strip()):
        raise ValueError(f'{where}: invalid integer ns value/counter: {v!r}')
    return int(v)


def applicability(case, metric):
    if metric in {'handshake_total_ns', 'credential_validation_total_ns',
                  'certificate_verify_crypto_ns', 'auth_total_ns', 'credential_residual_ns'}:
        return 'applicable'
    if case == 'unknown':
        return 'unknown'
    if metric == 'x509_signatures_ns':
        return 'applicable' if case == 'x509' else 'not_applicable'
    if metric == 'landmark_trust_ns':
        return 'applicable' if case == 'landmark' else 'not_applicable'
    if metric == 'standalone_signatures_ns':
        return 'applicable' if case == 'standalone' else 'not_applicable'
    return 'not_applicable' if case == 'x509' else 'applicable'


def check_sample(r):
    errors, warnings = [], []
    case = r['case']
    if case == 'unknown':
        errors.append('unknown_case')
    for k in [*METRICS, *COUNTS, *CACHE]:
        if r.get(k) is not None and r[k] < 0:
            errors.append('negative:'+k)
    for m in METRICS:
        app = applicability(case, m)
        if app == 'not_applicable' and r[m] is not None:
            errors.append('unexpected_nonapplicable_value:'+m)
        elif app == 'applicable' and r[m] is None:
            warnings.append('missing_applicable:'+m)
    def contains(parent, children):
        if all(r[k] is not None for k in [parent, *children]):
            if r[parent] < sum(r[k] for k in children):
                errors.append('containment:'+parent+'<'+ '+'.join(children))
    if case == 'x509':
        contains('credential_validation_total_ns', ['x509_signatures_ns'])
    elif case in {'landmark', 'standalone'}:
        contains('credential_validation_total_ns', ['mtc_total_ns'])
        binding = 'landmark_trust_ns' if case == 'landmark' else 'standalone_signatures_ns'
        contains('mtc_total_ns', ['merkle_total_ns', binding])
        contains('merkle_total_ns', ['merkle_leaf_hash_ns', 'merkle_path_ns'])
    contains('handshake_total_ns', ['auth_total_ns'])
    expected_type = 'x509' if case == 'x509' else 'mtc'
    if r['credential_type'] and r['credential_type'] != expected_type:
        errors.append('credential_type_case_mismatch')
    if case in {'landmark', 'standalone'}:
        for k in ['mtc_verification_mode', 'mtc_trust_mode']:
            if r[k] and r[k] != case:
                errors.append(k+':case_mismatch')
    for mode, key in [('x509', 'x509_signature_count'),
                      ('standalone', 'standalone_signature_count')]:
        if case == mode:
            if r[key] is None:
                warnings.append('missing_counter:'+key)
            elif r[key] == 0:
                warnings.append('zero_counter:'+key)
        elif r[key] is not None:
            errors.append('unexpected_counter:'+key)
    if all(r[k] is None for k in CACHE):
        warnings.append('cache_telemetry_absent_not_zero')
    return errors, warnings


def read_source(path, client):
    blob = path.read_bytes()
    sha = digest(blob)
    reader = csv.DictReader(io.StringIO(blob.decode('utf-8-sig')))
    columns = reader.fieldnames or []
    if len(columns) != len(set(columns)):
        raise ValueError('Duplicate headers: '+str(path))
    summary_path = path.with_name('summary.json')
    summary_blob = summary_path.read_bytes() if summary_path.exists() else b''
    summary = json.loads(summary_blob) if summary_blob else {}
    summary_sha = digest(summary_blob) if summary_blob else ''
    depth = summary.get('depth') if client == 'chromium' else summary.get('x509_trust_path', {}).get('depth_including_root')
    rows, seen = [], set()
    for index, raw in enumerate(reader, 1):
        if None in raw:
            raise ValueError(f'{path}: record {index}: extra columns')
        r = {k: '' if missing(raw.get(k)) else raw[k] for k in META}
        for k in [*TIMES, *COUNTS, *CACHE]:
            r[k] = numeric(raw.get(k), f'{path}:{reader.line_num}:{k}')
        profile_col = 'signature_profile' if client == 'chromium' else 'profile'
        original_case = raw.get('case', '')
        case = 'x509' if re.fullmatch(r'x509-simple-d\d+', original_case) else ALIASES.get(original_case, 'unknown')
        phase_col = 'phase' if 'phase' in columns else None
        phase = raw['phase'] if phase_col else 'measured'
        rep_col = 'repetition' if client == 's_client' else 'pair_index'
        r.update(sample_id=client+':'+sha+':'+str(index), client=client,
                 source_file=str(path.resolve()), source_sha256=sha,
                 source_record=index, source_line=reader.line_num,
                 summary_file=str(summary_path.resolve()) if summary_blob else '',
                 summary_sha256=summary_sha, campaign_id=summary.get('run_id', ''),
                 campaign_depth=depth if depth is not None else '',
                 campaign_depth_source=('summary.depth' if client == 'chromium' else 'summary.x509_trust_path.depth_including_root') if depth is not None else '',
                 phase=phase, phase_source='CSV.phase' if phase_col else 'input_role:measurements.csv (warmups separate)',
                 repetition=raw.get(rep_col, ''), repetition_source='CSV.'+rep_col,
                 profile=raw.get(profile_col, ''), profile_source='CSV.'+profile_col,
                 case=case, case_original=original_case)
        a, b = r['credential_validation_total_ns'], r['certificate_verify_crypto_ns']
        r['auth_total_ns'] = a+b if a is not None and b is not None else None
        # Exclusive components are computed in integer ns per connection,
        # before any summary statistic is calculated. Never clamp negatives.
        def residual(parent, children):
            vals = [r[k] for k in [parent, *children]]
            return vals[0]-sum(vals[1:]) if all(v is not None for v in vals) else None
        r['credential_residual_ns'] = residual('credential_validation_total_ns',
            ['x509_signatures_ns' if case == 'x509' else 'mtc_total_ns'])
        r['mtc_residual_ns'] = residual('mtc_total_ns', ['merkle_total_ns',
            'landmark_trust_ns' if case == 'landmark' else 'standalone_signatures_ns']) if case in {'landmark', 'standalone'} else None
        r['merkle_residual_ns'] = residual('merkle_total_ns',
            ['merkle_leaf_hash_ns', 'merkle_path_ns']) if case in {'landmark', 'standalone'} else None
        r['metric_applicability_json'] = json.dumps({m: applicability(case, m) for m in METRICS}, sort_keys=True)
        r['absent_source_columns_json'] = json.dumps(sorted(set(TIMES+META)-set(columns)))
        errors, warnings = check_sample(r)
        identity = (r['profile'], original_case, phase, r['repetition'], r['run_id'])
        if identity in seen:
            errors.append('duplicate_connection_identity')
        seen.add(identity)
        reasons = []
        if phase != 'measured':
            reasons.append('not_measured_phase')
        if client == 'chromium':
            if raw.get('status') != 'PASS':
                reasons.append('status_not_PASS')
            if not truth(raw.get('pair_complete')):
                reasons.append('pair_not_complete')
            if raw.get('netlog_timing_status') != 'OK' or not missing(raw.get('netlog_timing_error')):
                reasons.append('NetLog_not_OK')
            if not truth(raw.get('certificate_verify_success')):
                reasons.append('CertificateVerify_not_successful')
            if raw.get('analysis_status') != 'OK' or not missing(raw.get('analysis_error')):
                reasons.append('PCAP_NetLog_association_not_OK')
            if raw.get('url_linked_connection_count') != '1':
                reasons.append('not_one_target_connection')
            r['global_handshake_success_evidence'] = 'exporter_status='+r['status']+';CertificateVerify_success='+r['certificate_verify_success']
        else:
            r['global_handshake_success_evidence'] = 'not_available;two_local_authentication_intervals='+str(a is not None and b is not None)
            if a is None or b is None:
                reasons.append('local_authentication_intervals_incomplete')
        if case in {'landmark', 'standalone'} and not truth(raw.get('mtc_success')):
            reasons.append('local_MTC_verification_not_successful')
        if errors:
            reasons.append('consistency_error')
        r['statistics_included'] = int(not reasons)
        r['statistics_exclusion_reasons'] = ';'.join(reasons)
        r['check_errors'] = ';'.join(errors)
        r['check_warnings'] = ';'.join(warnings)
        config = {k: r[k] for k in CONFIG_FIELDS}
        r['configuration_json'] = json.dumps(config, sort_keys=True, separators=(',', ':'))
        r['configuration_id'] = digest(r['configuration_json'].encode())
        rows.append(r)
    return rows, {'path': str(path.resolve()), 'sha256': sha,
                  'summary_path': str(summary_path.resolve()) if summary_blob else '',
                  'summary_sha256': summary_sha, 'columns': columns,
                  'source_rows': len(rows)}


def quantile(sorted_values, p):
    """Hyndman-Fan 7: h=(n-1)p, linear interpolation, p in [0,1]."""
    h = Decimal(len(sorted_values)-1)*p
    i = int(h)
    f = h-i
    lo = Decimal(sorted_values[i])
    return lo if i == len(sorted_values)-1 else lo+f*(Decimal(sorted_values[i+1])-lo)


def describe(values):
    if not values:
        return dict.fromkeys(['mean', 'median', 'stddev', 'min', 'q1', 'q3', 'iqr', 'p05', 'p95', 'max'])
    with localcontext() as ctx:
        ctx.prec = 60
        s = sorted(values)
        n = len(s)
        mean = Decimal(sum(s))/n
        q1, q3 = quantile(s, Decimal('.25')), quantile(s, Decimal('.75'))
        variance = sum((Decimal(v)-mean)**2 for v in s)/(n-1) if n > 1 else None
        return dict(mean=mean, median=quantile(s, Decimal('.5')),
                    stddev=variance.sqrt() if variance is not None else None,
                    min=s[0], q1=q1, q3=q3, iqr=q3-q1,
                    p05=quantile(s, Decimal('.05')), p95=quantile(s, Decimal('.95')), max=s[-1])


def statistics_rows(samples):
    groups = defaultdict(list)
    for r in samples:
        if r['phase'] == 'measured':
            groups[r['configuration_id']].append(r)
    result = []
    for config_id, all_rows in sorted(groups.items()):
        included = [r for r in all_rows if r['statistics_included']]
        first = all_rows[0]
        for m in METRICS:
            values = [r[m] for r in included if r[m] is not None]
            result.append(dict(configuration_id=config_id, client=first['client'],
                profile=first['profile'], case=first['case'], phase='measured',
                configuration_json=first['configuration_json'], metric=m, unit='ns',
                applicability=applicability(first['case'], m),
                n_measured_before_exclusions=len(all_rows), n_excluded=len(all_rows)-len(included),
                n_observations=len(included), n_valid=len(values),
                n_missing=len(included)-len(values), n_zero=values.count(0),
                n_missing_applicable=sum(r[m] is None and applicability(r['case'], m)=='applicable' for r in included),
                n_not_applicable=sum(applicability(r['case'], m)=='not_applicable' for r in included),
                **describe(values)))
    return result


def write_csv(path, rows, columns):
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction='raise')
        writer.writeheader()
        for row in rows:
            # 12 decimal places in ns for statistics; integer samples never pass through float.
            writer.writerow({k: format(v, '.12f') if isinstance(v, Decimal) else v for k, v in row.items()})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--chromium', type=Path, required=True)
    parser.add_argument('--out-dir', type=Path, required=True)
    args = parser.parse_args()
    # Never overwrite either input (including symlink targets).
    inputs = {args.native.resolve(), args.chromium.resolve(),
              args.native.with_name('summary.json').resolve(), args.chromium.with_name('summary.json').resolve()}
    names = ['authentication_samples.csv', 'authentication_statistics.csv', 'authentication_checks.json']
    if any((args.out_dir/n).resolve() in inputs for n in names):
        raise ValueError('An output path matches an input path')
    samples, sources = [], []
    for path, client in [(args.native, 's_client'), (args.chromium, 'chromium')]:
        rows, source = read_source(path, client)
        samples.extend(rows)
        sources.append(source)
    stats = statistics_rows(samples)
    checks = {'samples': len(samples), 'statistics_rows': len(stats),
              'public_configuration_fields': PUBLIC_CONFIG_FIELDS, 'clients': {}}
    for client in ['s_client', 'chromium']:
        rs = [r for r in samples if r['client'] == client]
        checks['clients'][client] = {
            'rows': len(rs), 'phase_counts': dict(Counter(r['phase'] for r in rs)),
            'statistics_included': sum(r['statistics_included'] for r in rs),
            'exclusion_reasons': dict(Counter(x for r in rs for x in r['statistics_exclusion_reasons'].split(';') if x)),
            'errors': dict(Counter(x for r in rs for x in r['check_errors'].split(';') if x)),
            'missing_times': {m: sum(r[m] is None for r in rs) for m in METRICS},
            'signature_counts_by_case': {case: {k: dict(Counter(str(r[k]) for r in rs if r['case']==case)) for k in COUNTS} for case in ['x509', 'landmark', 'standalone']},
            'cache_present': {k: sum(r[k] is not None for r in rs) for k in CACHE}}
    for src in sources:
        if digest(Path(src['path']).read_bytes()) != src['sha256']:
            raise RuntimeError('An input changed during analysis')
        if src['summary_path'] and digest(Path(src['summary_path']).read_bytes()) != src['summary_sha256']:
            raise RuntimeError('A summary changed during analysis')
    args.out_dir.mkdir(parents=True, exist_ok=True)
    public_samples = [public_projection(r) for r in samples]
    # Group using the full private configuration first. Anonymization must not
    # pool configurations simply because their remaining labels are identical.
    configs = {r['configuration_id']: r for r in samples}
    public_stats = []
    for r in stats:
        dimensions = {k: configs[r['configuration_id']][k] for k in PUBLIC_CONFIG_FIELDS}
        exported = public_projection({**dimensions, **r})
        exported.pop('campaign_depth', None)
        for key in STATISTIC_FIELDS:
            if exported[key] is not None:
                exported[key] = format(Decimal(exported[key]), '.2f')
        public_stats.append(exported)
    write_csv(args.out_dir/names[0], public_samples,
              [k for k in [*BASE, *META, *METRICS] if k not in REMOVE_COLUMNS])
    public_stats.sort(key=statistics_sort_key)
    write_csv(args.out_dir/names[1], public_stats, list(public_stats[0]) if public_stats else [])
    (args.out_dir/names[2]).write_text(json.dumps(checks, indent=2, ensure_ascii=False)+'\n')
    print(json.dumps({'samples':len(samples), 'statistics_rows':len(stats),
                      'included':{k:v['statistics_included'] for k,v in checks['clients'].items()}}, indent=2))


if __name__ == '__main__':
    main()
