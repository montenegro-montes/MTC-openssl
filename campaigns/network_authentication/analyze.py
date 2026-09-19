"""Offline paired effects; retains failures and keeps warmups separate."""
import collections
import json
import random
import statistics
from pathlib import Path
from .common import frozen, require, save, sha
from .audit import audit

METRICS = ['client_handshake_wall_ms', 'connection_establishment_wall_ms_native',
           'client_cpu_ms', 'server_cpu_ms', 'certificate_total_bytes',
           'certificate_verify_total_bytes', 'handshake_total_bytes', 'tls_bio_total_bytes']


def effect_summary(values, expected, resamples, seed):
    medians = [statistics.median(v) for v in values.values() if v]
    result = {'campaigns_available': len(medians), 'campaigns_expected': expected,
              'paired_rounds_available': sum(len(v) for v in values.values()),
              'median_campaign_effect': statistics.median(medians) if medians else None,
              'bootstrap95': None}
    # No silent complete-case confidence interval after losing a whole campaign.
    if len(medians) == expected and len(medians) >= 2:
        rng = random.Random(seed)
        draws = sorted(statistics.median(rng.choices(medians, k=len(medians))) for _ in range(resamples))
        result['bootstrap95'] = [draws[int(.025 * (resamples-1))], draws[int(.975 * (resamples-1))]]
    return result


def summarize(rows, spec):
    measured = [r for r in rows if r['phase'] == 'measured']
    by = collections.defaultdict(list)
    lookup = {}
    for r in measured:
        by[(r['condition'], r['case']['id'])].append(r)
        key = (r['campaign'], r['round'], r['case']['id'])
        require(key not in lookup, 'Duplicate observation key')
        lookup[key] = r
    cells = []
    for (condition, case_id), group in sorted(by.items()):
        good = [r for r in group if r['success'] == 1]
        cells.append({'condition': condition, 'case': group[0]['case'], 'attempts': len(group),
                      'successes': len(good), 'failures': len(group)-len(good),
                      'failure_rate': (len(group)-len(good))/len(group),
                      'successful_observation_medians': {m: statistics.median(r[m] for r in good) if good else None for m in METRICS}})
    paired = collections.defaultdict(lambda: collections.defaultdict(list))
    interactions = collections.defaultdict(lambda: collections.defaultdict(list))
    for r in measured:
        c = r['case']
        if c['credential'] != 'mtc-landmark': continue
        baseline_id = f"{c['profile']}-{c['authentication']}-x509-ca-n0"
        b = lookup[(r['campaign'], r['round'], baseline_id)]
        # Keys exist even if no successful pair remains.
        for metric in METRICS:
            key = (r['condition'], c['profile'], c['authentication'], c['tree_size'], metric)
            values = paired[key][r['repetition']]
            if r['success'] == 1 and b['success'] == 1:
                values.append(r[metric] - b[metric])
        if c['authentication'] == 'mutual':
            server_id = f"{c['profile']}-server-only-mtc-landmark-n{c['tree_size']}"
            server_base_id = f"{c['profile']}-server-only-x509-ca-n0"
            so = lookup[(r['campaign'], r['round'], server_id)]
            sb = lookup[(r['campaign'], r['round'], server_base_id)]
            for metric in METRICS:
                key = (r['condition'], c['profile'], c['tree_size'], metric)
                values = interactions[key][r['repetition']]
                if all(x['success'] == 1 for x in [r, b, so, sb]):
                    values.append((r[metric] - b[metric]) - (so[metric] - sb[metric]))
    expected_pairs = spec['campaign_repetitions'] * spec['measured_rounds']
    def report(mapping, keys):
        result = []
        for group, values in sorted(mapping.items()):
            row = dict(zip(keys, group))
            row.update(effect_summary(values, spec['campaign_repetitions'], spec['bootstrap_resamples'], spec['seed']))
            row['paired_rounds_expected'] = expected_pairs
            row['pairs_unavailable'] = expected_pairs - row['paired_rounds_available']
            result.append(row)
        return result
    return {'cells': cells,
            'mtc_minus_x509': report(paired, ['condition', 'profile', 'authentication', 'tree_size', 'metric']),
            'mutual_minus_server_only_interaction': report(interactions, ['condition', 'profile', 'tree_size', 'metric']),
            'interpretation': 'Successful-pair latency is conditional on success. Report failure rates alongside it. '
                              'Campaign-bootstrap intervals are descriptive with five blocks; no multiplicity correction. '
                              'TLS BIO bytes are not retransmitted wire bytes. Landmark trust distribution is external.'}


def analyze(root, output):
    require(not output.exists(), 'Refusing to overwrite analysis')
    require(not output.is_relative_to(root), 'Analysis must be outside the sealed campaign root')
    validation = audit(root)
    manifest = frozen(root)
    rows = []
    for path in (root / 'full').glob('*/observations.jsonl'):
        rows += [json.loads(x) for x in path.read_text().splitlines()]
    result = summarize(rows, manifest['protocol'])
    output.mkdir(parents=True)
    save(output / 'audit.json', validation)
    save(output / 'summary.json', result)
    save(output / 'provenance.json', {'input': str(root), 'manifest_sha256': sha(root / 'manifest.json'),
                                     'full_integrity_sha256': sha(root / 'full/integrity.json')})
    print(output)
