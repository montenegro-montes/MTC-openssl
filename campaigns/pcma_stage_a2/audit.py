"""Fail-closed structural, paired and accounting audit for completed A.2 data."""
import csv
import hashlib
import json
import math
from pathlib import Path
from collections import Counter

from lab import IDENTITY, PAIR, EQUAL, configurations, digest
from workloads import generate


def require(condition, message):
    if not condition:
        raise ValueError('AUDIT FAILED: ' + message)


def audit(directory):
    manifest = json.loads((directory/'manifest.json').read_text())
    require(manifest['format'] == 'pcma-stage-a2-v1', 'not Stage A.2')
    c, configs = manifest['configuration'], manifest['configurations']
    if c['execution'] == 'full':
        require(configs == configurations(c), 'full matrix/seed derivation mismatch')
    else:
        require(c['execution'] == 'single' and len(configs) == 1, 'invalid single configuration')
        require(configs[0]['seed'] == c['base_seed'], 'single seed mismatch')
    schemes = c['schemes']
    require(len(schemes) == len(set(schemes)), 'duplicate requested schemes')
    require(manifest['expected_configurations'] == len(configs)*len(schemes), 'configuration count metadata')
    require(manifest['expected_observations'] == len(configs)*len(schemes)*c['accesses'], 'observation count metadata')
    for name, expected in manifest['output_sha256'].items():
        require(digest(directory/name) == expected, f'output hash: {name}')
    sequences = json.loads((directory/'sequences.json').read_text())
    require(len(sequences) == len(configs), 'sequence count')
    expected = {}
    for cfg, sequence in zip(configs, sequences):
        require(all(sequence[k] == cfg[k] for k in IDENTITY), 'sequence configuration')
        leaves = generate(cfg['workload'], cfg['tree_size'], c['accesses'], cfg['seed'])
        require(sequence['leaves'] == leaves, 'workload/seed mismatch')
        key = tuple(str(cfg[k]) for k in IDENTITY)
        require(key not in expected, 'duplicate configuration')
        expected[key] = leaves
    seen, pairs, counts = set(), {}, Counter()
    with (directory/'observations.csv').open(newline='') as stream:
        for row in csv.DictReader(stream):
            key = tuple(row[k] for k in IDENTITY)
            scheme, t = row['advertisement_scheme'], int(row['access_t'])
            require(key in expected and scheme in schemes, 'unexpected configuration/scheme')
            require(1 <= t <= c['accesses'], 'invalid access position')
            observation = key + (t, scheme)
            require(observation not in seen, 'duplicate observation')
            seen.add(observation)
            counts[key+(scheme,)] += 1
            require(int(row['leaf_id']) == expected[key][t-1], 'leaf/seed consistency')
            signature = tuple(row[k] for k in EQUAL)
            pair = key+(t,)
            if pair in pairs:
                require(pairs[pair] == signature, 'proof/cache state differs across schemes')
            else:
                pairs[pair] = signature
            def num(k):
                v = float(row[k])
                require(math.isfinite(v), 'nonfinite '+k)
                return v
            n, depth = int(row['tree_size']), int(row['normal_proof_hashes'])
            require(n in c['tree_sizes'] and depth == (n-1).bit_length(), 'tree size/depth')
            ad, partial, normal = num('advertisement_bytes'), num('partial_proof_bytes'), num('normal_proof_bytes')
            transmitted, reused = num('transmitted_hashes'), num('reused_hashes')
            require(all(v >= 0 and v.is_integer() for v in (ad, partial, normal, transmitted, reused)) and transmitted+reused == depth, 'invalid sizes/reuse')
            require(normal == 45+32*depth and partial == 46+(depth+7)//8+32*transmitted, 'proof sizes')
            require(num('net_authentication_bytes') == partial+ad, 'net authentication equation')
            saved, gross = normal-partial-ad, normal-partial
            require(num('net_bytes_saved') == saved and num('gross_proof_bytes_saved') == gross, 'saving equations')
            require(math.isclose(num('net_saving_percentage'), 100*saved/normal, abs_tol=1e-9), 'saving percentage')
            count, budget = num('cached_nodes'), num('cache_budget_bytes')
            before = num('advertised_nodes')
            require(all(v >= 0 and v.is_integer() for v in (before, count, budget)), 'invalid cache counts')
            require(num('cache_bytes') == count*69 <= budget, 'post-access cache budget')
            require(num('advertised_cache_bytes') == before*69 <= budget, 'pre-access cache budget')
            require(row['encoding_applicable'] == 'True', 'encoding not applicable')
            if scheme == 'baseline':
                require(ad == 38+5*before, 'PCA1 encoder size')
            for field, denominator, numerator in (
                ('advertisement_bytes_per_cached_node', before, ad),
                ('advertisement_bytes_per_reusable_node', reused, ad),
                ('advertisement_efficiency', ad, gross)):
                require((row[field] == '') if not denominator else math.isclose(num(field), numerator/denominator, abs_tol=1e-9), field)
            for field in ('encode_time_ns', 'decode_time_ns', 'proof_construction_time_ns', 'verification_or_reconstruction_time_ns'):
                require(num(field) >= 0, 'negative timing')
    require(len(counts) == len(configs)*len(schemes), 'missing configurations/schemes')
    require(all(v == c['accesses'] for v in counts.values()), 'incomplete configuration')
    require(len(seen) == manifest['expected_observations'], 'incomplete matrix')
    return dict(status='PASS', configurations=len(counts), observations=len(seen),
                manifest_sha256=digest(directory/'manifest.json'), output_sha256=manifest['output_sha256'])


def compare_stage_a(directory, stage_a):
    """Only label paired after exact per-access identity, state counts and proof checks."""
    am = json.loads((stage_a/'manifest.json').read_text())
    require(am.get('format') == 'pcma-stage-a-matrix-v1', 'comparison requires Stage-A matrix')
    require(digest(stage_a/'observations.csv') == am['observations_sha256'], 'Stage-A CSV hash')
    current = json.loads((directory/'manifest.json').read_text())
    original_fixture = json.loads(Path(am['fixtures']).read_text())
    for n, entry in current['fixtures']['sizes'].items():
        old_entry = original_fixture['sizes'][n]
        for field in ('tree_root_sha256', 'root_signed_sha256'):
            require(entry[field] == old_entry[field], 'Stage-A fixture/root identity')
    with (stage_a/'observations.csv').open(newline='') as f:
        original = {}
        for r in csv.DictReader(f):
            key = (r['tree_size'], r['workload'], r['cache_policy'], r['cache_budget_bytes'], r['random_seed'], r['sequence_position'])
            require(key not in original, 'duplicate Stage-A row')
            original[key] = r
    groups = {}
    with (directory/'observations.csv').open(newline='') as f:
        for row in csv.DictReader(f):
            key = tuple(row[k] for k in PAIR)
            require(key in original, 'Stage-A pairing missing (check full-cache seed offsets)')
            old = original[key]
            for new, previous in [('leaf_id','leaf_id'), ('normal_proof_bytes','normal_proof_bytes'),
                                  ('partial_proof_bytes','pcma_proof_bytes'), ('reused_hashes','reused_hashes'),
                                  ('transmitted_hashes','transmitted_hashes'), ('cached_nodes','cached_nodes'), ('cache_bytes','cache_bytes')]:
                require(row[new] == old[previous], 'Stage-A paired mismatch: '+new)
            require(int(old['state_advertisement_bytes']) == 38+5*int(row['advertised_nodes']), 'Stage-A state count')
            k = tuple(row[x] for x in IDENTITY)+ (row['advertisement_scheme'],)
            g = groups.setdefault(k, [0, 0, 0, 0, 0])
            for i, value in enumerate((1, int(old['state_advertisement_bytes']), int(row['advertisement_bytes']), int(old['net_bytes_saved']), int(row['net_bytes_saved']))):
                g[i] += value
    result = []
    for key, (count, ba, na, bs, ns) in groups.items():
        result.append(dict(zip(IDENTITY+('advertisement_scheme',), key),
                           baseline_advertisement_bytes=ba/count, new_advertisement_bytes=na/count,
                           advertisement_reduction_bytes=(ba-na)/count,
                           advertisement_reduction_percentage=100*(ba-na)/ba if ba else None,
                           baseline_net_bytes_saved=bs/count, new_net_bytes_saved=ns/count,
                           improvement=(ns-bs)/count))
    return result
