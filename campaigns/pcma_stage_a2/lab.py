"""Stage A.2 execution primitives. No campaign executes on import."""
import csv
import datetime
import hashlib
import itertools
import json
from pathlib import Path
import time

from formats import SCHEMES, VERSION, decode, encode
from cache import NodeCache
from core import encode_mtp2, proof_nodes, verify_mtp2
from run import git_commit, load_fixture
from workloads import generate

DEFAULT = Path(__file__).parent / 'configs/default.json'
IDENTITY = ('tree_size', 'workload', 'cache_policy', 'cache_budget_bytes', 'seed')
PAIR = IDENTITY + ('access_t',)
EQUAL = ('leaf_id', 'normal_proof_hashes', 'reused_hashes', 'transmitted_hashes',
         'normal_proof_bytes', 'partial_proof_bytes', 'advertised_nodes',
         'cached_nodes', 'cache_bytes', 'state_sha256', 'partial_proof_sha256')


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def json_write(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')


def csv_write(path, rows):
    rows = iter(rows)
    first = next(rows, None)
    if first is None:
        raise ValueError('refusing empty table')
    with Path(path).open('x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(first))
        writer.writeheader()
        writer.writerow(first)
        writer.writerows(rows)


def config_read(path=DEFAULT):
    c = json.loads(Path(path).read_text())
    allowed = {'tree_sizes': [16, 64, 256, 1024],
               'workloads': ['uniform', 'zipf', 'clustered'],
               'policies': ['lru', 'upper-level'], 'budgets_kb': [0, 1, 2, 4, 8, 16],
               'schemes': list(SCHEMES) + ['trimmed-bitmap']}
    for key, values in allowed.items():
        selected = c[key]
        if not selected or len(selected) != len(set(selected)) or any(v not in values for v in selected):
            raise ValueError(f'invalid {key}')
    if type(c['accesses']) is not int or c['accesses'] < 1 or type(c['base_seed']) is not int:
        raise ValueError('invalid accesses/seed')
    if type(c['stage_a_included_full']) is not bool:
        raise ValueError('stage_a_included_full must be boolean')
    if not 0 < c['material_advertisement_reduction_percent'] <= 100:
        raise ValueError('material reduction must be in (0,100]')
    return c


def stage_a_seed(n, workload, policy, kb, base, included_full=True):
    # Stage A increments ordinal for all 13 variants, including full cache.
    group = [16, 64, 256, 1024].index(n) * 3 + ['uniform', 'zipf', 'clustered'].index(workload)
    variant = ['lru', 'upper-level'].index(policy) * 6 + [0, 1, 2, 4, 8, 16].index(kb)
    return base + group * (13 if included_full else 12) + variant + 1


def configurations(c):
    return [dict(tree_size=n, workload=w, cache_policy=p, cache_budget_bytes=kb * 1024,
                 seed=stage_a_seed(n, w, p, kb, c['base_seed'], c['stage_a_included_full']))
            for n, w, p, kb in itertools.product(c['tree_sizes'], c['workloads'], c['policies'], c['budgets_kb'])]


def observations(credentials, proofs, root, sequence, cfg, schemes):
    """Evaluate all formats on one pre-access state; learn/account exactly once."""
    n = cfg['tree_size']
    cache = NodeCache(cfg['cache_budget_bytes'], cfg['cache_policy'])
    for t, leaf in enumerate(sequence, 1):
        proof = proofs[leaf]
        keys, values = cache.advertised_keys(root), cache.values()
        state_hash = hashlib.sha256(encode('baseline', n, root, keys)).hexdigest()
        pending, expected_partial, expected_authenticated = [], None, None
        for scheme in schemes:
            start = time.perf_counter_ns()
            wire = encode(scheme, n, root, keys)
            enc = time.perf_counter_ns() - start
            start = time.perf_counter_ns()
            available = decode(wire, n, root, scheme)
            dec = time.perf_counter_ns() - start
            if available != frozenset(keys):
                raise RuntimeError('advertisement changed semantic state')
            start = time.perf_counter_ns()
            partial, transmitted = encode_mtp2(proof, available)
            construction = time.perf_counter_ns() - start
            start = time.perf_counter_ns()
            authenticated = verify_mtp2(credentials[leaf], partial, values, root)
            verification = time.perf_counter_ns() - start
            if expected_partial is not None and (partial != expected_partial or authenticated != expected_authenticated):
                raise RuntimeError('proof reuse differs across formats')
            expected_partial, expected_authenticated = partial, authenticated
            depth = len(proof.siblings)
            normal, ad = 45 + 32 * depth, len(wire)
            net, gross = len(partial) + ad, normal - len(partial)
            reused = depth - transmitted
            pending.append(dict(cfg, access_t=t, leaf_id=leaf, advertisement_scheme=scheme,
                encoding_applicable=True, normal_proof_hashes=depth, reused_hashes=reused,
                transmitted_hashes=transmitted, normal_proof_bytes=normal,
                partial_proof_bytes=len(partial), advertisement_bytes=ad,
                net_authentication_bytes=net, gross_proof_bytes_saved=gross,
                net_bytes_saved=normal-net, net_saving_percentage=100*(normal-net)/normal,
                advertised_nodes=len(keys), advertised_cache_bytes=len(keys)*69,
                advertisement_bytes_per_cached_node=ad/len(keys) if keys else None,
                advertisement_bytes_per_reusable_node=ad/reused if reused else None,
                advertisement_efficiency=gross/ad if ad else None,
                encode_time_ns=enc, decode_time_ns=dec, proof_construction_time_ns=construction,
                verification_or_reconstruction_time_ns=verification,
                state_sha256=state_hash, partial_proof_sha256=hashlib.sha256(partial).hexdigest()))
        cache.account(proof_nodes(proof))
        cache.update({k: v for k, v in expected_authenticated.items() if k.level < len(proof.siblings)})
        for row in pending:
            row.update(cached_nodes=len(cache.values()), cache_bytes=cache.bytes)
            yield row


def fixture_identity(path, sizes):
    data = json.loads(path.read_text())
    identity = {'manifest_path': str(path.resolve()), 'manifest_sha256': digest(path), 'sizes': {}}
    for n in sizes:
        entry = data['sizes'][str(n)]
        directory = Path(entry['directory'])
        files = [directory / 'root.signed'] + [directory / f'{kind}-{i:04d}.bin' for i in range(n) for kind in ('credential', 'proof')]
        hashes = {p.name: digest(p) for p in files}
        if hashes['root.signed'] != entry['root_signed_sha256']:
            raise ValueError('signed-root fixture digest mismatch')
        identity['sizes'][str(n)] = dict(entry, file_sha256=hashes)
    return identity


def execute(output, fixtures, c, configs):
    if output.exists():
        raise FileExistsError('output exists; select a new directory')
    identity = fixture_identity(fixtures, sorted({x['tree_size'] for x in configs}))
    output.mkdir(parents=True, exist_ok=False)
    sequences = []
    def rows():
        loaded = {}
        for cfg in configs:
            n = cfg['tree_size']
            if n not in loaded:
                loaded[n] = load_fixture(fixtures, n)
            seq = generate(cfg['workload'], n, c['accesses'], cfg['seed'])
            sequences.append(dict(cfg, leaves=seq))
            yield from observations(*loaded[n], seq, cfg, c['schemes'])
    csv_write(output / 'observations.csv', rows())
    json_write(output / 'sequences.json', sequences)
    manifest = dict(format='pcma-stage-a2-v1', protocol_version='MTP2+PCA1/PCA2',
                    advertisement_format_version=VERSION, created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    git_commit=git_commit(), configuration=c, configurations=configs,
                    expected_configurations=len(configs)*len(c['schemes']),
                    expected_observations=len(configs)*len(c['schemes'])*c['accesses'],
                    fixtures=identity, timing='diagnostic Python nanoseconds',
                    privacy=json.loads((Path(__file__).parent/'configs/privacy.json').read_text()),
                    source_sha256={str(p.relative_to(Path(__file__).resolve().parents[2])): digest(p)
                                   for directory in (Path(__file__).parent, Path(__file__).parent.parent/'pcma')
                                   for p in sorted(directory.glob('*.py'))},
                    output_sha256={name: digest(output/name) for name in ('observations.csv', 'sequences.json')})
    json_write(output/'manifest.json', manifest)
    return manifest
