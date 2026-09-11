"""Randomized full handshakes; preserve raw samples, bootstrap paired round deltas."""
import argparse
import csv
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import re
import statistics
import subprocess
import time
from scenarios import SCENARIOS, OPENSSL, BATCH, base, client_args

parser = argparse.ArgumentParser()
parser.add_argument('--runs', type=int, default=30)
parser.add_argument('--warmup', type=int, default=3)
parser.add_argument('--seed', type=int, default=42)
parser.add_argument('--host', default=os.environ.get('TLS_HOST', 'server'))
args = parser.parse_args()
if args.runs < 2 or args.warmup < 0: parser.error('runs >= 2, warmup >= 0 required')
output = Path('/work/results') / ('compact-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'))
output.mkdir(parents=True)
(output / 'logs').mkdir()
metadata = {'runs_per_scenario': args.runs, 'warmup_per_scenario': args.warmup, 'seed': args.seed,
            'hostname': args.host, 'platform': platform.platform(), 'cpu_count': os.cpu_count(),
            'scenarios': SCENARIOS, 'batch': str(BATCH), 'openssl_binary': OPENSSL,
            'openssl': subprocess.check_output([OPENSSL, 'version', '-a'], text=True),
            'compact_sha256': Path('/opt/openssl-compact/COMPACT_SHA256').read_text().strip(),
            'phase1_sha256': Path('/opt/openssl-mt/MERKLE_PATCH_SHA256').read_text().strip(),
            'openssl_commit': Path('/opt/openssl/SOURCE_COMMIT').read_text().strip(),
            'phase1_tree_population': 'same batch size and certificates as compact',
            'protocol': 'TLS1.3', 'groups': 'X25519', 'ciphersuite': 'TLS_AES_256_GCM_SHA384',
            'timing_scope': 'HANDSHAKE_START to HANDSHAKE_DONE; excludes process startup and TCP connect',
            'cpu_scope': 'client process CPU during handshake; does not measure server CPU',
            'warm_root_scope': 'root signature verified once at process setup before handshake; setup and full process wall time also recorded'}
metadata['batches'] = {s: json.loads((BATCH / s / 'manifest.json').read_text()) for s in ['classic', 'pq']}
metadata['input_sha256'] = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for s in ['classic', 'pq'] for p in [BATCH/s/'root.signed', BATCH/s/'bundle-0000.bin', BATCH/s/'x509-merkle/root.bin', BATCH/s/'x509-merkle/proof-0000.bin', Path('/work/certs')/s/'server.pem', Path('/work/certs')/s/'ca.pem']}
for name in ['cpu.max', 'memory.max']:
    path = Path('/sys/fs/cgroup') / name
    if path.exists(): metadata[name] = path.read_text().strip()
(output / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
rng = random.Random(args.seed)
rows = []

def sample(scenario, round_number, warmup):
    port = 4433 + SCENARIOS.index(scenario)
    start = time.perf_counter_ns()
    proc = subprocess.run(client_args(scenario, args.host, port), input='GET / HTTP/1.0\r\n\r\n', text=True, capture_output=True, timeout=20)
    elapsed = (time.perf_counter_ns() - start) / 1e6
    log = proc.stdout + proc.stderr
    logname = f'{"warmup" if warmup else "sample"}-{round_number:04d}-{scenario}.log'
    (output/'logs'/logname).write_text(log)
    found = re.findall(r'^LAB_METRICS (\{.*\})$', proc.stderr, re.M)
    if proc.returncode or len(found) != 1 or 'HTTP/1.0 200' not in log:
        raise RuntimeError(f'Failed {scenario}; inspect {output}/logs/{logname}; no summary generated')
    row = json.loads(found[0])
    if row['reused'] or row['server_cert_type'] != (2 if '-compact-' in scenario else 0):
        raise RuntimeError('Unexpected session reuse/certificate type')
    expected = 'Compact verification: OK' if '-compact-' in scenario else ('Merkle verification: OK' if scenario.endswith('-mt') else 'Verify return code: 0 (ok)')
    if expected not in log: raise RuntimeError('Missing authentication confirmation: ' + logname)
    setup = re.findall(r'^COMPACT_SETUP (\{.*\})$', proc.stderr, re.M)
    row.update(scenario=scenario, round=round_number, client_process_http_wall_ms=elapsed,
               compact_setup_ms=json.loads(setup[0])['setup_ms'] if setup else 0,
               transport_total_bytes=row['transport_read_bytes'] + row['transport_written_bytes'])
    return row

for warmup, rounds in [(True, args.warmup), (False, args.runs)]:
    for round_number in range(rounds):
        order = SCENARIOS.copy(); rng.shuffle(order)
        for scenario in order:
            row = sample(scenario, round_number, warmup)
            if not warmup:
                rows.append(row)
                # Save successful raw rows immediately, including on later failure.
                with (output/'samples.csv').open('w', newline='') as stream:
                    writer = csv.DictWriter(stream, fieldnames=list(rows[0])); writer.writeheader(); writer.writerows(rows)
        print(('warmup' if warmup else 'round'), round_number + 1, flush=True)

fields = ['handshake_wall_ms','handshake_client_cpu_ms','transport_total_bytes','certificate_message_bytes',
          'certificate_verify_message_bytes','encrypted_extensions_bytes','compact_setup_ms','client_process_http_wall_ms']
summary = []
for scenario in SCENARIOS:
    group = [r for r in rows if r['scenario'] == scenario]
    result = {'scenario': scenario, 'n': len(group)}
    for field in fields:
        values = [r[field] for r in group]
        result[field + '_median'] = statistics.median(values)
        result[field + '_min'] = min(values); result[field + '_max'] = max(values)
    summary.append(result)
with (output/'summary.csv').open('w', newline='') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(summary[0])); writer.writeheader(); writer.writerows(summary)
# Paired by round; negative deltas mean smaller/faster than the same-key X.509 baseline.
comparison = []
for scenario in SCENARIOS[2:]:
    for field in ['transport_total_bytes','handshake_wall_ms','handshake_client_cpu_ms','client_process_http_wall_ms']:
        other = {r['round']: r[field] for r in rows if r['scenario'] == scenario}
        baseline = {r['round']: r[field] for r in rows if r['scenario'] == base(scenario)}
        deltas = [other[i]-baseline[i] for i in sorted(other)]
        boot = sorted(statistics.median(rng.choices(deltas, k=len(deltas))) for _ in range(2000))
        comparison.append({'scenario': scenario, 'baseline': base(scenario), 'metric': field,
                           'paired_delta_median': statistics.median(deltas), 'bootstrap95_low': boot[49], 'bootstrap95_high': boot[1949]})
with (output/'comparisons.csv').open('w', newline='') as stream:
    writer = csv.DictWriter(stream, fieldnames=list(comparison[0])); writer.writeheader(); writer.writerows(comparison)
report = ['# Exploratory comparison', '', 'One local Docker run; not a final study result. Negative paired deltas favor the variant.', '',
          '| Scenario | TLS bytes (median) | Handshake wall ms | Client handshake CPU ms | Full client + HTTP ms |',
          '|---|---:|---:|---:|---:|']
for row in summary:
    report.append(f"| {row['scenario']} | {row['transport_total_bytes_median']:.0f} | {row['handshake_wall_ms_median']:.3f} | {row['handshake_client_cpu_ms_median']:.3f} | {row['client_process_http_wall_ms_median']:.3f} |")
report += ['', 'See comparisons.csv for paired bootstrap intervals. The warm variant verifies its signed root before the timed handshake; setup cost is recorded separately and remains inside full process time.',
           'Offline timings in metadata are Python/OpenSSL process times and cannot be directly compared with isolated C handshake verification.',
           'Signed-root distribution is included on wire in cold mode and excluded in warm mode; account for cache bootstrap and refresh when reporting deployment savings.']
(output/'report.md').write_text('\n'.join(report)+'\n')
print(output)
