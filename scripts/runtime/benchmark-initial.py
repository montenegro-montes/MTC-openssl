"""Fresh s_client processes; wall time includes startup, TLS, HTTP and shutdown."""
import argparse
import csv
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('--runs', type=int, default=30)
args = parser.parse_args()
if args.runs < 1:
    parser.error('--runs must be positive')
scenario = os.environ.get('SCENARIO', 'classic')
if scenario not in ('classic', 'pq', 'classic-mt', 'pq-mt'):
    parser.error('use classic, pq, classic-mt or pq-mt')
merkle = scenario.endswith('-mt')
cert_scenario = scenario.removesuffix('-mt')
openssl = '/opt/openssl-mt/bin/openssl' if merkle else '/opt/openssl/bin/openssl'
out = Path('/work/results') / (datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '-' + scenario)
out.mkdir(parents=True)
metadata = {'scenario': scenario, 'groups': os.environ.get('GROUPS_TLS', 'X25519'),
            'runs': args.runs, 'metric': 'client_process_http_wall_ms',
            'openssl': subprocess.check_output([openssl, 'version', '-a'], text=True),
            'providers': subprocess.check_output([openssl, 'list', '-providers'], text=True)}
for name, path in [('openssl_commit', '/opt/openssl/SOURCE_COMMIT'), ('liboqs_commit', '/opt/oqs/SOURCE_COMMIT'), ('provider_commit', '/opt/oqs/PROVIDER_COMMIT')]:
    metadata[name] = Path(path).read_text().strip()
metadata['openssl_binary'] = openssl
metadata['merkle_required'] = merkle
if merkle:
    metadata['merkle_patch_sha256'] = Path('/opt/openssl-mt/MERKLE_PATCH_SHA256').read_text().strip()
    import hashlib
    root_path = Path(os.environ.get('MERKLE_ROOT', f'/work/merkle/{cert_scenario}/root.bin'))
    metadata['root_file_sha256'] = hashlib.sha256(root_path.read_bytes()).hexdigest()
(out / 'metadata.json').write_text(json.dumps(metadata, indent=2))
with (out / 'samples.csv').open('w') as stream:
    writer = csv.writer(stream)
    writer.writerow(['run', 'scenario', 'client_process_http_wall_ms', 'handshake_bytes_read', 'handshake_bytes_written', 'leaf_der_bytes'])
    for i in range(args.runs):
        start = time.perf_counter_ns()
        result = subprocess.run(['bash', '/opt/lab/client.sh'], capture_output=True, text=True, timeout=30)
        elapsed = (time.perf_counter_ns() - start) / 1e6
        log = result.stdout + result.stderr
        (out / f'{i:04d}.log').write_text(log)
        match = re.search(r'SSL handshake has read (\d+) bytes and written (\d+) bytes', log)
        if (result.returncode or not match or 'Verify return code: 0 (ok)' not in log
                or 'HTTP/1.0 200' not in log
                or (merkle and 'Merkle verification: OK' not in log)):
            raise SystemExit(f'Failed sample {i}; inspect {out}. No successful row recorded.')
        writer.writerow([i, scenario, f'{elapsed:.6f}', *match.groups(), Path(f'/work/certs/{cert_scenario}/server.der').stat().st_size])
        stream.flush()
print(out)
