#!/usr/bin/env python3
"""Resolve chain cells without generating certificates in the measurement driver."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys

REPO = Path(__file__).resolve().parents[3]
CHAIN = REPO / 'campaigns/scaling/cert_chain_scaling'
sys.path.insert(0, str(CHAIN))
from result_state import validate_fixture


def requirements(profiles, depths, mutual):
    # D=2 retains the existing population and mutual credentials.
    return [(profile, depth, role) for depth in depths if depth > 2
            for role in (('server', 'client') if mutual else ('server',))
            for profile in profiles]


def check_cell(directory, profile, depth, role):
    validate_fixture(directory, profile, depth)
    meta = json.loads((directory / 'manifest.json').read_text())
    if meta.get('role', 'server') != role:
        raise ValueError('certificate role mismatch')
    names = ['root.pem', 'server.pem', 'server.key', 'intermediates.pem', 'server-chain.pem']
    if not all(name in meta['files_sha256'] for name in names):
        raise ValueError('incomplete fixture hashes')
    def certs(name):
        return re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',
                          (directory / name).read_bytes(), re.S)
    root, leaf, intermediates, chain = map(certs, ('root.pem', 'server.pem', 'intermediates.pem', 'server-chain.pem'))
    if not (len(root) == len(leaf) == 1 and len(intermediates) == depth - 2
            and chain == leaf + intermediates and root[0] not in chain
            and meta['transmitted_certificates'] == depth - 1 and meta['root_transmitted'] is False):
        raise ValueError('invalid depth/transmitted chain')


def resolve(profiles, depths, mutual, preferred=None, execute=False, image='mt-tls-mtc:local'):
    bindings = []
    # Search manifests only; never repair, overwrite or trust partial outputs.
    candidates = sorted((REPO / 'artifacts').glob('**/depth-*/manifest.json'), reverse=True)
    for profile, depth, role in requirements(profiles, depths, mutual):
        selected = None
        paths = [p.parent for p in candidates if p.parent.name == f'depth-{depth}' and p.parent.parent.name == profile]
        if preferred and role == 'server':
            paths = [preferred / profile / f'depth-{depth}']
        for directory in paths:
            try:
                if not directory.resolve().is_relative_to((REPO / 'artifacts').resolve()):
                    raise ValueError('chain escapes artifacts')
                check_cell(directory, profile, depth, role)
            except (OSError, ValueError, KeyError, TypeError):
                continue
            selected = directory
            break
        label = f'X.509 {role} {profile} D={depth}'
        print(f'  {label}: {"FOUND" if selected else "MISSING"}', file=sys.stderr, flush=True)
        if selected is None and execute:
            if preferred and role == 'server':
                raise ValueError(f'explicit chain override invalid: {paths[0]}; preserved for inspection')
            stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
            root = REPO / f'artifacts/fixtures/handshake-chain-{role}-{stamp}'
            selection = ['--profile', profile, '--depth', str(depth), '--role', role, '--image', image]
            print(f'  {label}: PREPARING', file=sys.stderr, flush=True)
            subprocess.run([sys.executable, str(CHAIN / 'generate_fixtures.py'), '--output', str(root), *selection],
                           check=True, stdout=sys.stderr)
            print(f'  {label}: VALIDATING', file=sys.stderr, flush=True)
            report = REPO / f'artifacts/results/handshake-chain-{role}-{stamp}/validation.json'
            subprocess.run([sys.executable, str(CHAIN / 'validate.py'), str(root), '--output', str(report), *selection],
                           check=True, stdout=sys.stderr)
            if json.loads(report.read_text()).get('passed') is not True:
                raise ValueError(f'{label}: validation did not PASS')
            selected = root / profile / f'depth-{depth}'
            check_cell(selected, profile, depth, role)
            print(f'  {label}: PASS', file=sys.stderr, flush=True)
        if selected:
            bindings.append(f'{profile}|{depth}|{role}|{selected.relative_to(REPO)}')
    return bindings


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--profile', nargs='+', required=True)
    p.add_argument('--depth', nargs='+', type=int, choices=range(2, 6), required=True)
    p.add_argument('--mutual', action='store_true')
    p.add_argument('--preferred', type=Path)
    p.add_argument('--execute', action='store_true')
    p.add_argument('--image', default='mt-tls-mtc:local')
    args = p.parse_args()
    try:
        preferred = (REPO / args.preferred) if args.preferred else None
        print('\n'.join(resolve(args.profile, args.depth, args.mutual, preferred, args.execute, args.image)))
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        p.exit(1, f'ERROR: dependency preparation failed: {error}. No measurements started.\n')


if __name__ == '__main__':
    main()
