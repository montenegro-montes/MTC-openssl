"""Prepare local, authenticated RP state for a protocol server-pair check."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time

MTC = Path(__file__).resolve().parents[3] / 'src/mtc'
sys.path.insert(0, str(MTC))
from landmarks import Landmark, decode_publication
from local_log import LocalLog
from trusted_subtrees import (build_evidence, encode_trusted_subtrees,
                              validate_trusted_subtrees)


def build_state(fixture, manifest, image):
    """Return validated MTS1 and metadata without writing to the fixture."""
    fixture = Path(fixture).resolve()
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
        raise ValueError('An immutable image ID is required')
    profile = manifest.get('profile', manifest['crypto_family'])
    root_dir = fixture.parents[2]
    transparency = root_dir / 'transparency' / profile
    authority = transparency / 'trusted-authority.bin'
    snapshot = transparency / 'snapshot-n16.mcp2'
    log_dir = transparency / 'persistent-log'
    for path in (authority, snapshot, log_dir, fixture / 'landmarks.txt'):
        if not path.exists():
            raise ValueError(f'Missing RP input: {path}')

    prefix = '/fixture-root/transparency/' + profile
    result = subprocess.run([
        'docker', 'run', '--rm', '--network', 'none',
        '-v', f'{root_dir}:/fixture-root:ro',
        '--entrypoint', '/opt/mtc/check-snapshot', image,
        prefix + '/trusted-authority.bin', prefix + '/snapshot-n16.mcp2',
    ], capture_output=True, text=True, check=True)
    checkpoint = json.loads(result.stdout)
    log = LocalLog(log_dir)
    if (checkpoint['log_number'] != manifest['log_number']
            or checkpoint['tree_size'] != manifest['tree_size']
            or {'tree_size': checkpoint['tree_size'], 'hash': checkpoint['hash']}
               != log.state()):
        raise ValueError('Authenticated checkpoint and local log differ')

    now = int(time.time())
    latest, records = decode_publication((fixture / 'landmarks.txt').read_bytes(), now)
    sequence = list(reversed([
        Landmark(latest - offset, size, expiration)
        for offset, (size, expiration) in enumerate(records)
    ]))
    if (not sequence or sequence[0] != Landmark(0, 0, 0)
            or latest != manifest['latest_landmark']):
        raise ValueError('Landmark publication differs from the fixture')
    trusted = validate_trusted_subtrees(
        checkpoint['log_number'], sequence, now,
        {'tree_size': checkpoint['tree_size'], 'hash': checkpoint['hash']},
        build_evidence(log, sequence, now))
    if trusted.retained_landmark != latest or not trusted:
        raise ValueError('Latest landmark has no validated trusted subtrees')
    return encode_trusted_subtrees(trusted), {
        'log_number': checkpoint['log_number'],
        'retained_landmark': trusted.retained_landmark,
    }


def write_state(destination, mts1, retained):
    generation = Path(destination) / 'generations' / 'validated'
    generation.mkdir(parents=True, exist_ok=False)
    (generation / 'trusted-subtrees.mts1').write_bytes(mts1)
    (generation / 'retained-landmark.json').write_text(
        json.dumps(retained, sort_keys=True, separators=(',', ':')) + '\n')
    return generation / 'trusted-subtrees.mts1'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-dir', type=Path, required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.fixture_dir / 'manifest.json').read_text())
    state, retained = build_state(args.fixture_dir, manifest, args.image)
    path = write_state(args.output, state, retained)
    print(f'PASS: authenticated RP state; retained landmark {retained["retained_landmark"]}')
    print(path)
