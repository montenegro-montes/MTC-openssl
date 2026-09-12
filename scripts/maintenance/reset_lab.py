#!/usr/bin/env python3
"""Discard local laboratory state after explicit confirmation; never run TLS."""
import json
from pathlib import Path
import re
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[2]
PROJECTS = {'mt', 'mtcompact', 'mtprofile', 'mtclab', 'controlledn16',
            'mtscaling', 'mtlatency', 'mtbandwidth', 'mtloss', 'mtcombined',
            'mtcapture', 'certchainscaling'}


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True).strip()


def owned(labels):
    project = (labels or {}).get('com.docker.compose.project', '')
    return project in PROJECTS or re.fullmatch(r'pcmab[0-9a-f]{12}', project) is not None


def inventory(kind):
    args = {'container': ('ps', '-aq'), 'network': ('network', 'ls', '-q'),
            'volume': ('volume', 'ls', '-q')}[kind]
    ids = docker(*args).split()
    if not ids:
        return []
    records = json.loads(docker(kind, 'inspect', *ids))
    return [r['Name'] if kind == 'volume' else r['Id'] for r in records
            if owned(r.get('Config', {}).get('Labels') if kind == 'container' else r.get('Labels'))]


def main():
    print('WARNING: ALL local laboratory data in artifacts/ and .mt-state/ will be lost.\n'
          'This deletes certificates, private keys, fixtures, raw results, logs and progress.\n'
          'Laboratory Docker containers, networks, volumes and mt-tls-* image tags will be removed.\n'
          'NO backup or archive will be created. This cannot be undone.\n'
          'Source code and published results/ are preserved. Shared Docker build cache is preserved.\n'
          'Stop any active campaign processes before continuing.', flush=True)
    try:
        answer = input('Type RESET ALL to confirm: ')
    except EOFError:
        answer = ''
    if answer != 'RESET ALL':
        print('Cancelled; nothing changed.')
        return
    # Finish discovery before any deletion; Docker must be reachable.
    containers, networks, volumes = (inventory(k) for k in ('container', 'network', 'volume'))
    images = docker('image', 'ls', '--filter', 'reference=mt-tls-*',
                    '--format', '{{.Repository}}:{{.Tag}}').splitlines()
    images = sorted({x for x in images if x.startswith('mt-tls-') and not x.endswith(':<none>')})
    for kind, ids in [('container', containers), ('network', networks), ('volume', volumes), ('image', images)]:
        if ids:
            args = [kind, 'rm'] + (['-f'] if kind == 'container' else []) + ids
            docker(*args)
    # No glob expansion or externally supplied paths; symlinks themselves are unlinked.
    for name in ('artifacts', '.mt-state'):
        path = REPO / name
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.exists():
            shutil.rmtree(path)
    print('Reset complete. No backup created. Run mt-campaigns init, then next.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        raise SystemExit(f'Reset failed; some Docker resources may already have been removed. '
                         f'Local deletion starts only after Docker cleanup succeeds. {error}')
