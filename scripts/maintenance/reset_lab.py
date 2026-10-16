#!/usr/bin/env python3
"""Discard local laboratory state after explicit confirmation; never run TLS."""
import json
import hashlib
from pathlib import Path
import platform
import re
import shutil
import subprocess

REPO = Path(__file__).resolve().parents[2]
PROJECTS = {'mtlatency', 'mtbandwidth', 'mtloss', 'mtcombined',
            'certchainscaling'}
LINUX_CHROMIUM_POLICY = Path('/etc/chromium/policies/managed/mtc-ca-policy.json')
MACOS_PROFILE_IDENTIFIER = 'org.mtc.chromium.ca.chromium-x509-depth-matrix-v1'


def docker(*args):
    return subprocess.check_output(['docker', *args], text=True).strip()


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def generated_chromium_policies():
    """Return only complete, hash-validated policy packages owned by this lab."""
    packages = []
    for manifest in sorted((REPO / 'artifacts').glob('chromium-ca-policy*/policy-manifest.json')):
        try:
            root = manifest.parent
            data = json.loads(manifest.read_text())
            outputs = data['outputs']
            expected = {'canonical-policy.json', 'linux/mtc-ca-policy.json',
                        'macos/chromium-mtc-ca.mobileconfig'}
            if (data.get('fixture_set') != 'chromium-x509-depth-matrix-v1'
                    or data.get('policy_name') != 'CACertificates'
                    or set(outputs) != expected):
                continue
            paths = {name: root / name for name in expected}
            if any(not path.is_file() or path.is_symlink() for path in paths.values()):
                continue
            if any(sha256(paths[name]) != outputs[name].get('sha256') for name in expected):
                continue
            packages.append(paths)
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            continue
    return packages


def command_output(command):
    return subprocess.run(command, text=True, capture_output=True, check=False)


def installed_chromium_policy(system=None, linux_path=None):
    """Identify only an installed policy matching a validated lab package."""
    packages = generated_chromium_policies()
    if not packages:
        return None
    system = system or platform.system()
    if system == 'Linux':
        installed = Path(linux_path or LINUX_CHROMIUM_POLICY)
        if not installed.is_file() or installed.is_symlink():
            return None
        digest = sha256(installed)
        if any(sha256(p['linux/mtc-ca-policy.json']) == digest for p in packages):
            return {'platform': system, 'path': installed, 'sha256': digest}
    elif system == 'Darwin':
        result = command_output(['profiles', 'show', '-type', 'configuration'])
        listing = (result.stdout or '') + (result.stderr or '')
        if result.returncode == 0 and MACOS_PROFILE_IDENTIFIER in listing:
            return {'platform': system, 'identifier': MACOS_PROFILE_IDENTIFIER}
    return None


def remove_chromium_policy(policy):
    """Remove the exact policy previously identified; never select by a broad pattern."""
    if policy['platform'] == 'Linux':
        path = policy['path']
        if (not path.is_file() or path.is_symlink()
                or sha256(path) != policy['sha256']):
            raise ValueError('Chromium policy changed after inspection; preserved')
        subprocess.run(['sudo', 'rm', '--', str(path)], check=True)
        if path.exists() or path.is_symlink():
            raise OSError('Chromium policy still exists after removal')
    elif policy['platform'] == 'Darwin':
        subprocess.run(['sudo', 'profiles', 'remove', '-forced',
                        '-identifier', policy['identifier']], check=True)
        result = command_output(['profiles', 'show', '-type', 'configuration'])
        listing = (result.stdout or '') + (result.stderr or '')
        if result.returncode == 0 and policy['identifier'] in listing:
            raise OSError('Chromium configuration profile still exists after removal')
    else:
        raise ValueError('Unsupported Chromium policy platform')


def owned(labels):
    project = (labels or {}).get('com.docker.compose.project', '')
    return project in PROJECTS


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
    # Finish Docker discovery before any destructive action; Docker must be reachable.
    containers, networks, volumes = (inventory(k) for k in ('container', 'network', 'volume'))
    images = docker('image', 'ls', '--filter', 'reference=mt-tls-*',
                    '--format', '{{.Repository}}:{{.Tag}}').splitlines()
    images = sorted({x for x in images if x.startswith('mt-tls-') and not x.endswith(':<none>')})
    policy = installed_chromium_policy()
    if policy:
        target = str(policy.get('path') or policy.get('identifier'))
        try:
            remove = input('Chromium certificate policy installed by this laboratory was detected:\n'
                           f'  {target}\nRemove it too? [y/N] ')
        except EOFError:
            remove = ''
        if remove in ('y', 'Y'):
            remove_chromium_policy(policy)
            print('Chromium certificate policy removed.')
        else:
            print('Chromium certificate policy preserved.')
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
    print('Reset complete. No backup created. Run bin/base/mt-prepare init before preparing the laboratory again.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        raise SystemExit(f'Reset failed; some Docker resources may already have been removed. '
                         f'Local deletion starts only after Docker cleanup succeeds. {error}')
