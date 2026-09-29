#!/usr/bin/env python3
"""Explicit, executable-scoped AppArmor userns setup for development Chromium."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import shlex
import shutil
import subprocess
import tempfile

RESTRICTION = Path('/proc/sys/kernel/apparmor_restrict_unprivileged_userns')
PROFILES = Path('/sys/kernel/security/apparmor/profiles')


def profile_for(executable):
    path = str(Path(executable).expanduser().resolve())
    if any(c in path for c in '*?[]{}@"\\') or any(ord(c) < 32 for c in path):
        raise ValueError('Executable path contains unsupported AppArmor pattern characters')
    name = 'mtc-chromium-'+hashlib.sha256(path.encode()).hexdigest()[:16]
    content = ('# Managed by mt-chromium-mtc sandbox-setup; exact executable only.\n'
               'abi <abi/4.0>,\ninclude <tunables/global>\n\n'
               f'profile {name} "{path}" flags=(unconfined) {{\n  userns,\n}}\n')
    return name, content


def run(args, privileged=False, capture=False):
    if privileged and os.geteuid() != 0:
        if not shutil.which('sudo'):
            raise ValueError('Root privileges required; sudo is unavailable. Ask your administrator.')
        args = ['sudo', *args]
    print('RUN: '+shlex.join(map(str, args)), flush=True)
    return subprocess.run(args, check=True, text=True, capture_output=capture)


def loaded(name, privileged=False):
    try:
        text = PROFILES.read_text()
    except PermissionError:
        if not privileged:
            raise ValueError('Cannot read loaded AppArmor profiles. Administrator check: sudo cat '+str(PROFILES))
        text = run(['cat', str(PROFILES)], privileged=True, capture=True).stdout
    return name+' (unconfined)' in text.splitlines()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('setup', 'status'))
    parser.add_argument('executable', type=Path)
    args = parser.parse_args()
    if platform.system() != 'Linux' or not RESTRICTION.exists() or RESTRICTION.read_text().strip() != '1':
        print('NOT REQUIRED: restricted Linux AppArmor user namespaces are not enabled.'); return
    enabled = Path('/sys/module/apparmor/parameters/enabled')
    if not enabled.is_file() or enabled.read_text().strip() != 'Y' or not PROFILES.exists():
        raise ValueError('AppArmor/kernel policy interface unavailable; no security settings changed.')
    executable = args.executable.expanduser().resolve()
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError('Configured Chromium executable missing/not executable: '+str(executable))
    binary = shutil.which('apparmor_parser')
    if binary is None:
        binary = next((str(p) for p in (Path('/usr/sbin/apparmor_parser'), Path('/sbin/apparmor_parser')) if p.is_file() and os.access(p, os.X_OK)), None)
    if binary is None:
        raise ValueError('apparmor_parser missing; install the AppArmor tools through your administrator. No fallback applied.')
    name, content = profile_for(executable)
    target = Path('/etc/apparmor.d')/name
    if target.is_symlink():
        raise ValueError('Symlink policy preserved; administrator inspection required: '+str(target))
    installed = target.is_file() and target.read_text() == content
    active = loaded(name, privileged=args.action == 'setup')
    print(f'Executable: {executable}\nProfile: {target}\nInstalled exact policy: {installed}\nLoaded: {active}')
    if args.action == 'status':
        if not (installed and active):
            raise ValueError('Required policy is not installed/loaded. Run mt-chromium-mtc sandbox-setup.')
        return
    if installed and active:
        print('READY: no changes needed.'); return
    if target.exists() and not installed:
        raise ValueError('Different existing policy preserved; administrator inspection required: '+str(target))
    print('Policy to install/load:\n'+content, flush=True)
    with tempfile.TemporaryDirectory(prefix='mtc-apparmor-') as temp:
        source = Path(temp)/name; source.write_text(content)
        # Compile policy without loading it or reading a stale parser cache.
        run([binary, '-Q', '-T', str(source)])
        if not installed:
            run(['install', '-o', 'root', '-g', 'root', '-m', '0644', str(source), str(target)], privileged=True)
        run([binary, '-r', '-T', str(target)], privileged=True)
    if target.read_text() != content or not loaded(name, privileged=True):
        raise ValueError('Policy installation/load could not be confirmed')
    print('READY: exact Chromium userns policy installed and loaded.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit('ERROR: '+str(error))
