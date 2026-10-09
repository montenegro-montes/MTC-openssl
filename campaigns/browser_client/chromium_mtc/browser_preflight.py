"""Focused helpers for Chromium provenance and optional capture preflight."""
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time


class CaptureCheckError(ValueError):
    def __init__(self, category, message):
        super().__init__(message)
        self.category = category


def build_evidence_problem(state, actual, recorded, pins, current_boringssl):
    """Return why existing build evidence does not bind this exact executable."""
    path = Path(state) / 'build-result.json'
    if not path.is_file():
        return 'missing .mt-state/chromium-mtc/build-result.json from build run chromium'
    import browser_validation as bv
    evidence = bv.read(path)
    expected = {
        'executable': str(Path(actual['executable']).resolve()),
        'executable_sha256': actual['sha256'],
        'chromium_commit': actual['commit'],
        'boringssl_commit': current_boringssl,
        'chromium_tree': pins['CHROMIUM_PATCHED_TREE'],
        'boringssl_tree': pins['BORINGSSL_PATCHED_TREE'],
    }
    for key, value in expected.items():
        observed = evidence.get(key)
        if key == 'executable' and observed:
            observed = str(Path(observed).resolve())
        if observed != value:
            return f'build evidence {key} mismatch'
    if recorded.get('sha256') != actual['sha256']:
        return 'detected executable hash differs from build evidence target'
    return None


def chromium_findings(actual, recorded, pins, current_boringssl, evidence_problem,
                      strict=False):
    """Classify immutable-integrity failures separately from provenance drift."""
    failures, warnings = [], []
    if actual['sha256'] != recorded.get('sha256'):
        failures.append('Executable changed since detection')
    commit_problems = []
    if actual['commit'] != recorded.get('chromium_commit'):
        commit_problems.append('Chromium source commit changed since detection')
    if actual['commit'] != pins['CHROMIUM_PATCHED_COMMIT']:
        commit_problems.append(
            'Unexpected Chromium commit: current=' + actual['commit']
            + ' pinned=' + pins['CHROMIUM_PATCHED_COMMIT'])
    if recorded.get('boringssl_commit') != pins['BORINGSSL_PATCHED_COMMIT']:
        commit_problems.append('Unexpected recorded BoringSSL commit')
    if current_boringssl != recorded.get('boringssl_commit'):
        commit_problems.append('BoringSSL source commit changed since detection')
    if strict:
        failures.extend(commit_problems)
    else:
        warnings.extend(commit_problems)
    if evidence_problem:
        message = ('Executable cannot be verifiably linked to the current source: '
                   + evidence_problem)
        (failures if strict else warnings).append(message)
    return failures, warnings


def capture_command(tools, output):
    interface = tools.get('interface')
    if not interface:
        raise CaptureCheckError('interface', 'capture interface is unavailable on this platform')
    if tools.get('dumpcap'):
        return [tools['dumpcap'], '-i', interface, '-f', 'tcp port 4433',
                '-s', '0', '-w', str(output)]
    if tools.get('tcpdump'):
        return [tools['tcpdump'], '-nn', '-i', interface, '-s', '0',
                '-U', '-w', str(output), 'tcp port 4433']
    raise CaptureCheckError('tool', 'dumpcap/tcpdump is unavailable')


def verify_capture_permissions(tools, startup_timeout=1.0, popen=subprocess.Popen):
    """Prove that capture starts; receiving a packet is deliberately unnecessary."""
    with tempfile.TemporaryDirectory(prefix='chromium-capture-preflight-') as temporary:
        capture = Path(temporary) / 'probe.pcapng'
        command = capture_command(tools, capture)
        try:
            child = popen(command, stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE, text=True,
                          start_new_session=True,
                          env={**os.environ, 'LC_ALL': 'C'})
        except OSError as error:
            raise CaptureCheckError('startup', str(error)) from error
        deadline = time.monotonic() + startup_timeout
        while child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        if child.poll() is None:
            child.send_signal(signal.SIGINT)
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired as error:
                child.kill(); child.wait(timeout=1)
                raise CaptureCheckError('timeout',
                                        'capture process did not stop after startup probe') from error
            return {'status': 'started', 'tool': Path(command[0]).name,
                    'interface': tools['interface']}
        stderr = child.stderr.read() if child.stderr else ''
        if child.returncode == 0:
            return {'status': 'started', 'tool': Path(command[0]).name,
                    'interface': tools['interface']}
        diagnostic = ' '.join(stderr.split())[-500:] or f'exit status {child.returncode}'
        if re.search(r'permission|operation not permitted|not permitted|you don.t have permission',
                     diagnostic, re.I):
            category = 'permission'
        elif re.search(r'no such device|interface.*not found|there is no device',
                       diagnostic, re.I):
            category = 'interface'
        else:
            category = 'startup'
        raise CaptureCheckError(category, diagnostic)
