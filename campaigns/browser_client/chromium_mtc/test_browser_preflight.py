"""Focused preflight policy tests; never starts a real capture."""
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import browser_preflight as bp
import browser_validation as bv


def inputs(**changes):
    actual = dict(executable='/tmp/chrome', sha256='a' * 64, commit='current')
    recorded = dict(executable='/tmp/chrome', sha256='a' * 64,
                    chromium_commit='current', boringssl_commit='boring')
    pins = dict(CHROMIUM_PATCHED_COMMIT='pinned',
                BORINGSSL_PATCHED_COMMIT='boring',
                CHROMIUM_PATCHED_TREE='ctree', BORINGSSL_PATCHED_TREE='btree')
    for key, value in changes.items():
        {'actual': actual, 'recorded': recorded, 'pins': pins}[key].update(value)
    return actual, recorded, pins


class Process:
    def __init__(self, running=True, stderr='', returncode=1):
        self.running = running
        self.stderr = io.StringIO(stderr)
        self.returncode = None if running else returncode
        self.signalled = False

    def poll(self):
        return None if self.running else self.returncode

    def send_signal(self, unused):
        self.signalled = True
        self.running = False
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.running = False
        self.returncode = -9


class BrowserPreflightTests(unittest.TestCase):
    def findings(self, strict=False, problem=None, **changes):
        actual, recorded, pins = inputs(**changes)
        return bp.chromium_findings(
            actual, recorded, pins, 'boring', problem, strict=strict)

    def test_commit_drift_warns_in_development(self):
        failures, warnings = self.findings()
        self.assertFalse(failures)
        self.assertTrue(any('Unexpected Chromium commit' in item
                            for item in warnings))

    def test_commit_drift_fails_in_strict(self):
        failures, warnings = self.findings(strict=True)
        self.assertFalse(warnings)
        self.assertTrue(any('Unexpected Chromium commit' in item
                            for item in failures))

    def test_hash_mismatch_fails_in_both_modes(self):
        for strict in (False, True):
            with self.subTest(strict=strict):
                failures, _ = self.findings(
                    strict=strict, recorded={'sha256': 'b' * 64})
                self.assertIn('Executable changed since detection', failures)

    def test_missing_executable_fails_independently_of_mode(self):
        missing = self.temp_path('missing-chromium')
        for strict in (False, True):
            with self.subTest(strict=strict):
                with self.assertRaises(ValueError):
                    bv.browser_executable(str(missing))

    def temp_path(self, name):
        if not hasattr(self, '_temporary'):
            self._temporary = tempfile.TemporaryDirectory()
            self.addCleanup(self._temporary.cleanup)
        return Path(self._temporary.name) / name

    def test_missing_build_evidence_warns_or_fails(self):
        problem = 'missing build-result.json'
        dev_failures, dev_warnings = self.findings(problem=problem)
        strict_failures, _ = self.findings(strict=True, problem=problem)
        self.assertFalse(dev_failures)
        self.assertTrue(any('verifiably linked' in item for item in dev_warnings))
        self.assertTrue(any('verifiably linked' in item
                            for item in strict_failures))

    def test_normal_preflight_capture_is_conditional(self):
        source = (Path(__file__).resolve().parents[3]
                  / 'bin/browser_client/mt-chromium-tests').read_text()
        self.assertIn('if args.check_capture:', source)
        self.assertIn('[INFO] Capture permissions not tested', source)

    def test_capture_started_without_packets_passes(self):
        process = Process(running=True)
        result = bp.verify_capture_permissions(
            dict(interface='lo0', dumpcap='/usr/bin/dumpcap', tcpdump=None),
            startup_timeout=0, popen=lambda *args, **kwargs: process)
        self.assertEqual(result['status'], 'started')
        self.assertTrue(process.signalled)

    def test_permission_failure_is_classified(self):
        process = Process(running=False, stderr='Permission denied', returncode=1)
        with self.assertRaises(bp.CaptureCheckError) as caught:
            bp.verify_capture_permissions(
                dict(interface='lo0', dumpcap='/usr/bin/dumpcap', tcpdump=None),
                startup_timeout=0, popen=lambda *args, **kwargs: process)
        self.assertEqual(caught.exception.category, 'permission')

    def test_strict_and_capture_checks_are_independent(self):
        failures, _ = self.findings(strict=True)
        self.assertTrue(failures)
        process = Process(running=True)
        self.assertEqual(bp.verify_capture_permissions(
            dict(interface='lo', dumpcap=None, tcpdump='/usr/bin/tcpdump'),
            startup_timeout=0,
            popen=lambda *args, **kwargs: process)['status'], 'started')

    def test_capture_diagnostics_ready_on_linux_and_macos(self):
        for system, interface in (('Linux', 'lo'), ('Darwin', 'lo0')):
            with self.subTest(system=system), patch.object(bp.os, 'access', return_value=True):
                tools = bp.capture_requirements(system=system, which=lambda name: '/bin/'+name)
                result = bp.capture_diagnostics(
                    tools, check_capture=True, interfaces={interface},
                    verifier=lambda unused: {'status': 'started'})
                self.assertEqual(result['category'], 'READY')
                self.assertEqual(result['permissions'], 'PASS')

    def test_missing_required_analyzer_is_specific(self):
        paths = {'dumpcap': '/bin/dumpcap', 'tcpdump': None, 'tshark': None}
        with patch.object(bp.os, 'access', return_value=True):
            tools = bp.capture_requirements(system='Linux', which=paths.get)
            result = bp.capture_diagnostics(tools, interfaces={'lo'})
        self.assertEqual(result['category'], 'MISSING')
        self.assertIn('tshark', result['reason'])
        self.assertEqual(bp.capture_guidance(result, 'Linux'), ['sudo apt install tshark'])

    def test_missing_loopback_is_reported_before_permission_probe(self):
        with patch.object(bp.os, 'access', return_value=True):
            tools = bp.capture_requirements(system='Darwin', which=lambda name: '/bin/'+name)
            result = bp.capture_diagnostics(
                tools, check_capture=True, interfaces=set(),
                verifier=lambda unused: self.fail('capture probe must not run'))
        self.assertEqual(result['category'], 'MISSING')
        self.assertEqual(result['loopback'], 'MISSING')

    def test_permission_and_execution_failures_are_distinct(self):
        with patch.object(bp.os, 'access', return_value=True):
            tools = bp.capture_requirements(system='Linux', which=lambda name: '/bin/'+name)
            for source, expected in (('permission', 'PERMISSION_DENIED'),
                                     ('startup', 'EXECUTION_FAILED')):
                def reject(unused, category=source):
                    raise bp.CaptureCheckError(category, 'probe failed')
                with self.subTest(category=source):
                    result = bp.capture_diagnostics(
                        tools, check_capture=True, interfaces={'lo'}, verifier=reject)
                    self.assertEqual(result['category'], expected)

    def test_measurement_preflight_uses_shared_capture_diagnostics(self):
        source = (Path(__file__).resolve().parents[3]
                  / 'bin/browser_client/mt-chromium-tests').read_text()
        self.assertIn('capture=bp.capture_diagnostics(tools,check_capture=True)', source)
        start = source.index('browser_measurements_prepare() {')
        end = source.index('\n}', start)
        prepare = source[start:end]
        self.assertLess(prepare.index('browser_measurements_environment "$image" "$chromium"'),
                        prepare.index('if [[ "$all_profiles" == true ]]'))


if __name__ == '__main__':
    unittest.main()
