"""Offline platform routing checks: no browser, Docker, network or build commands."""
import ast
from contextlib import redirect_stdout
import io
import os
import platform
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[3]
LAUNCHER = (REPO/'bin/browser_client/mt-chromium-mtc').read_text()
BUILD = LAUNCHER.split('build_phase() {', 1)[1].split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
DETECT = LAUNCHER.split('10.*) python3', 1)[1].split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]


class Platforms(unittest.TestCase):
    def plan(self, system, machine):
        env = {}
        with patch('sys.argv', ['driver', str(REPO), 'prepare-build', 'plan']), \
             patch('platform.system', return_value=system), patch('platform.machine', return_value=machine), \
             patch('subprocess.run', side_effect=AssertionError('Unexpected execution')), \
             patch('subprocess.check_output', side_effect=AssertionError('Unexpected execution')), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as stop:
                exec(compile(BUILD, 'build_phase', 'exec'), env)
        self.assertEqual(stop.exception.code, 0)
        return env

    def test_linux_build_plan(self):
        env = self.plan('Linux', 'x86_64')
        self.assertIn("target_os = ['linux']", env['layout'])
        self.assertEqual(env['executable'].name, 'chrome')
        self.assertIn('install-build-deps.sh', env['check'][0])
        self.assertEqual(env['steps'][3], '200.check-linux-build-dependencies')

    def test_macos_build_plans(self):
        for arch, cpu in [('arm64', 'arm64'), ('x86_64', 'x64')]:
            with self.subTest(arch=arch):
                env = self.plan('Darwin', arch)
                self.assertIn("target_os = ['mac']", env['layout'])
                self.assertIn('target_cpu = "'+cpu+'"', env['gn_args'])
                self.assertTrue(str(env['executable']).endswith('Chromium.app/Contents/MacOS/Chromium'))
                self.assertEqual(env['steps'][3], '200.check-macos-build-dependencies')
                self.assertEqual(env['build'][-1], 'chrome')
                self.assertEqual(env['check'], ['xcodebuild', '-version'])

    def test_existing_binary_detection(self):
        for system, binary in [('Linux', 'chrome'), ('Darwin', 'Chromium.app/Contents/MacOS/Chromium')]:
            for build_dir in ('mtc', 'mtc-release'):
                with self.subTest(system=system, output=build_dir), tempfile.TemporaryDirectory() as temp:
                    src = Path(temp)/'src'; state = Path(temp)/'state'; state.mkdir()
                    output = src/'out'/build_dir
                    exe = output/binary; exe.parent.mkdir(parents=True)
                    exe.write_text('test placeholder'); exe.chmod(0o700)
                    (output/'args.gn').write_text('is_debug = false\nis_component_build = false\n')
                    env = {}
                    with patch('sys.argv', ['driver', str(src), str(state)]), patch('platform.system', return_value=system), \
                         patch('subprocess.check_output', return_value='test-commit\n'), redirect_stdout(io.StringIO()):
                        exec(compile(DETECT, 'detect', 'exec'), env)
                    self.assertEqual(env['exe'], exe)
                    self.assertFalse(env['d']['is_debug'])

    def test_embedded_python_syntax(self):
        for match in re.finditer(r"<<'PY'\n(.*?)\nPY\n", LAUNCHER, re.S):
            compile(match[1], 'embedded-python', 'exec')

    def test_validation_chooses_native_binary(self):
        source = (REPO/'campaigns/browser_client/chromium_mtc/browser_validation.py').read_text()
        node = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'browser_executable')
        env = dict(Path=Path, os=os, platform=platform, sha=lambda p: 'test-sha',
                   command=lambda *a, **kw: SimpleNamespace(stdout='test-commit'))
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'browser-discovery', 'exec'), env)
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            for name in ('chrome', 'Chromium.app/Contents/MacOS/Chromium'):
                exe = home/'chromium-mtc-rebuild/src/out/mtc-release'/name
                exe.parent.mkdir(parents=True, exist_ok=True); exe.write_text('placeholder'); exe.chmod(0o700)
            for system, name in [('Darwin', 'Chromium'), ('Linux', 'chrome')]:
                with patch.object(Path, 'home', return_value=home), patch('platform.system', return_value=system):
                    self.assertEqual(Path(env['browser_executable']()['executable']).name, name)

    def test_macos_missing_xcode_fails(self):
        env = self.plan('Darwin', 'arm64')
        node = next(n for n in ast.parse(BUILD).body if isinstance(n, ast.FunctionDef) and n.name == 'check_dependencies')
        exec(compile(ast.Module(body=[node], type_ignores=[]), 'dependency-check', 'exec'), env)
        with tempfile.TemporaryDirectory() as temp:
            env.update(state=Path(temp), src=Path(temp), env=dict(os.environ))
            with patch('subprocess.run', side_effect=FileNotFoundError('xcodebuild')):
                with self.assertRaisesRegex(SystemExit, 'Install full Xcode'):
                    env['check_dependencies']()


if __name__ == '__main__':
    unittest.main()
