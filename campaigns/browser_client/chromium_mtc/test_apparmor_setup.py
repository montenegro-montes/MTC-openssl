"""Local AppArmor tests: no sudo, policy loading, or Chromium execution."""
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import apparmor_setup as app


class AppArmorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.chrome = self.root / 'chrome'
        self.chrome.write_text('')
        self.chrome.chmod(0o755)
        self.name, self.content = app.profile_for(self.chrome)
        self.policy = self.root / 'policies'
        self.policy.mkdir()
        self.profiles = self.root / 'profiles'
        self.profiles.write_text(self.name + ' (unconfined)\n')
        self.restriction = self.root / 'restriction'
        self.restriction.write_text('1')
        self.enabled = self.root / 'enabled'
        self.enabled.write_text('Y')
        for key, value in [('POLICY_DIR', self.policy), ('PROFILES', self.profiles),
                           ('RESTRICTION', self.restriction)]:
            self.enterContext(patch.object(app, key, value))

    def invoke(self, action):
        def path(value):
            return self.enabled if str(value) == '/sys/module/apparmor/parameters/enabled' else Path(value)
        with patch.object(app.platform, 'system', return_value='Linux'), \
             patch.object(app.shutil, 'which', return_value='/usr/sbin/apparmor_parser'), \
             patch.object(app, 'Path', side_effect=path), \
             patch('sys.argv', ['apparmor_setup.py', action, str(self.chrome)]), \
             contextlib.redirect_stdout(io.StringIO()):
            app.main()

    def test_status_direct(self):
        (self.policy / self.name).write_text(self.content)
        with patch.object(app, 'run') as run:
            self.invoke('status')
        run.assert_not_called()

    def test_status_sudo(self):
        (self.policy / self.name).write_text(self.content)
        read = Path.read_text
        def restricted(path, *args, **kwargs):
            if path == self.profiles:
                raise PermissionError()
            return read(path, *args, **kwargs)
        with patch.object(Path, 'read_text', restricted), \
             patch.object(app.os, 'geteuid', return_value=1000), \
             patch.object(app.subprocess, 'run', return_value=SimpleNamespace(
                 stdout=self.name + ' (unconfined)\n')) as run:
            self.invoke('status')
        run.assert_called_once_with(
            ['sudo', 'cat', str(self.profiles)], check=True, text=True, capture_output=True)

    def test_no_conflict(self):
        (self.policy / 'foreign').write_text('profile foreign "/another/chrome" {\n}\n')
        app.check_attachments(self.chrome, self.name)

    def test_managed_existing_idempotent(self):
        (self.policy / self.name).write_text(self.content)
        with patch.object(app, 'run') as run:
            self.invoke('setup')
        run.assert_not_called()

    def test_external_attachment(self):
        for header in [
            f'profile chromium-mtc-dev "{self.chrome}" flags=(unconfined)',
            f'profile chromium-mtc-dev {self.chrome}',
            f'"{self.chrome}" flags=(unconfined)',
            f'{self.chrome}',
        ]:
            with self.subTest(header=header):
                (self.policy / 'foreign').write_text(header + ' {\n userns,\n}\n')
                with self.assertRaisesRegex(ValueError, 'conflicting profile attachments'):
                    app.check_attachments(self.chrome, self.name)

    def test_setup_and_status_abort_on_conflict(self):
        (self.policy / 'foreign').write_text(
            f'profile chromium-mtc-dev "{self.chrome}" {{\n userns,\n}}\n')
        for action in ('setup', 'status'):
            with self.subTest(action=action), patch.object(app, 'run') as run:
                with self.assertRaisesRegex(ValueError, 'chromium-mtc-dev') as error:
                    self.invoke(action)
                self.assertIn(str(self.chrome), str(error.exception))
                self.assertIn(str(self.policy / 'foreign'), str(error.exception))
                run.assert_not_called()
                self.assertFalse((self.policy / self.name).exists())


if __name__ == '__main__':
    unittest.main()
