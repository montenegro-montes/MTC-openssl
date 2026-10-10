#!/usr/bin/env python3
"""Focused, side-effect-free checks for the Chromium setup menu."""

from pathlib import Path
import subprocess
import unittest


REPO = Path(__file__).resolve().parents[1]
MENU = REPO / "bin/browser_client/mt-chromium-menu.sh"
SETUP = REPO / "bin/browser_client/mt-chromium-setup"


class ChromiumSetupMenuTests(unittest.TestCase):
    def preparation_menu(self, system, apparmor):
        script = f"""
REPO={str(REPO)!r}
MENU_CALL_DIR={str(REPO)!r}
source {str(MENU)!r}
uname() {{ printf '%s\\n' {system!r}; }}
apparmor_required() {{ return {0 if apparmor else 1}; }}
menu_invoke() {{ :; }}
menu_preparation_run_remaining() {{ :; }}
menu_submenu preparation
"""
        return subprocess.run(
            ["bash", "-c", script], input="0\n", text=True,
            capture_output=True, check=True,
        ).stdout

    def test_macos_hides_apparmor_and_names_xcode_readiness(self):
        output = self.preparation_menu("Darwin", False)
        self.assertIn("Check Xcode / SDK readiness", output)
        self.assertIn("Run all remaining preparation steps", output)
        self.assertNotIn("AppArmor", output)
        self.assertNotIn("Install build dependencies", output)

    def test_linux_with_restricted_userns_shows_apparmor(self):
        output = self.preparation_menu("Linux", True)
        self.assertIn("Install build dependencies", output)
        self.assertIn("Prepare Chromium AppArmor sandbox", output)
        self.assertIn("Check Chromium AppArmor sandbox", output)
        self.assertNotIn("Check Xcode / SDK readiness", output)

    def test_setup_uses_existing_policy_and_credentials_workflows(self):
        source = SETUP.read_text()
        self.assertIn("generate_chromium_ca_policy.py", source)
        self.assertIn("result=bv.chromium_ca_policy(root)", source)
        self.assertIn("browser-validation credentials --all-profiles --depth", source)
        self.assertNotIn("Chromium CA policy instructions", source)


if __name__ == "__main__":
    unittest.main()
