"""Static orchestration tests; setup commands and Docker are never run."""
from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[3]
SETUP = REPO / 'bin/browser_client/mt-chromium-setup'


class SetupAllMtcModesTests(unittest.TestCase):
    def test_all_profiles_prepares_both_modes(self):
        source = SETUP.read_text()
        block = source.split(
            'browser_validation_credentials_all_profiles() {', 1)[1].split(
                '\n}\n\ncase "${1:-help}"', 1)[0]
        self.assertIn('for profile in "${profiles[@]}"', block)
        self.assertIn('for trust_mode in landmark standalone', block)
        self.assertIn('--mtc-trust-mode "$trust_mode"', block)
        self.assertIn('--optimized-all-profiles', block)
        self.assertIn('$((${#profiles[@]}*2))', block)
        self.assertIn('--all-profiles prepares both landmark and standalone',
                      block)

    def test_failure_identifies_profile_and_mode_and_stops(self):
        source = SETUP.read_text()
        block = source.split(
            'browser_validation_credentials_all_profiles() {', 1)[1].split(
                '\n}\n\ncase "${1:-help}"', 1)[0]
        self.assertIn('failed for profile=$profile trust_mode=$trust_mode',
                      block)
        self.assertIn('return "$result"', block)


if __name__ == '__main__':
    unittest.main()
