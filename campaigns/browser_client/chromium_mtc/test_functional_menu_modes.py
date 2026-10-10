"""Focused interactive-menu tests; commands are printed, never executed."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest


MENU = Path(__file__).resolve().parents[3] / 'bin/browser_client/mt-chromium-menu.sh'


def menu(function, answers=''):
    script = r'''
source "$1"
menu_invoke() { printf 'COMMAND'; printf ' <%s>' "$@"; printf '\n'; }
menu_measurements_run_prepared() {
    printf 'PREPARED'; printf ' <%s>' "$@"; printf '\n';
}
''' + function
    return subprocess.run(
        ['bash', '-c', script, 'menu-test', str(MENU)], input=answers,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=True).stdout


class FunctionalMenuModesTests(unittest.TestCase):
    def run_prepared(self, setup_status=0):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            setup = root / 'bin/browser_client/mt-chromium-setup'
            setup.parent.mkdir(parents=True)
            setup.write_text(
                '#!/usr/bin/env bash\n'
                'printf "setup <%s>\\n" "$*" >> "$COMMAND_LOG"\n'
                f'exit {setup_status}\n')
            setup.chmod(0o755)
            runner = root / 'mt-chromium-tests'
            runner.write_text(
                '#!/usr/bin/env bash\n'
                'printf "campaign <%s>\\n" "$*" >> "$COMMAND_LOG"\n'
                f'exit {setup_status}\n')
            runner.chmod(0o755)
            command_log = root / 'commands.log'
            script = r'''
REPO="$2"
MENU_CALL_DIR="$2"
source "$1"
menu_measurements_run_prepared 3 run --pairs 1 --warmups 1 --all-profiles
'''
            environment = os.environ.copy()
            environment['COMMAND_LOG'] = str(command_log)
            result = subprocess.run(
                ['bash', '-c', script, str(runner), str(MENU), str(root)],
                input='y\n', text=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=environment, check=False)
            commands = command_log.read_text().splitlines()
            return result, commands

    def test_landmark_headless_is_explicit_and_default(self):
        output = menu('menu_mtc_case mtc-positive', '\n1\n')
        self.assertIn('<--mtc-trust-mode> <landmark>', output)
        self.assertIn('<--browser-mode> <headless>', output)

    def test_standalone_headed_is_explicit(self):
        output = menu('menu_mtc_case mtc-positive', '2\n2\n')
        self.assertIn('<--mtc-trust-mode> <standalone>', output)
        self.assertIn('<--browser-mode> <headed>', output)

    def test_back_executes_nothing(self):
        self.assertNotIn('COMMAND', menu('menu_mtc_case mtc-positive', '3\n'))

    def test_x509_has_no_mtc_mode(self):
        output = menu('menu_browser_mode x509-positive', '1\n')
        self.assertIn('<x509-positive>', output)
        self.assertNotIn('mtc-trust-mode', output)

    def test_landmark_run_all_is_explicit(self):
        output = menu('menu_validation_all', '1\n')
        self.assertIn('<run> <all> <--mtc-trust-mode> <landmark>', output)

    def test_incomplete_standalone_or_both_run_all_is_not_started(self):
        for answer in ('2\n', '3\n'):
            with self.subTest(answer=answer):
                output = menu('menu_validation_all', answer)
                self.assertNotIn('COMMAND', output)
                self.assertIn('no incomplete Run all was started', output)

    def test_rp_http_remains_explicitly_landmark(self):
        output = menu(
            'menu_mtc_case mtc-positive --mtc-trusted-subtrees-url '
            'http://127.0.0.1:18083/trusted-subtrees', '1\n')
        self.assertIn('standalone is not supported', output)
        self.assertIn('<--mtc-trust-mode> <landmark>', output)

    def test_standalone_bad_merkle_is_rejected_before_execution(self):
        output = menu('menu_mtc_case mtc-bad-merkle', '2\n')
        self.assertNotIn('COMMAND', output)
        self.assertIn('mutates landmark trusted subtrees', output)

    def test_measurement_summary_is_all_profiles_and_three_scenarios(self):
        output = menu(
            'menu_measurement_summary x25519-mlkem768 3 30 5')
        self.assertIn('Profiles: ALL (5)', output)
        self.assertIn('Scenarios: 3', output)
        self.assertIn('Key establishment: x25519-mlkem768', output)
        self.assertIn('X.509 depth: 3', output)
        self.assertIn('Measured pairs per profile: 30', output)
        self.assertIn('Warmup pairs per profile: 5', output)
        self.assertIn('Total measured runs: 5 × 3 × 30 = 450', output)
        self.assertIn('Total warmup runs: 5 × 3 × 5 = 75', output)
        self.assertIn('Total TLS runs: 525', output)

    def test_measurements_menu_uses_all_profiles_without_profile_selector(self):
        source = MENU.read_text()
        measurement_block = source.split(
            'if [[ "$section" == measurements && "${args[0]}" == run ]]',
            1)[1].split(
                'if [[ "${args[0]}" == sandbox-setup', 1)[0]
        self.assertIn(
            'args+=(--pairs "$pairs" --warmups "$warmups" --all-profiles)',
                      measurement_block)
        self.assertNotIn('--profile', measurement_block)

    def test_measurements_menu_generates_all_profiles_command(self):
        output = menu('menu_submenu measurements', '2\n2\n2\n1\n')
        self.assertIn(
            'PREPARED <3> <run> <--key-establishment> '
            '<x25519-mlkem768> <--depth> <3> <--pairs> <1> '
            '<--warmups> <1> '
            '<--all-profiles>', output)
        self.assertIn('Total measured runs: 5 × 3 × 1 = 15', output)
        self.assertIn('Total warmup runs: 5 × 3 × 1 = 15', output)
        self.assertIn('Total TLS runs: 30', output)

    def test_measurements_menu_assigns_warmups_from_pairs(self):
        cases = (
            ('1', '1', '1', '15'),
            ('2', '30', '5', '450'),
            ('3', '100', '5', '1500'),
        )
        for choice, pairs, warmups, measured in cases:
            with self.subTest(choice=choice):
                output = menu(
                    'menu_submenu measurements',
                    f'2\n1\n1\n{choice}\n')
                self.assertIn(
                    f'<--pairs> <{pairs}>', output)
                self.assertIn(
                    f'<--warmups> <{warmups}>', output)
                self.assertIn(
                    f'Total measured runs: 5 × 3 × '
                    f'{pairs} = {measured}', output)

    def test_measurements_prepare_before_starting_campaign(self):
        result, commands = self.run_prepared()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(commands, [
            'campaign <browser-measurements run --pairs 1 --warmups 1 '
            '--all-profiles>',
        ])
        self.assertIn('performs dependency preparation', result.stdout)

    def test_measurements_do_not_start_after_preparation_failure(self):
        result, commands = self.run_prepared(setup_status=23)
        self.assertEqual(result.returncode, 23)
        self.assertEqual(commands, [
            'campaign <browser-measurements run --pairs 1 --warmups 1 '
            '--all-profiles>',
        ])

    def test_preflight_menu_variants(self):
        expected = {
            '1\n': '<readonly> <preflight>',
            '2\n': '<readonly> <preflight> <--check-capture>',
            '3\n': '<readonly> <preflight> <--strict>',
            '4\n': '<readonly> <preflight> <--strict> <--check-capture>',
        }
        for answers, command in expected.items():
            with self.subTest(answers=answers):
                self.assertIn('COMMAND '+command, menu('menu_preflight', answers))

    def test_preflight_menu_back_executes_nothing(self):
        self.assertNotIn('COMMAND', menu('menu_preflight', '0\n'))


if __name__ == '__main__':
    unittest.main()
