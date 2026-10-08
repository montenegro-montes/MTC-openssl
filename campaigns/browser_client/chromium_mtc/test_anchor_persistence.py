"""Fast anchor persistence/discovery tests; no browser, Docker, or fixtures."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bv = load('browser_validation_anchor_persistence_test', 'browser_validation.py')
measurements = load('browser_measurements_anchor_persistence_test', 'browser_measurements.py')


class AnchorPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.fixture = self.repo / 'artifacts/mtc/browser-profile-n16'
        self.fixture.mkdir(parents=True)
        (self.fixture / 'manifest.json').write_text('{}\n')
        self.output = self.repo / 'artifacts/results/run-one'
        self.output.mkdir(parents=True)
        self.mtc = {'fixture': str(self.fixture), 'trust': str(self.fixture / 'trust.bin')}
        self.expected = {'ca_id': '32473.101', 'source': {'trust_file': 'trust.bin'}}
        self.canonical = self.fixture.with_name(self.fixture.name + '-chromium-anchor.json')

    def export(self, arguments, **_kwargs):
        output = Path(arguments[arguments.index('--output') + 1])
        bv.write(output, self.expected)

    def choose(self, output=None):
        with patch.object(bv, 'expected_anchor', return_value=self.expected), \
             patch.object(bv, 'command', side_effect=self.export) as export:
            result = bv.choose_anchor(self.mtc, output or self.output)
        return result, export

    def test_generated_anchor_is_persisted_exactly_and_audit_copy_remains(self):
        result, export = self.choose()
        export.assert_called_once()
        self.assertEqual(bv.read(self.canonical), self.expected)
        self.assertEqual(bv.read(self.output / 'chromium-anchor.json'), self.expected)
        self.assertEqual(result['anchor'], str(self.canonical.resolve()))
        self.assertEqual(result['anchor_origin'], 'generated')

    def test_second_execution_reuses_canonical_without_regeneration(self):
        self.choose()
        second_output = self.repo / 'artifacts/results/run-two'
        second_output.mkdir(parents=True)
        result, export = self.choose(second_output)
        export.assert_not_called()
        self.assertEqual(result['anchor_origin'], 'reused')
        self.assertEqual(result['anchor'], str(self.canonical.resolve()))
        self.assertFalse((second_output / 'chromium-anchor.json').exists())

    def test_mismatched_canonical_anchor_fails_closed_without_overwrite(self):
        wrong = {'wrong': True}
        bv.write(self.canonical, wrong)
        with patch.object(bv, 'expected_anchor', return_value=self.expected), \
             patch.object(bv, 'command') as export:
            with self.assertRaisesRegex(ValueError, 'Canonical Chromium anchor'):
                bv.choose_anchor(self.mtc, self.output)
        export.assert_not_called()
        self.assertEqual(bv.read(self.canonical), wrong)

    def test_measurements_discovers_canonical_after_result_directory_is_removed(self):
        self.choose()
        shutil.rmtree(self.output)
        with patch.object(measurements.bv, 'discover', return_value=(self.mtc.copy(), [])), \
             patch.object(measurements.bv, 'expected_anchor', return_value=self.expected):
            selected = measurements.existing_mtc(self.repo, 'unused-image', 'ecdsa-p256')
        self.assertEqual(selected['anchor'], str(self.canonical.resolve()))

    def test_measurements_does_not_search_results_for_anchor(self):
        decoy = self.repo / 'artifacts/results/old-run/chromium-anchor.json'
        decoy.parent.mkdir(parents=True)
        bv.write(decoy, self.expected)
        with patch.object(measurements.bv, 'discover', return_value=(self.mtc.copy(), [])), \
             patch.object(measurements.bv, 'expected_anchor', return_value=self.expected):
            with self.assertRaisesRegex(ValueError, 'missing exact reusable'):
                measurements.existing_mtc(self.repo, 'unused-image', 'ecdsa-p256')


if __name__ == '__main__':
    unittest.main()
