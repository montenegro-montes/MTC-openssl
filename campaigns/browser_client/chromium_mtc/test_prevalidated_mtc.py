"""Offline selected-fixture tests; no Docker or Chromium."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import browser_validation as bv


class PrevalidatedMtcTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.fixture = self.root/'fixture'
        self.directory = self.fixture/'batch16/mtc'/bv.PROFILE
        self.directory.mkdir(parents=True)
        key = self.fixture/'population'/bv.PROFILE/'0.key'
        key.parent.mkdir(parents=True)
        key.write_bytes(b'test-key')
        self.image = 'sha256:'+'a'*64
        self.meta = dict(profile=bv.PROFILE, tree_size=16, draft=bv.core.DRAFT,
                         merkle_hash='SHA-256', ca_id='32473.101',
                         provenance=dict(image_id=self.image))
        self.save(self.directory/'manifest.json', self.meta)
        self.save(self.fixture/'manifest.json', dict(server_hostname=bv.HOST,
                  profiles=[bv.PROFILE], sizes=[16], provenance=dict(image_id=self.image)))
        c = bv.core
        validity = c.seq(c.der(24,b'20200101000000Z'),c.der(24,b'20990101000000Z'))
        tbs = c.seq(c.der(0xa0,c.integer(2)), c.integer(1<<48), c.ALG,
                    c.name('32473.101'), validity, c.seq(), c.seq())
        (self.directory/'landmark-0000.pem').write_bytes(c.pem(c.seq(tbs,c.ALG,c.der(3,b'\0'))))
        proof = (c.vec(b'') + c.uint(0, 6) + c.uint(16, 6)
                 + c.vec(b'\0' * 32) + c.vec(b'signature', 3))
        (self.directory/'standalone-0000.pem').write_bytes(
            c.pem(c.seq(tbs, c.ALG, c.der(3, b'\0'+proof))))
        (self.directory/'trust.bin').write_bytes(b'test-trust')
        self.save(self.directory/'fixture-sha256.json', bv.hashes(self.directory))
        self.validation = self.root/'validation.json'
        self.evidence = dict(passed=True, server_hostname=bv.HOST, fixture=str(self.fixture),
                             fixture_hashes=bv.hashes(self.fixture), provenance=dict(image_id=self.image),
                             cells=[dict(profile=bv.PROFILE, tree_size=16, mtc_mode='landmark',
                                         success=True, fixture_hash=bv.sha(self.directory/'manifest.json'),
                                         image_id=self.image, draft=c.DRAFT)])
        self.save(self.validation, self.evidence)
        anchor = dict(
            ca_id='32473.101', log_number=1,
            min_serial=1<<48, max_serial=(1<<48)+15,
            landmark=dict(tree_size=16, requested_trust_anchor_id='32473.101.2.1.1',
                          selected_trust_anchor_id='32473.101.1.1.1'))
        self.enterContext(patch.object(bv, 'parse_landmark', return_value=anchor))
        self.enterContext(patch.object(bv, 'parse_standalone', return_value={
            key: value for key, value in anchor.items() if key != 'landmark'}))
        self.crypto = self.enterContext(patch.object(bv, 'validate_mtc', side_effect=AssertionError('crypto called')))
        self.discovery = self.enterContext(patch.object(bv, 'discover', side_effect=AssertionError('discovery called')))
        self.enterContext(patch.object(bv, 'docker_openssl', side_effect=AssertionError('Docker called')))

    def save(self, path, value):
        path.write_text(json.dumps(value))

    def selected(self):
        return bv.prevalidated_mtc(self.fixture, self.validation)

    def test_valid(self):
        result = self.selected()
        self.assertEqual(result['origin'], 'reused-prevalidated')
        self.assertEqual(result['requested_tai'], '32473.101.2.1.1')
        self.assertEqual(result['validation_sha256'], bv.sha(self.validation))
        self.crypto.assert_not_called()
        self.discovery.assert_not_called()

    def test_explicit_landmark_selects_landmark_credential(self):
        result = bv.prevalidated_mtc(
            self.fixture, self.validation, trust_mode='landmark')
        self.assertEqual(result['mode'], 'landmark')
        self.assertEqual(Path(result['cert']).name, 'landmark-0000.pem')
        self.assertEqual(result['requested_tai'], '32473.101.2.1.1')
        self.assertEqual(result['selected_tai'], '32473.101.1.1.1')

    def test_invalid_trust_mode_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Unsupported MTC trust mode'):
            bv.prevalidated_mtc(
                self.fixture, self.validation, trust_mode='invalid')

    def test_landmark_rejects_incompatible_trust_anchor(self):
        incompatible = dict(
            ca_id='32473.999', log_number=1,
            min_serial=1 << 48, max_serial=(1 << 48) + 15,
            landmark=dict(
                tree_size=16,
                requested_trust_anchor_id='32473.999.2.1.1',
                selected_trust_anchor_id='32473.999.1.1.1'))
        with patch.object(bv, 'parse_landmark', return_value=incompatible):
            with self.assertRaisesRegex(ValueError, 'trust identity mismatch'):
                bv.prevalidated_mtc(
                    self.fixture, self.validation, trust_mode='landmark')

    def test_missing_validation(self):
        self.validation.unlink()
        with self.assertRaises(ValueError): self.selected()

    def test_invalid_evidence(self):
        for change in (dict(passed=False), dict(server_hostname='wrong'),
                       dict(fixture=str(self.root/'other')), dict(cells=[])):
            with self.subTest(change=change):
                self.save(self.validation, {**self.evidence, **change})
                with self.assertRaises(ValueError): self.selected()

    def test_tampered_fixture(self):
        (self.directory/'trust.bin').write_bytes(b'tampered')
        with self.assertRaises(ValueError): self.selected()

    def test_symlink(self):
        key = self.fixture/'population'/bv.PROFILE/'0.key'
        key.rename(self.root/'key')
        key.symlink_to(self.root/'key')
        with self.assertRaises(ValueError): self.selected()

    def test_prepare_explicit_skips_mtc_discovery(self):
        # Stop at the unchanged anchor stage, before X.509 discovery.
        with patch.object(bv, 'choose_anchor', side_effect=RuntimeError('anchor-stage')) as anchor, \
             patch.object(bv, 'select_or_generate', side_effect=AssertionError('selection called')):
            with self.assertRaisesRegex(RuntimeError, 'anchor-stage'):
                bv.prepare_credentials(self.root, self.root, 'image',
                                       mtc_fixture=self.fixture, mtc_validation=self.validation)
        self.assertEqual(anchor.call_args.args[0]['origin'], 'reused-prevalidated')

    def test_standalone_uses_existing_selection(self):
        self.evidence['cells'].append(dict(
            profile=bv.PROFILE, tree_size=16, mtc_mode='standalone',
            success=True, fixture_hash=bv.sha(self.directory/'manifest.json'),
            image_id=self.image, draft=bv.core.DRAFT))
        self.evidence['fixture_hashes'] = bv.hashes(self.fixture)
        self.save(self.validation, self.evidence)
        result = bv.prevalidated_mtc(
            self.fixture, self.validation, trust_mode='standalone')
        self.assertEqual(result['mode'], 'standalone')
        self.assertEqual(Path(result['cert']).name, 'standalone-0000.pem')
        self.assertEqual(result['requested_tai'], '32473.101.2.1.0')
        self.assertEqual(result['selected_tai'], '32473.101')

    def test_requested_tai_matching_is_exact_not_a_ca_id_prefix(self):
        requests = [{'trust_anchor_ids': '32473.101.2.1.0'}]
        self.assertTrue(bv.requested_tai_observed(
            requests, '32473.101.2.1.0'))
        self.assertFalse(bv.requested_tai_observed(requests, '32473.101'))

    def test_standalone_rejects_landmark_only_validation(self):
        with self.assertRaisesRegex(ValueError, 'standalone cell'):
            bv.prevalidated_mtc(
                self.fixture, self.validation, trust_mode='standalone')

    def test_standalone_prepare_is_reuse_only(self):
        with self.assertRaisesRegex(ValueError, 'reuse-only'):
            bv.prepare_credentials(
                self.root, self.root, 'image', mtc_trust_mode='standalone')


if __name__ == '__main__':
    unittest.main()
