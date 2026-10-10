"""Small manifest-only tests for the formal Chromium X.509 matrix aggregator."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import browser_validation as bv
import generate_x509_depth_matrix as matrix


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n")


class X509DepthMatrixManifestTests(unittest.TestCase):
    def make_family(self, root, profile, index):
        root_hash = hashlib.sha256(f"root-{index}".encode()).hexdigest()
        key_hash = hashlib.sha256(f"key-{index}".encode()).hexdigest()
        spki_hash = hashlib.sha256(f"spki-{index}".encode()).hexdigest()
        cells = []
        for depth in matrix.DEPTHS:
            cert_hash = hashlib.sha256(f"cert-{index}-{depth}".encode()).hexdigest()
            fixture = f"{profile}/d{depth}"
            cell_manifest = dict(
                fixture_set=matrix.FORMAL_FIXTURE_SET, family_id=profile,
                profile=profile, depth=depth, hostname=bv.HOST,
                root_der_sha256=root_hash, server_key_sha256=key_hash,
                server_spki_sha256=spki_hash,
                files_sha256={"server.pem": cert_hash})
            write_json(root/fixture/"manifest.json", cell_manifest)
            cells.append(dict(depth=depth, fixture=fixture,
                root_der_sha256=root_hash, server_key_sha256=key_hash,
                server_spki_sha256=spki_hash, certificate_sha256=cert_hash,
                intermediate_count=depth-2))
        family = dict(fixture_set=matrix.FORMAL_FIXTURE_SET,
            family_id=profile, profile=profile, hostname=bv.HOST,
            depths=list(matrix.DEPTHS), shared_root=True, shared_server_key=True,
            root_der_sha256=root_hash, server_key_sha256=key_hash,
            server_spki_sha256=spki_hash, cells=cells)
        write_json(root/profile/"family-manifest.json", family)

    def test_builds_global_manifest_from_six_family_manifests(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for index, profile in enumerate(bv.PROFILES):
                self.make_family(root, profile, index)
            path = matrix.build_matrix_manifest(root, matrix.FORMAL_FIXTURE_SET)
            data = json.loads(path.read_text())
            self.assertEqual(data["cell_count"], 24)
            self.assertEqual(data["unique_root_count"], 6)
            self.assertEqual(data["unique_server_spki_count"], 6)
            self.assertEqual(list(data["families"]), sorted(bv.PROFILES))
            with self.assertRaisesRegex(ValueError, "already exists"):
                matrix.build_matrix_manifest(root, matrix.FORMAL_FIXTURE_SET)

    def test_rejects_cell_manifest_not_matching_family(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for index, profile in enumerate(bv.PROFILES):
                self.make_family(root, profile, index)
            path = root/bv.PROFILES[0]/"d2/manifest.json"
            cell = json.loads(path.read_text())
            cell["root_der_sha256"] = "0" * 64
            write_json(path, cell)
            with self.assertRaisesRegex(ValueError, "root_der_sha256 mismatch"):
                matrix.build_matrix_manifest(root, matrix.FORMAL_FIXTURE_SET)

    def test_ensure_reuses_valid_requested_fixture(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            output = repo/'artifacts/x509'/matrix.FORMAL_FIXTURE_SET
            output.mkdir(parents=True)
            with mock.patch.object(matrix.bv, 'precheck_formal_x509_fixture'), \
                 mock.patch.object(matrix, 'generate_matrix') as generate:
                matrix.ensure_matrix(repo, output, matrix.FORMAL_FIXTURE_SET,
                                     ['ecdsa-p256'], 3, 'image')
            generate.assert_not_called()

    def test_ensure_generates_absent_matrix_and_validates_selected_profiles(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            output = repo/'artifacts/x509'/matrix.FORMAL_FIXTURE_SET
            checked = []

            def precheck(candidate_repo, profile, depth, fixture_set):
                checked.append((Path(candidate_repo), profile, depth, fixture_set))
                if Path(candidate_repo) == repo:
                    raise ValueError('Missing formal X509 fixture')

            def generate(candidate, fixture_set, image):
                candidate.mkdir(parents=True)
                (candidate/'matrix.json').write_text('{}\n')

            with mock.patch.object(matrix.bv, 'precheck_formal_x509_fixture',
                                   side_effect=precheck), \
                 mock.patch.object(matrix, 'generate_matrix', side_effect=generate) as call:
                matrix.ensure_matrix(repo, output, matrix.FORMAL_FIXTURE_SET,
                                     ['ecdsa-p256', 'ecdsa-p384'], 3, 'image')
            self.assertTrue((output/'matrix.json').is_file())
            call.assert_called_once()
            self.assertEqual([entry[1] for entry in checked[-2:]],
                             ['ecdsa-p256', 'ecdsa-p384'])
            self.assertTrue(all(entry[2] == 3 for entry in checked))

    def test_ensure_preserves_existing_invalid_matrix(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            output = repo/'artifacts/x509'/matrix.FORMAL_FIXTURE_SET
            family = output/'ecdsa-p256'; family.mkdir(parents=True)
            marker = family/'preserved'; marker.write_text('original')
            with mock.patch.object(
                    matrix.bv, 'precheck_formal_x509_fixture',
                    side_effect=ValueError('bad hashes')), \
                 mock.patch.object(matrix, 'generate_matrix') as generate:
                with self.assertRaisesRegex(ValueError, 'profile=ecdsa-p256 depth=3'):
                    matrix.ensure_matrix(repo, output, matrix.FORMAL_FIXTURE_SET,
                                         ['ecdsa-p256'], 3, 'image')
            generate.assert_not_called()
            self.assertEqual(marker.read_text(), 'original')

    def test_ensure_completes_absent_families_without_overwriting(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            output = repo/'artifacts/x509'/matrix.FORMAL_FIXTURE_SET
            output.mkdir(parents=True)

            def precheck(candidate_repo, profile, depth, fixture_set):
                if Path(candidate_repo) == repo and not (output/'matrix.json').exists():
                    raise ValueError('missing family')

            def family(candidate, fixture_set, profile, image):
                (candidate/profile).mkdir(parents=True)

            def manifest(candidate, fixture_set):
                path=candidate/'matrix.json'; path.write_text('{}\n'); return path

            with mock.patch.object(matrix.bv, 'precheck_formal_x509_fixture',
                                   side_effect=precheck), \
                 mock.patch.object(matrix, 'generate_family', side_effect=family) as generate, \
                 mock.patch.object(matrix, 'build_matrix_manifest', side_effect=manifest):
                matrix.ensure_matrix(repo, output, matrix.FORMAL_FIXTURE_SET,
                                     ['ecdsa-p256'], 3, 'image')
            self.assertEqual([call.args[2] for call in generate.call_args_list],
                             list(matrix.bv.PROFILES))
            self.assertTrue((output/'matrix.json').is_file())

    def test_ensure_reports_generation_failure_with_profile_and_depth(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            output = repo/'artifacts/x509'/matrix.FORMAL_FIXTURE_SET
            with mock.patch.object(
                    matrix.bv, 'precheck_formal_x509_fixture',
                    side_effect=ValueError('missing')), \
                 mock.patch.object(matrix, 'generate_matrix',
                                   side_effect=ValueError('generator failed')):
                with self.assertRaisesRegex(
                        ValueError, 'profiles=ecdsa-p256 depth=3.*generator failed'):
                    matrix.ensure_matrix(repo, output, matrix.FORMAL_FIXTURE_SET,
                                         ['ecdsa-p256'], 3, 'image')


if __name__ == "__main__":
    unittest.main()
