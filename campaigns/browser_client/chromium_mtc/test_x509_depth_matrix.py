"""Small manifest-only tests for the formal Chromium X.509 matrix aggregator."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
