"""Focused offline tests for credential-size accounting."""
import csv
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID

import credential_size_analysis as analysis
import core


class CredentialSizeAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def mtc(self, mode):
        directory = self.root / mode
        directory.mkdir()
        validity = core.seq(core.der(24, b'20200101000000Z'),
                            core.der(24, b'20990101000000Z'))
        tbs = core.seq(core.der(0xa0, core.integer(2)), core.integer(1 << 48),
                       core.ALG, core.name('32473.101'), validity,
                       core.seq(), core.seq())
        path = [b'a' * 32, b'b' * 32]
        signatures = (() if mode == 'landmark' else
                      (('32473.101', b'ca-signature'),
                       ('32473.102', b'cosigner-signature')))
        raw = core.certificate(tbs, core.proof(0, 16, path, signatures))
        credential = directory / f'{mode}-0000.pem'
        credential.write_bytes(core.pem(raw))
        anchor = directory / f'chromium-anchor-{mode}.json'
        anchor.write_text('{"mode":"' + mode + '"}\n')
        return dict(cert=str(credential), anchor=str(anchor),
                    fixture=str(directory)), raw

    def x509_fixture(self):
        fixture = self.root / 'x509'; fixture.mkdir()
        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([x509.NameAttribute(
            NameOID.COMMON_NAME, 'server.mtc.example.com')])
        now = datetime.now(timezone.utc)
        certificate = (x509.CertificateBuilder().subject_name(subject)
                       .issuer_name(issuer).public_key(key.public_key())
                       .serial_number(1).not_valid_before(now - timedelta(days=1))
                       .not_valid_after(now + timedelta(days=1))
                       .sign(key, hashes.SHA256()))
        pem = certificate.public_bytes(Encoding.PEM)
        (fixture / 'server.pem').write_bytes(pem)
        (fixture / 'root.pem').write_bytes(pem)
        (fixture / 'server.key').write_bytes(key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        return fixture

    def assert_partition(self, row):
        self.assertEqual(
            row['credential_bytes'],
            row['cryptographic_signature_bytes']
            + row['public_key_structure_bytes']
            + (row['merkle_inclusion_proof_bytes'] or 0)
            + row['metadata_and_encoding_bytes'])

    def test_components_partition_each_credential_exactly(self):
        x509_row = analysis.analyze_x509('ecdsa-p256', self.x509_fixture())
        landmark, _ = self.mtc('landmark')
        standalone, _ = self.mtc('standalone')
        rows = [x509_row,
                analysis.analyze_mtc('ecdsa-p256', 'mtc-landmark', landmark),
                analysis.analyze_mtc('ecdsa-p256', 'mtc-standalone', standalone)]
        for row in rows:
            self.assert_partition(row)

    def test_merkle_hash_count_is_exact(self):
        for mode in ('landmark', 'standalone'):
            selected, _ = self.mtc(mode)
            row = analysis.analyze_mtc(
                'ecdsa-p256', 'mtc-' + mode, selected)
            self.assertEqual(row['merkle_inclusion_proof_bytes'], 64)
            self.assertEqual(row['merkle_proof_hash_count'], 2)

    def test_landmark_and_standalone_signatures_are_independent(self):
        landmark, _ = self.mtc('landmark')
        standalone, _ = self.mtc('standalone')
        first = analysis.analyze_mtc('ecdsa-p256', 'mtc-landmark', landmark)
        second = analysis.analyze_mtc('ecdsa-p256', 'mtc-standalone', standalone)
        self.assertEqual(first['cryptographic_signature_bytes'], 0)
        self.assertGreater(second['cryptographic_signature_bytes'], 0)

    def test_unavailable_measurement_is_not_estimated(self):
        row = analysis.analyze_x509('ecdsa-p256', self.x509_fixture())
        measurements = self.root / 'measurements.csv'
        with measurements.open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=(
                'signature_profile', 'case', 'status',
                'tls_server_certificate_bytes'))
            writer.writeheader()
        analysis.reconcile([row], measurements)
        self.assertEqual(row['reconciliation_status'], 'unavailable')
        self.assertIsNone(row['tls_server_certificate_bytes'])

    def test_analysis_does_not_modify_fixture(self):
        selected, _ = self.mtc('standalone')
        fixture = Path(selected['fixture'])
        before = {path.relative_to(fixture): hashlib.sha256(path.read_bytes()).hexdigest()
                  for path in fixture.rglob('*') if path.is_file()}
        analysis.analyze_mtc('ecdsa-p256', 'mtc-standalone', selected)
        after = {path.relative_to(fixture): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in fixture.rglob('*') if path.is_file()}
        self.assertEqual(before, after)

    def test_tls_reconciliation_accounts_for_framing(self):
        row = analysis.analyze_x509('ecdsa-p256', self.x509_fixture())
        expected = analysis.tls_certificate_message_bytes(row)
        measurements = self.root / 'measurements.csv'
        with measurements.open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=(
                'signature_profile', 'case', 'status',
                'tls_server_certificate_bytes'))
            writer.writeheader(); writer.writerow(dict(
                signature_profile='ecdsa-p256', case='x509', status='PASS',
                tls_server_certificate_bytes=expected))
        analysis.reconcile([row], measurements)
        self.assertEqual(row['reconciliation_status'], 'reconciled')
        self.assertEqual(row['reconciliation_difference_bytes'], 0)


if __name__ == '__main__':
    unittest.main()
