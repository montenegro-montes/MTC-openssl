#!/usr/bin/env python3
import csv
import importlib.util
import sys
import tempfile
import unittest
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import native_verification_plot as plot


def rows(new=True):
    result = []
    for profile in plot.PROFILES:
        for case, source in (("x509", "x509-simple-d3"),
                             ("landmark", "mtc-simple-landmark"),
                             ("standalone", "mtc-simple-standalone")):
            for phase, repetition, delta in (("warmup", "1", 9.0),
                                             ("measured", "1", 0.0),
                                             ("measured", "2", 0.2)):
                merkle = 0.1 if case != "x509" else None
                landmark = 0.2 if case == "landmark" else None
                standalone = 0.3 if case == "standalone" else None
                credential = 1.0 + delta
                row = {
                    "profile": profile, "case": source, "phase": phase,
                    "repetition": repetition,
                    "x509_verification_ms": str(credential),
                    "mtc_credential_auth_ms": "" if case == "x509" else "0.9",
                    "merkle_proof_ms": "" if merkle is None else str(merkle),
                    "landmark_validation_ms": "" if landmark is None else str(landmark),
                    "standalone_validation_ms": "" if standalone is None else str(standalone),
                    "certificate_verify_ms": "0.4",
                }
                if new:
                    row["credential_verification_total_ms"] = str(credential)
                    row["client_authentication_verification_total_ms"] = "1.7"
                result.append(row)
    return result


def write_csv(path, content):
    fields = list(content[0])
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(content)


class NativeVerificationPlotTests(unittest.TestCase):
    def test_source_contract_has_continuous_interval_and_csv_fields(self):
        root = Path(__file__).resolve().parents[3]
        patch = (root / "src/profiling/patch_native_metrics.py").read_text()
        launcher = (root / "bin/performance/mt-handshake-performance").read_text()
        self.assertIn("'ssl_verify_internal'", patch)
        self.assertIn("'tls_process_cert_verify'", patch)
        self.assertIn("mtc_native_authentication_begin", patch)
        self.assertIn("mtc_native_authentication_end", patch)
        self.assertIn("mtc_native_credential_validation_begin", patch)
        self.assertIn("mtc_native_credential_validation_end", patch)
        self.assertIn("mtc_native_credential_validation_snapshot", patch)
        self.assertIn("'MTC_NATIVE_X509_VERIFY',True,True,True)", patch)
        self.assertIn("'MTC_NATIVE_CERTIFICATE_VERIFY',True,True,False", patch)
        components = (root / "src/profiling/native_components.c").read_text()
        self.assertIn("authentication_regions != 2", components)
        self.assertIn("credential_validation_complete", components)
        native_metrics = (root / "src/profiling/native_metrics.c").read_text()
        self.assertIn("credential_validation_total_ns", native_metrics)
        self.assertIn("handshake_total_ns", native_metrics)
        for field in ("credential_verification_total_ms",
                      "client_authentication_verification_total_ms",
                      "credential_verification_other_ms"):
            self.assertIn(field, launcher)

    def test_historical_csv_uses_x509_alias_and_missing_suboperations_as_zero(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "native.csv"
            write_csv(path, rows(new=False))
            medians = plot.load_medians(path)
        self.assertAlmostEqual(medians[("ecdsa-p256", "x509")]["credential_other"], 1.1)
        self.assertAlmostEqual(medians[("ecdsa-p256", "landmark")]["credential_other"], 0.8)
        self.assertIsNone(medians[("ecdsa-p256", "x509")]["authentication_total"])

    def test_components_are_exclusive_and_aliases_are_consistent(self):
        component = plot.row_components(rows(new=True)[4])
        self.assertAlmostEqual(component["credential_other"] + component["merkle"]
                               + component["landmark"] + component["standalone"],
                               component["credential_total"])
        bad = rows(new=True)[0]
        bad["credential_verification_total_ms"] = "2"
        with self.assertRaisesRegex(ValueError, "compatibility alias"):
            plot.row_components(bad)

    def test_negative_residual_warns_and_is_preserved(self):
        row = rows(new=True)[0]
        row.update({"phase": "measured", "x509_verification_ms": "0.1",
                    "credential_verification_total_ms": "0.1",
                    "merkle_proof_ms": "0.2"})
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            value = plot.row_components(row)["credential_other"]
        self.assertAlmostEqual(value, -0.1)
        self.assertTrue(caught)

    def test_unavailable_certificate_verify_is_not_invented_as_zero(self):
        row = rows(new=True)[0]
        row["certificate_verify_ms"] = ""
        with self.assertRaisesRegex(ValueError, "CertificateVerify"):
            plot.row_components(row)

    def test_authentication_total_outliers_use_tukey_iqr(self):
        self.assertEqual(plot._outliers([1.0, 1.0, 1.1, 1.1, 9.0]), [9.0])
        self.assertEqual(plot._outliers([1.0, 2.0, 3.0]), [])

    @unittest.skipUnless(importlib.util.find_spec("matplotlib"),
                         "matplotlib is not installed")
    def test_render_writes_png_and_pdf(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "native.csv"
            write_csv(source, rows(new=True))
            png, pdf = plot.render(source, root / "plots")
            self.assertGreater(png.stat().st_size, 0)
            self.assertGreater(pdf.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()
