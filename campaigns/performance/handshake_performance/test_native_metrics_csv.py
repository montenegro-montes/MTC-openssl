#!/usr/bin/env python3
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import native_metrics_csv as metrics


def native(**updates):
    record = {
        "timing_schema_version": 2,
        "tcp_connect_wall_ms_native": 0.5,
        "handshake_wall_ms": 1.5,
        "connection_establishment_wall_ms_native": 2.0,
        "x509_verification_ms": 0.25,
        "credential_verification_total_ms": 0.25,
        "certificate_verify_ms": 0.1,
        "client_authentication_verification_total_ms": 0.35,
    }
    record.update(updates)
    return "NATIVE_METRICS " + json.dumps(record, separators=(",", ":"))


def mtc(mode, **updates):
    record = {
        "timing_schema_version": 2,
        "mtc_credential_auth_ms": 0.2,
        "merkle_proof_ms": 0.01,
        "landmark_validation_ms": 0.02 if mode == "landmark" else None,
        "standalone_validation_ms": 0.03 if mode == "standalone" else None,
        "mtc_verification_mode": mode,
        "mtc_success": True,
    }
    record.update(updates)
    return "MTC_VERIFY " + json.dumps(record, separators=(",", ":"))


class NativeMetricsCsvTests(unittest.TestCase):
    def test_launcher_csv_keeps_historical_order_and_appends_all_v2_fields(self):
        root = Path(__file__).resolve().parents[3]
        launcher = (root / "bin/performance/mt-handshake-performance").read_text()
        header_line = next(
            line for line in launcher.splitlines()
            if line.startswith("  printf 'profile,case,key_establishment"))
        header = header_line.split("'", 2)[1].removesuffix(r"\n")
        fields = header.split(",")
        historical_prefix = [
            "profile", "case", "key_establishment", "openssl_group",
            "phase", "repetition", *metrics.HISTORICAL_FIELDS,
            "process_wall_ms", "tls_bytes_read", "tls_bytes_written",
            "tls_bytes_total",
        ]
        self.assertEqual(fields[:len(historical_prefix)], historical_prefix)
        self.assertEqual(fields[len(historical_prefix):], list(metrics.V2_FIELDS))
        expected_values = len(metrics.HISTORICAL_FIELDS) + len(metrics.V2_FIELDS)
        expected_array = expected_values + 1
        self.assertIn(
            f"-eq {expected_array} && "
            f"${{native_metrics[{expected_array - 1}]}} == __END__",
            launcher)
        self.assertIn(
            f'"${{native_metrics[@]:12:{len(metrics.V2_FIELDS)}}}"',
            launcher)

    def test_x509_positive_accepts_integer_and_decimal_string(self):
        parsed = metrics.parse_native_metrics(native(
            x509_signatures_ns="123", x509_signature_count=2,
            x509_signatures_scope="selected_chain_evp_digest_verify",
            certificate_verify_crypto_ns="45",
            credential_validation_total_ns="200",
            handshake_total_ns=500), "x509-simple-d3")
        self.assertEqual(parsed["timing_schema_version"], 2)
        self.assertEqual(parsed["credential_type"], "x509")
        self.assertEqual(parsed["x509_signatures_ns"], 123)
        self.assertEqual(parsed["x509_signature_count"], 2)
        self.assertEqual(parsed["certificate_verify_crypto_ns"], 45)
        self.assertEqual(parsed["credential_validation_total_ns"], 200)
        self.assertEqual(parsed["handshake_total_ns"], 500)

    def test_landmark_exports_merkle_fields_without_standalone_values(self):
        text = native(credential_validation_total_ns=120,
                      handshake_total_ns=300) + "\n" + mtc(
            "landmark", mtc_total_ns=90, merkle_leaf_hash_ns="10",
            merkle_path_ns=20, merkle_total_ns="35",
            landmark_trust_ns="17")
        parsed = metrics.parse_native_metrics(text, "mtc-simple-landmark")
        self.assertEqual(parsed["mtc_total_ns"], 90)
        self.assertEqual(parsed["merkle_leaf_hash_ns"], 10)
        self.assertEqual(parsed["merkle_path_ns"], 20)
        self.assertEqual(parsed["merkle_total_ns"], 35)
        self.assertEqual(parsed["landmark_trust_ns"], 17)
        self.assertEqual(parsed["credential_type"], "mtc")
        self.assertIsNone(parsed.get("standalone_signatures_ns"))

    def test_historical_verification_mode_name_is_accepted(self):
        historical_mtc = mtc(
            "landmark", mtc_total_ns=90, landmark_trust_ns=17).replace(
                '"mtc_verification_mode":"landmark"',
                '"verification_mode":"landmark"')
        parsed = metrics.parse_native_metrics(
            native(credential_validation_total_ns=120,
                   handshake_total_ns=300) + "\n" + historical_mtc,
            "mtc-simple-landmark")
        self.assertEqual(parsed["mtc_verification_mode"], "landmark")

    def test_landmark_trust_zero_is_not_conflated_with_null(self):
        text = native(credential_validation_total_ns=120,
                      handshake_total_ns=300) + "\n" + mtc(
            "landmark", mtc_total_ns=90, landmark_trust_ns=0)
        parsed = metrics.parse_native_metrics(text, "mtc-simple-landmark")
        row = dict(zip(
            (*metrics.HISTORICAL_FIELDS, *metrics.V2_FIELDS),
            metrics.csv_values(parsed)))
        self.assertEqual(parsed["landmark_trust_ns"], 0)
        self.assertEqual(row["landmark_trust_ns"], "0")

    def test_standalone_exports_signature_and_cache_fields(self):
        text = native(credential_validation_total_ns=1000,
                      handshake_total_ns=1500) + "\n" + mtc(
            "standalone", mtc_total_ns="900", merkle_leaf_hash_ns=10,
            merkle_path_ns="20", merkle_total_ns=35,
            standalone_signatures_ns="700", standalone_signature_count=2,
            standalone_signature_cache_ns="11",
            standalone_signature_cache_hits=1,
            standalone_signature_cache_misses="1")
        parsed = metrics.parse_native_metrics(text, "mtc-simple-standalone")
        self.assertEqual(parsed["credential_type"], "mtc")
        self.assertEqual(parsed["standalone_signatures_ns"], 700)
        self.assertEqual(parsed["standalone_signature_count"], 2)
        self.assertEqual(parsed["standalone_signature_cache_ns"], 11)
        self.assertTrue(parsed["mtc_success"])
        self.assertIsNone(parsed.get("landmark_trust_ns"))

    def test_absent_and_null_fields_produce_empty_cells(self):
        parsed = metrics.parse_native_metrics(
            native(x509_signatures_ns=None), "x509-simple")
        row = dict(zip(
            (*metrics.HISTORICAL_FIELDS, *metrics.V2_FIELDS),
            metrics.csv_values(parsed)))
        self.assertEqual(row["x509_signatures_ns"], "")
        self.assertEqual(row["x509_signature_cache_ns"], "")
        self.assertEqual(row["landmark_trust_ns"], "")

    def test_zero_is_not_conflated_with_null(self):
        parsed = metrics.parse_native_metrics(native(
            x509_signatures_ns=0, x509_signature_count="0",
            x509_signature_cache_ns="0", x509_signature_cache_hits=0,
            x509_signature_cache_misses="0"), "x509-simple")
        row = dict(zip(
            (*metrics.HISTORICAL_FIELDS, *metrics.V2_FIELDS),
            metrics.csv_values(parsed)))
        self.assertEqual(row["x509_signatures_ns"], "0")
        self.assertEqual(row["x509_signature_cache_ns"], "0")

    def test_incompatible_schema_versions_fail(self):
        text = native() + "\n" + mtc(
            "landmark", timing_schema_version=3)
        with self.assertRaisesRegex(ValueError, "incompatible timing_schema_version"):
            metrics.parse_native_metrics(text, "mtc-simple-landmark")

    def test_invalid_unsigned_integer_fails(self):
        with self.assertRaisesRegex(ValueError, "not an unsigned integer"):
            metrics.parse_native_metrics(
                native(x509_signatures_ns="1.5"), "x509-simple")

    def test_interval_containment_is_enforced(self):
        valid = metrics.parse_native_metrics(native(
            x509_signatures_ns=100, x509_signature_count=2,
            certificate_verify_crypto_ns=50,
            credential_validation_total_ns=200,
            handshake_total_ns=500), "x509-simple")
        self.assertEqual(valid["handshake_total_ns"], 500)
        invalid = (
            dict(handshake_total_ns=199, credential_validation_total_ns=200),
            dict(credential_validation_total_ns=99, x509_signatures_ns=100),
            dict(handshake_total_ns=49, certificate_verify_crypto_ns=50),
        )
        for update in invalid:
            with self.subTest(update=update):
                with self.assertRaisesRegex(ValueError, "incoherent timing"):
                    metrics.parse_native_metrics(native(**update), "x509-simple")

    def test_mtc_total_is_contained_by_credential_validation(self):
        text = native(
            credential_validation_total_ns=300,
            handshake_total_ns=500) + "\n" + mtc(
                "landmark", mtc_total_ns=250)
        parsed = metrics.parse_native_metrics(text, "mtc-simple-landmark")
        self.assertEqual(parsed["credential_validation_total_ns"], 300)
        with self.assertRaisesRegex(ValueError, "incoherent timing"):
            metrics.parse_native_metrics(
                native(credential_validation_total_ns=249,
                       handshake_total_ns=500) + "\n" +
                mtc("landmark", mtc_total_ns=250),
                "mtc-simple-landmark")

    def test_historical_records_keep_v2_columns_empty(self):
        old_native = native().replace('"timing_schema_version":2,', "")
        old_mtc = mtc("landmark").replace('"timing_schema_version":2,', "")
        parsed = metrics.parse_native_metrics(
            old_native + "\n" + old_mtc, "mtc-simple-landmark")
        self.assertIsNone(parsed["timing_schema_version"])
        self.assertIsNone(parsed["credential_type"])
        self.assertIsNone(parsed.get("mtc_total_ns"))
        self.assertEqual(parsed["mtc_credential_auth_ms"], 0.2)


if __name__ == "__main__":
    unittest.main()
