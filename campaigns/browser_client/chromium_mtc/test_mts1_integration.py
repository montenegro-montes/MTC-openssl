"""Focused offline tests for the Chromium MTS1 command-line integration."""

from pathlib import Path
import tempfile
import unittest

import browser_validation as bv


def entry(log_number=1, start=0, end=4, digest=b"\x11" * 32):
    return (log_number.to_bytes(2, "big") + start.to_bytes(6, "big") +
            end.to_bytes(6, "big") + digest)


def mts1(*entries):
    return b"MTS1" + len(entries).to_bytes(2, "big") + b"".join(entries)


class Mts1IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "trusted-subtrees.mts1"

    def validate(self, data, log_number=1):
        self.path.write_bytes(data)
        bv.validate_mts1(self.path, log_number)

    def test_valid_override_is_propagated(self):
        self.validate(mts1(entry()))
        command = bv.browser_command(
            "chrome", self.root / "profile", self.root, self.root / "anchor.json",
            "https://example.test/", trusted_subtrees=self.path,
            mtc_ca=self.root / "mtc-ca.der",
            mtc_ca_root=self.root / "mtc-representation-root.pem")
        self.assertIn("--mtc-plants07-trusted-subtrees=" + str(self.path), command)
        self.assertIn("--mtc-plants07-ca=" + str(self.root / "mtc-ca.der"), command)
        self.assertIn("--mtc-plants07-ca-root=" +
                      str(self.root / "mtc-representation-root.pem"), command)

    def test_absent_override_preserves_fallback(self):
        command = bv.browser_command(
            "chrome", self.root / "profile", self.root, self.root / "anchor.json",
            "https://example.test/", mtc_ca=self.root / "mtc-ca.der",
            mtc_ca_root=self.root / "mtc-representation-root.pem")
        self.assertTrue(any(value.startswith("--mtc-plants07-trust=") for value in command))
        self.assertFalse(any(value.startswith("--mtc-plants07-trusted-subtrees=")
                             for value in command))

    def test_anchor_without_ca_hierarchy_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "requires CA certificate"):
            bv.browser_command(
                "chrome", self.root / "profile", self.root,
                self.root / "anchor.json", "https://example.test/")

    def test_bad_magic(self):
        with self.assertRaisesRegex(ValueError, "magic"):
            self.validate(b"BAD!\x00\x00")

    def test_truncated_or_wrong_length(self):
        for data in (b"MTS1\x00", b"MTS1\x00\x01" + entry()[:-1],
                     b"MTS1\x00\x00\x00"):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                self.validate(data)

    def test_duplicate_interval(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            self.validate(mts1(entry(), entry(digest=b"\x22" * 32)))

    def test_non_power_of_two_interval(self):
        with self.assertRaisesRegex(ValueError, "interval"):
            self.validate(mts1(entry(start=0, end=3)))

    def test_mismatched_log_number(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.validate(mts1(entry(log_number=2)), log_number=1)

    def test_draft07_mtcproof_uses_uint24_signatures_vector(self):
        proof = (
            b"\x00\x00" +
            (0).to_bytes(6, "big") +
            (16).to_bytes(6, "big") +
            b"\x00\x00" +
            b"\x00\x00\x00"
        )

        extensions, pos = bv.take_vector(proof, 0)
        self.assertEqual(extensions, b"")
        start, pos = bv.take_number(proof, pos, 6)
        self.assertEqual(start, 0)
        end, pos = bv.take_number(proof, pos, 6)
        self.assertEqual(end, 16)
        path, pos = bv.take_vector(proof, pos)
        self.assertEqual(path, b"")
        signatures, pos = bv.take_vector(proof, pos, 3)
        self.assertEqual(signatures, b"")
        self.assertEqual(pos, len(proof))

    def test_uint16_mtcproof_signatures_leaves_trailing_byte(self):
        proof = (
            b"\x00\x00" +
            (0).to_bytes(6, "big") +
            (16).to_bytes(6, "big") +
            b"\x00\x00" +
            b"\x00\x00\x00"
        )

        extensions, pos = bv.take_vector(proof, 0)
        self.assertEqual(extensions, b"")
        _, pos = bv.take_number(proof, pos, 6)
        _, pos = bv.take_number(proof, pos, 6)
        _, pos = bv.take_vector(proof, pos)

        # Legacy U16 interprets the first two bytes of the U24 length as
        # zero, leaving the third byte as trailing data.
        _, pos = bv.take_vector(proof, pos)
        self.assertNotEqual(pos, len(proof))


if __name__ == "__main__":
    unittest.main()
