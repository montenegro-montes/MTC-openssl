"""Tests for the periodic remote RP update service."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import rp_update_service
from landmarks import Landmark, active, encode_publication
from rp_updater import RPHTTPError


class RPUpdateServiceTest(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="mtc-rp-update-service-test-"
        )
        self.root = Path(self.temporary.name)

        self.authority = self.root / "authority.bin"
        self.checker = self.root / "checker"
        self.landmarks = self.root / "landmarks.txt"
        self.state = self.root / "state"

        self.authority.write_bytes(b"authority")
        self.checker.write_bytes(b"checker")

        self.sequence = [
            Landmark(0, 0, 0),
            Landmark(1, 8, 100),
            Landmark(2, 16, 200),
        ]
        self.landmarks.write_bytes(
            encode_publication(self.sequence, 50)
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_landmark_sequence(self):
        sequence = rp_update_service.landmark_sequence(
            self.landmarks, 50
        )

        self.assertEqual(sequence, self.sequence)

    def test_landmark_sequence_uses_supplied_time(self):
        sequence = rp_update_service.landmark_sequence(
            self.landmarks, 50
        )

        self.assertEqual(sequence, self.sequence)
        self.assertEqual(
            [landmark.number for landmark in active(sequence, 50)],
            [1, 2],
        )

    def test_once_success(self):
        original = rp_update_service.update_and_publish_remote

        def fake_update(*args, **kwargs):
            return {
                "checkpoint": {
                    "log_number": 2,
                    "tree_size": 16,
                    "hash": "11" * 32,
                },
                "retained_landmark": None,
            }

        rp_update_service.update_and_publish_remote = fake_update
        output = io.StringIO()

        try:
            with contextlib.redirect_stdout(output):
                result = rp_update_service.main([
                    "--log-url", "http://log:8080",
                    "--rp-url", "http://rp:8082",
                    "--trusted-authority", str(self.authority),
                    "--checker", str(self.checker),
                    "--landmarks", str(self.landmarks),
                    "--state-directory", str(self.state),
                    "--once",
                ])
        finally:
            rp_update_service.update_and_publish_remote = original

        self.assertEqual(result, 0)

        record = json.loads(output.getvalue())
        self.assertEqual(record["result"], "UPDATED")
        self.assertEqual(record["severity"], "PASS")
        self.assertEqual(record["checkpoint"]["tree_size"], 16)

    def test_once_remote_failure(self):
        original = rp_update_service.update_and_publish_remote

        def fail(*args, **kwargs):
            raise RPHTTPError("RP state publication failed")

        rp_update_service.update_and_publish_remote = fail
        output = io.StringIO()

        try:
            with contextlib.redirect_stdout(output):
                result = rp_update_service.main([
                    "--log-url", "http://log:8080",
                    "--rp-url", "http://rp:8082",
                    "--trusted-authority", str(self.authority),
                    "--checker", str(self.checker),
                    "--landmarks", str(self.landmarks),
                    "--state-directory", str(self.state),
                    "--once",
                ])
        finally:
            rp_update_service.update_and_publish_remote = original

        self.assertEqual(result, 1)

        record = json.loads(output.getvalue())
        self.assertEqual(record["result"], "UNAVAILABLE")
        self.assertEqual(record["severity"], "ERROR")


if __name__ == "__main__":
    unittest.main()
