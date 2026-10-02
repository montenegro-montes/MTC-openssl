"""Focused offline tests for the one-shot HTTP log Chromium bridge."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import http_log_integration as bridge
import rp_updater
from rp_state import RPStateStore
from trusted_subtrees import TrustedSubtree, encode_trusted_subtrees


class HttpLogIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_landmark_publication_must_reach_zero(self):
        complete = self.root / "complete.txt"
        complete.write_bytes(b"1\n16 200\n0 0\n")
        self.assertEqual([item.tree_size for item in bridge.read_landmark_sequence(complete, 100)],
                         [0, 16])
        partial = self.root / "partial.txt"
        partial.write_bytes(b"2\n16 200\n8 50\n")
        with self.assertRaisesRegex(ValueError, "landmark zero"):
            bridge.read_landmark_sequence(partial, 100)

    def test_rp_state_must_start_empty(self):
        state = self.root / "state"
        state.mkdir()
        self.assertEqual(bridge.require_empty_rp_state(state), state.resolve())
        (state / "unexpected").write_text("x")
        with self.assertRaisesRegex(ValueError, "start empty"):
            bridge.require_empty_rp_state(state)

    def test_one_update_records_http_and_publishes_one_generation(self):
        state = bridge.require_empty_rp_state(self.root / "state")
        mts1 = encode_trusted_subtrees([
            TrustedSubtree(1, 0, 8, b"a" * 32),
        ])

        def fake_get(base_url, path, binary=False):
            self.assertEqual(base_url, "http://127.0.0.1:8080/")
            return b"snapshot" if binary else {"path": path}

        def fake_update(base_url, authority, checker, directory,
                        log_number, sequence, now):
            rp_updater._get(base_url, "/snapshot", binary=True)
            rp_updater._get(base_url, "/proof/subtree?start=0&end=8&size=8")
            return RPStateStore(directory).publish(
                {"tree_size": 8, "hash": "ab" * 32}, mts1)

        with patch.object(rp_updater, "_get", side_effect=fake_get), \
                patch.object(rp_updater, "update_and_publish", side_effect=fake_update):
            current, path, generation, requests = bridge.update_once(
                "http://127.0.0.1:8080/", self.root / "authority",
                self.root / "checker", state, 1, [], 100)

        self.assertEqual(current["checkpoint"]["tree_size"], 8)
        self.assertEqual(path.read_bytes(), mts1)
        self.assertEqual(path.parent, generation.resolve())
        self.assertEqual([request["path"] for request in requests], [
            "/snapshot", "/proof/subtree?start=0&end=8&size=8",
        ])
        self.assertEqual(len(list((state / "generations").iterdir())), 1)

    def test_log_url_is_loopback_http_only(self):
        self.assertEqual(bridge.require_local_http_url("http://127.0.0.1:8080"),
                         "http://127.0.0.1:8080/")
        for value in ("https://127.0.0.1:8080/", "http://example.com:8080/",
                      "http://127.0.0.1:8080/path"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bridge.require_local_http_url(value)

    def test_managed_log_accepts_os_selected_or_explicit_port(self):
        ready = self.root / "ready.json"
        ready.write_text(json.dumps({"host": "127.0.0.1", "port": 49152}))
        expected = "http://127.0.0.1:49152/"
        self.assertEqual(
            bridge.managed_log_base_url(ready, "127.0.0.1", 0), expected)
        self.assertEqual(
            bridge.managed_log_base_url(ready, "127.0.0.1", 49152), expected)
        with self.assertRaisesRegex(ValueError, "invalid address"):
            bridge.managed_log_base_url(ready, "127.0.0.1", 8080)


if __name__ == "__main__":
    unittest.main()
