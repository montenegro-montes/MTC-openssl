"""Offline tests for HTTP transparency orchestration."""

import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run
from rp_state import RPStateStore
from trusted_subtrees import encode_trusted_subtrees


class HttpTransparencyRunnerTests(unittest.TestCase):
    def test_positive_show_reuses_browser_harness(self):
        command = run.command("http-positive", ["--snapshot", "snapshot.mcp2"])
        self.assertEqual(command[:2], ["python3", "campaigns/browser_client/chromium_mtc/http_log_integration.py"])

    def test_negative_show_selects_validation_runner(self):
        command = run.command("invalid-snapshot", ["--snapshot", "snapshot.mcp2"])
        self.assertEqual(command[2:4], ["_negative", "invalid-snapshot"])

    def test_managed_negative_defaults_to_os_selected_port(self):
        args = run.negative_parser("invalid-snapshot", [
            "--log-data", "log", "--snapshot", "snapshot.mcp2",
            "--trusted-authority", "authority.bin",
        ])
        self.assertEqual(args.log_port, 0)

    def test_subtree_corruption_is_single_and_audited(self):
        proof = {"proof": ["11" * 32], "hash": "22" * 32}
        records = []
        with patch.object(run.rp_updater, "_get", return_value=proof):
            with run.corrupt_subtree_response(records) as changed:
                first = run.rp_updater._get("http://127.0.0.1:1/", "/proof/subtree?x")
                second = run.rp_updater._get("http://127.0.0.1:1/", "/proof/subtree?y")
        self.assertTrue(changed["value"])
        self.assertNotEqual(first["proof"], proof["proof"])
        self.assertEqual(second, proof)
        self.assertEqual([item["corrupted_for_validation"] for item in records], [True, False])

    def test_plan_is_offline_and_lists_only_declared_cases(self):
        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(run.main(["plan"]), 0)
        for case in run.CASES:
            self.assertIn(case, output.getvalue())

    def test_invalid_first_landmark_proof_accepts_empty_mts1_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "rp-state"
            RPStateStore(state).publish(
                {"log_number": 1, "tree_size": 16, "hash": "11" * 32},
                encode_trusted_subtrees([]),
            )
            outcome = run.validate_negative_outcome(
                "invalid-subtree-proof", state, None, True)
        self.assertEqual(outcome["trusted_subtree_count"], 0)
        self.assertTrue(outcome["rp_current_published"])
        self.assertFalse(outcome["expected_rejection"])

    def test_invalid_snapshot_still_requires_no_published_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "rp-state"
            state.mkdir()
            outcome = run.validate_negative_outcome(
                "invalid-snapshot", state, "authentication failed", False)
        self.assertTrue(outcome["expected_rejection"])
        self.assertFalse(outcome["rp_current_published"])
        self.assertFalse(outcome["rp_generation_published"])


if __name__ == "__main__":
    unittest.main()
