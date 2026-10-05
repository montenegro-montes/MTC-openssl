"""Focused offline tests for the continuous checkpoint monitor."""

import json
from pathlib import Path
import signal
import tempfile
from urllib.error import URLError
from unittest.mock import patch

from checkpoint_monitor import (
    CheckpointMonitor,
    CheckpointStateStore,
    MonitorStateError,
    require_http_log_url,
)
import checkpoint_monitor
from rp_updater import RPHTTPError, _get


def checkpoint(size, byte="11", log_number=1):
    return {"log_number": log_number, "tree_size": size, "hash": byte * 32}


class Fetch:
    def __init__(self, values):
        self.values = iter(values)

    def __call__(self, base_url, authority, checker):
        value = next(self.values)
        if isinstance(value, Exception):
            raise value
        return dict(value)


def monitor(root, values, advance=lambda url, previous, candidate: candidate):
    return CheckpointMonitor(
        "http://mtc-log:8080", "authority.mca2", "check_snapshot",
        root, fetch_checkpoint=Fetch(values), advance=advance)


with tempfile.TemporaryDirectory(prefix="mtc-checkpoint-monitor-") as value:
    root = Path(value)
    state = root / "state"
    cp8 = checkpoint(8)
    cp16 = checkpoint(16, "22")

    unavailable_state = root / "unavailable-state"
    unavailable = monitor(
        unavailable_state, [RPHTTPError("offline")]).check_once()
    assert unavailable["result"] == "UNAVAILABLE"
    assert not (unavailable_state / "checkpoint.json").exists()

    instance = monitor(state, [cp8, cp8, cp16])
    initial = instance.check_once()
    assert initial["result"] == "INITIAL" and initial["severity"] == "PASS"
    assert "consistency_verified" not in initial
    original = (state / "checkpoint.json").read_bytes()
    unchanged = instance.check_once()
    assert unchanged["result"] == "UNCHANGED" and unchanged["severity"] == "PASS"
    assert "consistency_verified" not in unchanged
    assert (state / "checkpoint.json").read_bytes() == original
    advanced = instance.check_once()
    assert advanced["result"] == "ADVANCE" and advanced["severity"] == "PASS"
    assert advanced["consistency_verified"] is True
    assert advanced["consistency_old_size"] == 8
    assert advanced["consistency_new_size"] == 16
    accepted16 = (state / "checkpoint.json").read_bytes()

    # Restart recovers the accepted checkpoint without rewriting it.
    restarted = monitor(state, [cp16])
    assert restarted.check_once()["result"] == "UNCHANGED"
    assert (state / "checkpoint.json").read_bytes() == accepted16

    cases = [
        (checkpoint(8), "ROLLBACK", "ALERT"),
        (checkpoint(16, "33"), "CONSISTENCY", "ALERT"),
        (checkpoint(17, "44", 2), "CONSISTENCY"),
        (ValueError("bad snapshot"), "AUTHENTICATION", "ALERT"),
        (RPHTTPError("offline"), "UNAVAILABLE"),
    ]
    for candidate, expected, *severity in cases:
        result = monitor(state, [candidate]).check_once()
        assert result["result"] == expected
        if severity:
            assert result["severity"] == severity[0]
        assert (state / "checkpoint.json").read_bytes() == accepted16

    def invalid_proof(url, previous, candidate):
        raise ValueError("Checkpoint consistency verification failed")

    result = monitor(state, [checkpoint(32, "55")], invalid_proof).check_once()
    assert result["result"] == "CONSISTENCY" and result["severity"] == "ALERT"
    assert "consistency_verified" not in result
    assert (state / "checkpoint.json").read_bytes() == accepted16

    def proof_unavailable(url, previous, candidate):
        raise RPHTTPError("offline")

    result = monitor(state, [checkpoint(32, "55")], proof_unavailable).check_once()
    assert result["result"] == "UNAVAILABLE" and result["severity"] == "ERROR"
    assert (state / "checkpoint.json").read_bytes() == accepted16

    # Corrupt persistent state is never treated as INITIAL.
    corrupt_values = [
        b'{"log_number":1',
        json.dumps({"log_number": 1, "tree_size": 8,
                    "hash": "GG" * 32}).encode(),
        json.dumps({"log_number": 1, "tree_size": 8,
                    "hash": "11" * 32, "extra": True}).encode(),
    ]
    for index, data in enumerate(corrupt_values):
        corrupt = root / f"corrupt-{index}"
        corrupt.mkdir()
        (corrupt / "checkpoint.json").write_bytes(data)
        result = monitor(corrupt, [cp8]).check_once()
        assert result == {
            "result": "STATE", "severity": "ERROR",
            "previous": None, "candidate": None,
        }
        assert (corrupt / "checkpoint.json").read_bytes() == data

    symlink_state = root / "symlink-state"
    symlink_state.mkdir()
    target = root / "target.json"
    target.write_text(json.dumps(cp8))
    (symlink_state / "checkpoint.json").symlink_to(target)
    try:
        CheckpointStateStore(symlink_state).load()
    except MonitorStateError:
        pass
    else:
        raise AssertionError("symlink monitor state accepted")

for accepted in (
        "http://localhost:8080", "http://127.0.0.1:8080",
        "http://192.168.1.100:8080", "http://mtc-log:8080"):
    assert require_http_log_url(accepted) == accepted + "/"
for rejected in (
        "https://mtc-log:8080", "http://mtc-log", "http://user@mtc-log:8080",
        "http://@mtc-log:8080",
        "http://mtc-log:8080/path", "http://mtc-log:8080/?query=1",
        "http://mtc-log:8080/#fragment", "http://[broken:8080"):
    try:
        require_http_log_url(rejected)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid log URL accepted")

with patch("rp_updater.urlopen", side_effect=URLError("offline")):
    try:
        _get("http://mtc-log:8080", "/snapshot", binary=True)
    except RPHTTPError as error:
        assert isinstance(error, ValueError)
    else:
        raise AssertionError("transport failure was not typed")

# The CLI installs handlers for both container termination signals.
installed = []
with tempfile.TemporaryDirectory(prefix="mtc-monitor-cli-") as cli_state:
    with patch.object(checkpoint_monitor.signal, "signal",
                      side_effect=lambda signum, handler: installed.append(signum)), \
            patch.object(checkpoint_monitor, "CheckpointMonitor") as monitor_class:
        monitor_class.return_value.check_once.return_value = {
            "result": "UNCHANGED", "severity": "PASS",
            "previous": checkpoint(8), "candidate": checkpoint(8),
        }
        assert checkpoint_monitor.main([
            "--log-url", "http://mtc-log:8080",
            "--trusted-authority", "authority.mca2",
            "--checker", "check_snapshot",
            "--state-directory", cli_state,
            "--once",
        ]) == 0
assert installed == [signal.SIGTERM, signal.SIGINT]

print("PASS: continuous authenticated checkpoint monitor")
