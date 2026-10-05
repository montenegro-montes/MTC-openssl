"""Focused offline tests for checkpoint gossip comparison."""

import json
from pathlib import Path
import tempfile
from urllib.error import URLError
from unittest.mock import patch
from checkpoint_gossip import (
    _load_checkpoint_url,
    compare_checkpoints,
    main as gossip_main,
)
from rp_updater import RPHTTPError


def checkpoint(size, byte="11", log_number=1):
    return {
        "log_number": log_number,
        "tree_size": size,
        "hash": byte * 32,
    }


class Response:
    status = 200

    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self):
        return self.value


def main():
    same = compare_checkpoints(checkpoint(16), checkpoint(16))
    assert same["result"] == "CONSISTENT"
    assert same["severity"] == "PASS"

    split = compare_checkpoints(
        checkpoint(16, "11"),
        checkpoint(16, "22"),
    )
    assert split["result"] == "SPLIT_VIEW"
    assert split["severity"] == "ALERT"

    different_size = compare_checkpoints(
        checkpoint(8, "11"),
        checkpoint(16, "22"),
    )
    assert different_size["result"] == "NEEDS_CONSISTENCY"
    assert different_size["severity"] == "INFO"

    different_log = compare_checkpoints(
        checkpoint(16, "11", log_number=1),
        checkpoint(16, "22", log_number=2),
    )
    assert different_log["result"] == "DIFFERENT_LOG"
    assert different_log["severity"] == "INFO"

    # Different-size views with a valid consistency proof.
    calls = []

    def valid_advance(url, older, newer):
        calls.append((url, older, newer))
        return dict(newer)

    older = checkpoint(8, "11")
    newer = checkpoint(16, "22")

    consistent = compare_checkpoints(
        older,
        newer,
        log_url="http://mtc-log:8080/",
        advance=valid_advance,
    )
    assert consistent["result"] == "CONSISTENT"
    assert consistent["severity"] == "PASS"
    assert consistent["consistency_verified"] is True
    assert consistent["consistency_old_size"] == 8
    assert consistent["consistency_new_size"] == 16
    assert calls == [("http://mtc-log:8080/", older, newer)]

    # Input order must not matter: consistency is still checked 8 -> 16.
    calls.clear()
    consistent_reverse = compare_checkpoints(
        newer,
        older,
        log_url="http://mtc-log:8080/",
        advance=valid_advance,
    )
    assert consistent_reverse["result"] == "CONSISTENT"
    assert consistent_reverse["severity"] == "PASS"
    assert consistent_reverse["consistency_verified"] is True
    assert consistent_reverse["consistency_old_size"] == 8
    assert consistent_reverse["consistency_new_size"] == 16
    assert calls == [("http://mtc-log:8080/", older, newer)]

    # A failed consistency verification must be an alert.
    def invalid_advance(url, older, newer):
        raise ValueError("Checkpoint consistency verification failed")

    inconsistent = compare_checkpoints(
        older,
        newer,
        log_url="http://mtc-log:8080/",
        advance=invalid_advance,
    )
    assert inconsistent["result"] == "INCONSISTENT"
    assert inconsistent["severity"] == "ALERT"
    assert "consistency_verified" not in inconsistent

    # Log unavailability is not evidence of a split view.
    def unavailable_advance(url, older, newer):
        raise RPHTTPError("unavailable")

    unavailable = compare_checkpoints(
        older,
        newer,
        log_url="http://mtc-log:8080/",
        advance=unavailable_advance,
    )
    assert unavailable["result"] == "UNAVAILABLE"
    assert unavailable["severity"] == "ERROR"
    assert "consistency_verified" not in unavailable

    # CLI reads persisted checkpoint files and returns PASS for equal views.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        first_path = root / "first.json"
        second_path = root / "second.json"

        first_path.write_text(json.dumps(checkpoint(16)))
        second_path.write_text(json.dumps(checkpoint(16)))

        assert gossip_main([
            "--first", str(first_path),
            "--second", str(second_path),
        ]) == 0

    # CLI returns non-zero for direct split-view evidence.
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        first_path = root / "first.json"
        second_path = root / "second.json"

        first_path.write_text(json.dumps(checkpoint(16, "11")))
        second_path.write_text(json.dumps(checkpoint(16, "22")))

        assert gossip_main([
            "--first", str(first_path),
            "--second", str(second_path),
        ]) == 1

    # HTTP inputs use the same checkpoint validation and comparison.
    with patch("checkpoint_gossip.urlopen", side_effect=[
            Response(json.dumps(checkpoint(16)).encode()),
            Response(json.dumps(checkpoint(16)).encode()),
    ]):
        assert gossip_main([
            "--first-url", "http://monitor-a:8081/checkpoint",
            "--second-url", "http://monitor-b:8081/checkpoint",
        ]) == 0
    with patch("checkpoint_gossip.urlopen", side_effect=[
            Response(json.dumps(checkpoint(16, "11")).encode()),
            Response(json.dumps(checkpoint(16, "22")).encode()),
    ]):
        assert gossip_main([
            "--first-url", "http://monitor-a:8081/checkpoint",
            "--second-url", "http://monitor-b:8081/checkpoint",
        ]) == 1

    with patch("checkpoint_gossip.urlopen", return_value=Response(b'{"bad":true}')):
        try:
            _load_checkpoint_url("http://monitor-a:8081/checkpoint")
        except ValueError:
            pass
        else:
            raise AssertionError("invalid HTTP checkpoint accepted")

    with patch("checkpoint_gossip.urlopen", side_effect=URLError("offline")):
        try:
            _load_checkpoint_url("http://monitor-a:8081/checkpoint")
        except RPHTTPError:
            pass
        else:
            raise AssertionError("unavailable HTTP checkpoint accepted")

    print("PASS: offline checkpoint gossip comparison")


if __name__ == "__main__":
    main()
