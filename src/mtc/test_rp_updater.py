"""Focused relying-party checkpoint transition tests."""

from pathlib import Path
import tempfile
import threading

from core import root
from landmarks import Landmark
from local_log import LocalLog
from log_service import LogServer
import rp_updater
from rp_updater import (
    advance_checkpoint,
    build_trusted_subtree_configuration,
    fetch_and_advance_checkpoint,
)
from trusted_subtrees import decode_trusted_subtrees


with tempfile.TemporaryDirectory(prefix="mtc-rp-update-test-") as temporary:
    temp = Path(temporary)
    log_directory = temp / "log"
    published = temp / "published.mcf1"

    log = LocalLog(log_directory)
    entries = [bytes([i]) for i in range(16)]
    for entry in entries[:8]:
        log.append(entry)

    state8 = log.state()
    published.write_bytes(b"snapshot-8")

    server = LogServer(("127.0.0.1", 0), log_directory, published)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()

    base_url = "http://127.0.0.1:%d/" % server.server_address[1]

    states = {
        b"snapshot-8": {
            "log_number": 1,
            **state8,
        },
    }

    def authenticate(snapshot, trusted_authority, checker):
        data = Path(snapshot).read_bytes()
        if data not in states:
            raise ValueError("Snapshot authentication failed")
        return dict(states[data])

    try:
        # Authenticated bootstrap.
        current = fetch_and_advance_checkpoint(
            base_url, None, None, authenticate=authenticate)
        assert current == {"log_number": 1, **state8}

        # Same authenticated checkpoint is an idempotent no-op.
        assert fetch_and_advance_checkpoint(
            base_url, None, None, current, authenticate) == {
                "log_number": 1,
                **state8,
            }

        # Grow the real HTTP log to N=16 and publish its authenticated model.
        for entry in entries[8:]:
            log.append(entry)
        state16 = log.state()
        states[b"snapshot-16"] = {
            "log_number": 1,
            **state16,
        }
        published.write_bytes(b"snapshot-16")

        current = fetch_and_advance_checkpoint(
            base_url, None, None, current, authenticate)
        assert current == {"log_number": 1, **state16}

        # The authenticated N=16 checkpoint is the trust root for all
        # subsequently fetched, unsigned Section 4.4 subtree evidence.
        sequence = [
            Landmark(0, 0, 0),
            Landmark(1, 8, 100),
            Landmark(2, 16, 200),
        ]
        trusted, mts1 = build_trusted_subtree_configuration(
            base_url, 1, sequence, 50, current)

        assert [(item.log_number, item.start, item.end)
                for item in trusted] == [
            (1, 0, 4),
            (1, 4, 8),
            (1, 8, 12),
            (1, 12, 16),
        ]
        assert decode_trusted_subtrees(mts1) == trusted

        # The validation result records the newest completely retained
        # landmark directly, before the intervals are encoded as MTS1.
        sequence3 = [
            Landmark(0, 0, 0),
            Landmark(1, 4, 100),
            Landmark(2, 8, 200),
            Landmark(3, 16, 300),
        ]
        through3, through3_mts1 = build_trusted_subtree_configuration(
            base_url, 1, sequence3, 50, current)
        assert through3.retained_landmark == 3
        assert decode_trusted_subtrees(through3_mts1) == through3

        # The active-landmark limit retains the older complete prefix.
        limited, limited_mts1 = build_trusted_subtree_configuration(
            base_url, 1, sequence, 50, current,
            max_active_landmarks=1)
        assert [(item.start, item.end) for item in limited] == [
            (0, 4),
            (4, 8),
        ]
        assert decode_trusted_subtrees(limited_mts1) == limited

        # Corrupt structurally valid unsigned subtree evidence.  Failure in
        # landmark 2 retains the complete older landmark 1.
        real_get = rp_updater._get

        def corrupt_subtree(start_to_corrupt):
            def get(url, path, binary=False):
                result = real_get(url, path, binary)
                if (path.startswith("/proof/subtree?")
                        and result["start"] == start_to_corrupt):
                    result = dict(result)
                    node_hash = bytearray.fromhex(result["hash"])
                    node_hash[0] ^= 1
                    result["hash"] = node_hash.hex()
                return result
            return get

        rp_updater._get = corrupt_subtree(8)
        try:
            prefix, prefix_mts1 = build_trusted_subtree_configuration(
                base_url, 1, sequence, 50, current)
            assert [(item.start, item.end) for item in prefix] == [
                (0, 4),
                (4, 8),
            ]
            assert decode_trusted_subtrees(prefix_mts1) == prefix
        finally:
            rp_updater._get = real_get

        # Failure at landmark 2 retains landmark 1, but never assigns the
        # failed or newer landmark identity to the retained prefix.
        rp_updater._get = corrupt_subtree(4)
        try:
            prefix3, prefix3_mts1 = build_trusted_subtree_configuration(
                base_url, 1, sequence3, 50, current)
            assert prefix3.retained_landmark == 1
            assert decode_trusted_subtrees(prefix3_mts1) == prefix3
        finally:
            rp_updater._get = real_get

        # Failure in landmark 1 prevents incorporation of it and every newer
        # landmark.  The resulting MTS1 is valid but contains no subtrees.
        rp_updater._get = corrupt_subtree(0)
        try:
            empty, empty_mts1 = build_trusted_subtree_configuration(
                base_url, 1, sequence, 50, current)
            assert empty == []
            assert empty.retained_landmark is None
            assert decode_trusted_subtrees(empty_mts1) == []
        finally:
            rp_updater._get = real_get

        # Unsigned consistency evidence is accepted only when it connects the
        # independently authenticated checkpoint roots.  Corrupt the real
        # HTTP proof while keeping its claimed endpoints unchanged.
        real_get = rp_updater._get
        real_consistency = real_get(
            base_url, "/proof/consistency?old=8&new=16")
        assert real_consistency["proof"]

        corrupted = dict(real_consistency)
        corrupted["proof"] = list(corrupted["proof"])
        node = bytearray.fromhex(corrupted["proof"][0])
        node[0] ^= 1
        corrupted["proof"][0] = node.hex()

        def corrupted_get(url, path, binary=False):
            if path.startswith("/proof/consistency?"):
                return corrupted
            return real_get(url, path, binary)

        rp_updater._get = corrupted_get
        try:
            try:
                advance_checkpoint(
                    base_url,
                    {"log_number": 1, **state8},
                    {"log_number": 1, **state16},
                )
            except ValueError as exc:
                assert str(exc) == "Checkpoint consistency verification failed"
            else:
                raise AssertionError("corrupted consistency proof accepted")
        finally:
            rp_updater._get = real_get

        # Even a structurally valid proof response must name exactly the
        # independently authenticated checkpoint endpoints.
        mismatched = dict(real_consistency)
        mismatched["new_hash"] = root([b"different"] + entries[1:]).hex()

        def mismatched_get(url, path, binary=False):
            if path.startswith("/proof/consistency?"):
                return mismatched
            return real_get(url, path, binary)

        rp_updater._get = mismatched_get
        try:
            try:
                advance_checkpoint(
                    base_url,
                    {"log_number": 1, **state8},
                    {"log_number": 1, **state16},
                )
            except ValueError as exc:
                assert str(exc) == (
                    "Consistency response does not match checkpoints")
            else:
                raise AssertionError(
                    "mismatched consistency response accepted")
        finally:
            rp_updater._get = real_get

        # Checkpoints from different issuance logs are independent domains.
        # A direct transition must fail before requesting consistency evidence.
        log1_checkpoint = {"log_number": 1, **state8}
        log2_checkpoint = {"log_number": 2, **state16}
        consistency_requested = False
        real_get = rp_updater._get

        def detect_cross_log_get(url, path, binary=False):
            global consistency_requested
            if path.startswith("/proof/consistency?"):
                consistency_requested = True
            return real_get(url, path, binary)

        rp_updater._get = detect_cross_log_get
        try:
            try:
                advance_checkpoint(
                    base_url, log1_checkpoint, log2_checkpoint)
            except ValueError as exc:
                assert str(exc) == (
                    "Cannot advance checkpoint across issuance logs")
            else:
                raise AssertionError("cross-log checkpoint transition accepted")
            assert not consistency_requested
        finally:
            rp_updater._get = real_get

        # Rollback to an older authenticated checkpoint is rejected.
        published.write_bytes(b"snapshot-8")
        try:
            fetch_and_advance_checkpoint(
                base_url, None, None, current, authenticate)
        except ValueError as exc:
            assert str(exc) == "Checkpoint rollback"
        else:
            raise AssertionError("authenticated rollback accepted")

        # Same-size authenticated equivocation is rejected before any proof.
        alternate16 = {
            "tree_size": 16,
            "hash": root([b"different"] + entries[1:]).hex(),
        }
        states[b"snapshot-alternate-16"] = {
            "log_number": 1,
            **alternate16,
        }
        published.write_bytes(b"snapshot-alternate-16")
        try:
            fetch_and_advance_checkpoint(
                base_url, None, None, current, authenticate)
        except ValueError as exc:
            assert str(exc) == "Checkpoint hash changed at same tree size"
        else:
            raise AssertionError("same-size checkpoint equivocation accepted")

        # Unauthenticated snapshot is rejected at the authentication boundary.
        published.write_bytes(b"not-authenticated")
        try:
            fetch_and_advance_checkpoint(
                base_url, None, None, current, authenticate)
        except ValueError as exc:
            assert "Snapshot authentication failed" in str(exc)
        else:
            raise AssertionError("unauthenticated snapshot accepted")

        # Log 2 is an independent authenticated checkpoint domain.
        states[b"snapshot-log2-8"] = {
            "log_number": 2,
            **state8,
        }
        published.write_bytes(b"snapshot-log2-8")
        log2_current = fetch_and_advance_checkpoint(
            base_url, None, None, authenticate=authenticate)
        assert log2_current == {"log_number": 2, **state8}

        # Normal N -> M consistency verification still applies within log 2.
        states[b"snapshot-log2-16"] = {
            "log_number": 2,
            **state16,
        }
        published.write_bytes(b"snapshot-log2-16")
        log2_current = fetch_and_advance_checkpoint(
            base_url, None, None, log2_current, authenticate)
        assert log2_current == {"log_number": 2, **state16}

        # Identical size/root values in different logs remain distinct
        # authenticated checkpoints.
        assert log2_current["tree_size"] == current["tree_size"]
        assert log2_current["hash"] == current["hash"]
        assert log2_current["log_number"] != current["log_number"]

    finally:
        server.shutdown()
        thread.join()
        server.server_close()

print("PASS: RP authenticated checkpoint bootstrap, evolution, rollback and equivocation")
