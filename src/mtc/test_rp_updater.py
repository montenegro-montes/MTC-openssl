"""Focused relying-party checkpoint transition tests."""

from pathlib import Path
import tempfile
import threading

from core import root
from local_log import LocalLog
from log_service import LogServer
import rp_updater
from rp_updater import advance_checkpoint, fetch_and_advance_checkpoint


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
        b"snapshot-8": state8,
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
        assert current == state8

        # Same authenticated checkpoint is an idempotent no-op.
        assert fetch_and_advance_checkpoint(
            base_url, None, None, current, authenticate) == state8

        # Grow the real HTTP log to N=16 and publish its authenticated model.
        for entry in entries[8:]:
            log.append(entry)
        state16 = log.state()
        states[b"snapshot-16"] = state16
        published.write_bytes(b"snapshot-16")

        current = fetch_and_advance_checkpoint(
            base_url, None, None, current, authenticate)
        assert current == state16

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
                advance_checkpoint(base_url, state8, state16)
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
                advance_checkpoint(base_url, state8, state16)
            except ValueError as exc:
                assert str(exc) == (
                    "Consistency response does not match checkpoints")
            else:
                raise AssertionError(
                    "mismatched consistency response accepted")
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
        states[b"snapshot-alternate-16"] = alternate16
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

    finally:
        server.shutdown()
        thread.join()
        server.server_close()

print("PASS: RP authenticated checkpoint bootstrap, evolution, rollback and equivocation")
