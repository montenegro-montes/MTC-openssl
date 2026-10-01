"""Focused tests for atomic relying-party state publication."""

import hashlib
from pathlib import Path
import tempfile

from core import root
from rp_state import RPStateStore
from trusted_subtrees import TrustedSubtree, encode_trusted_subtrees


def rejected(operation, message):
    try:
        operation()
    except (ValueError, OSError):
        return
    raise AssertionError(message)


with tempfile.TemporaryDirectory(prefix="mtc-rp-state-test-") as temporary:
    directory = Path(temporary) / "rp-state"
    store = RPStateStore(directory)

    assert store.load_current() is None

    checkpoint8 = {
        "tree_size": 8,
        "hash": root([bytes([i]) for i in range(8)]).hex(),
    }
    mts8 = encode_trusted_subtrees([
        TrustedSubtree(1, 0, 4, b"\x11" * 32),
        TrustedSubtree(1, 4, 8, b"\x22" * 32),
    ])

    current8 = store.publish(checkpoint8, mts8)
    assert current8["checkpoint"] == checkpoint8
    assert current8["trusted_subtrees"] == mts8
    target8 = store.current.readlink()

    # Re-publishing identical immutable state is idempotent.
    again8 = store.publish(checkpoint8, mts8)
    assert again8["checkpoint"] == checkpoint8
    assert store.current.readlink() == target8

    checkpoint16 = {
        "tree_size": 16,
        "hash": root([bytes([i]) for i in range(16)]).hex(),
    }
    mts16 = encode_trusted_subtrees([
        TrustedSubtree(1, 0, 4, b"\x11" * 32),
        TrustedSubtree(1, 4, 8, b"\x22" * 32),
        TrustedSubtree(1, 8, 12, b"\x33" * 32),
        TrustedSubtree(1, 12, 16, b"\x44" * 32),
    ])

    current16 = store.publish(checkpoint16, mts16)
    assert current16["checkpoint"] == checkpoint16
    assert current16["trusted_subtrees"] == mts16
    target16 = store.current.readlink()
    assert target16 != target8

    # A malformed candidate must fail before current changes.
    rejected(
        lambda: store.publish(
            {
                "tree_size": 17,
                "hash": "00" * 32,
            },
            b"not-an-mts1",
        ),
        "invalid MTS1 accepted",
    )
    assert store.current.readlink() == target16
    assert store.load_current()["checkpoint"] == checkpoint16

    # MTS1 can be refreshed without changing the checkpoint, while the prior
    # immutable generation remains available.
    refreshed16 = encode_trusted_subtrees([])
    refreshed_current16 = store.publish(checkpoint16, refreshed16)
    refreshed_target16 = store.current.readlink()
    assert refreshed_current16["checkpoint"] == checkpoint16
    assert refreshed_current16["trusted_subtrees"] == refreshed16
    assert refreshed_target16 != target16
    assert (store.directory / target16).is_dir()
    previous_checkpoint16, previous_mts16 = store._read_generation(
        store.directory / target16)
    assert previous_checkpoint16 == checkpoint16
    assert previous_mts16 == mts16

    # Re-publishing the refreshed state is still idempotent.
    store.publish(checkpoint16, refreshed16)
    assert store.current.readlink() == refreshed_target16

    # A corrupt generation cannot be selected as current.
    corrupt = store.generations / (
        "%016d-%s-%s" % (
            17,
            "00" * 32,
            hashlib.sha256(b"bad").hexdigest(),
        ))
    corrupt.mkdir()
    (corrupt / "checkpoint.json").write_text(
        '{"hash":"' + ("00" * 32) + '","tree_size":17}\n',
        encoding="ascii",
    )
    (corrupt / "trusted-subtrees.mts1").write_bytes(b"bad")

    selector = store.directory / ".bad-current"
    selector.symlink_to(Path("generations") / corrupt.name)
    old_current = store.current.readlink()

    # Merely constructing bad state elsewhere cannot disturb current.
    rejected(
        lambda: store._read_generation(corrupt),
        "corrupt generation accepted",
    )
    assert store.current.readlink() == old_current
    assert store.load_current()["checkpoint"] == checkpoint16
    selector.unlink()

    # Simulate failure in the critical publication window: the new
    # generation has been fully written and validated, but switching current
    # fails.  The previously selected generation must remain authoritative.
    import rp_state

    checkpoint32 = {
        "tree_size": 32,
        "hash": root([bytes([i]) for i in range(32)]).hex(),
    }
    mts32 = encode_trusted_subtrees([
        TrustedSubtree(1, 0, 4, b"\x11" * 32),
        TrustedSubtree(1, 4, 8, b"\x22" * 32),
        TrustedSubtree(1, 8, 12, b"\x33" * 32),
        TrustedSubtree(1, 12, 16, b"\x44" * 32),
    ])

    before_failure = store.current.readlink()
    real_replace = rp_state.os.replace

    def failing_replace(source, destination):
        if Path(destination) == store.current:
            raise OSError("injected current switch failure")
        return real_replace(source, destination)

    rp_state.os.replace = failing_replace
    try:
        rejected(
            lambda: store.publish(checkpoint32, mts32),
            "injected current switch failure was not propagated",
        )
    finally:
        rp_state.os.replace = real_replace

    # The complete N=32 generation may remain as an unselected orphan, but
    # current must still expose the previously committed N=16 state.
    assert store.current.readlink() == before_failure
    retained = store.load_current()
    assert retained["checkpoint"] == checkpoint16
    assert retained["trusted_subtrees"] == refreshed16

    generation32 = store.generations / (
        "%016d-%s-%s" % (
            checkpoint32["tree_size"],
            checkpoint32["hash"],
            hashlib.sha256(mts32).hexdigest(),
        ))
    assert generation32.is_dir()
    written32_checkpoint, written32_mts1 = store._read_generation(generation32)
    assert written32_checkpoint == checkpoint32
    assert written32_mts1 == mts32

print("PASS: atomic fail-closed RP state publication")
