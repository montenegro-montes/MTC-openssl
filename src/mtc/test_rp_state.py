"""Focused tests for atomic relying-party state publication."""

import hashlib
import json
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
        "log_number": 1,
        "tree_size": 8,
        "hash": root([bytes([i]) for i in range(8)]).hex(),
    }
    mts8 = encode_trusted_subtrees([
        TrustedSubtree(1, 0, 4, b"\x11" * 32),
        TrustedSubtree(1, 4, 8, b"\x22" * 32),
    ])

    current8 = store.publish(checkpoint8, mts8, 1)
    assert current8["checkpoint"] == checkpoint8
    assert current8["trusted_subtrees"] == mts8
    assert current8["retained_landmark"] == 1
    target8 = store.current.readlink()

    # Re-publishing identical immutable state is idempotent.
    again8 = store.publish(checkpoint8, mts8, 1)
    assert again8["checkpoint"] == checkpoint8
    assert store.current.readlink() == target8

    checkpoint16 = {
        "log_number": 1,
        "tree_size": 16,
        "hash": root([bytes([i]) for i in range(16)]).hex(),
    }
    mts16 = encode_trusted_subtrees([
        TrustedSubtree(1, 0, 4, b"\x11" * 32),
        TrustedSubtree(1, 4, 8, b"\x22" * 32),
        TrustedSubtree(1, 8, 12, b"\x33" * 32),
        TrustedSubtree(1, 12, 16, b"\x44" * 32),
    ])

    current16 = store.publish(checkpoint16, mts16, 3)
    assert current16["checkpoint"] == checkpoint16
    assert current16["trusted_subtrees"] == mts16
    assert current16["retained_landmark"] == 3
    target16 = store.current.readlink()
    assert target16 != target8

    # A malformed candidate must fail before current changes.
    rejected(
        lambda: store.publish(
            {
                "log_number": 1,
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
    previous_checkpoint16, previous_mts16, previous_landmark16 = (
        store._read_generation(
        store.directory / target16)
    )
    assert previous_checkpoint16 == checkpoint16
    assert previous_mts16 == mts16
    assert previous_landmark16 == 3

    # Re-publishing the refreshed state is still idempotent.
    store.publish(checkpoint16, refreshed16)
    assert store.current.readlink() == refreshed_target16

    # A corrupt generation cannot be selected as current.
    corrupt = store.generations / (
        "%05d-%016d-%s-%s" % (
            1,
            17,
            "00" * 32,
            hashlib.sha256(b"bad").hexdigest(),
        ))
    corrupt.mkdir()
    (corrupt / "checkpoint.json").write_text(
        '{"hash":"' + ("00" * 32) + '","log_number":1,"tree_size":17}\n',
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
        "log_number": 1,
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
        "%05d-%016d-%s-%s" % (
            checkpoint32["log_number"],
            checkpoint32["tree_size"],
            checkpoint32["hash"],
            hashlib.sha256(mts32).hexdigest(),
        ))
    assert generation32.is_dir()
    written32_checkpoint, written32_mts1, written32_landmark = (
        store._read_generation(generation32))
    assert written32_checkpoint == checkpoint32
    assert written32_mts1 == mts32
    assert written32_landmark is None

# Commit 8: RP state is explicitly bound to one issuance-log domain.
with tempfile.TemporaryDirectory(prefix="mtc-rp-state-log2-test-") as temporary:
    directory = Path(temporary) / "rp-state"
    store = RPStateStore(directory)

    shared_hash = root([bytes([i]) for i in range(8)]).hex()
    checkpoint2 = {
        "log_number": 2,
        "tree_size": 8,
        "hash": shared_hash,
    }
    mts2 = encode_trusted_subtrees([
        TrustedSubtree(2, 0, 4, b"\x55" * 32),
        TrustedSubtree(2, 4, 8, b"\x66" * 32),
    ])

    published2 = store.publish(checkpoint2, mts2, 3)
    assert published2["checkpoint"] == checkpoint2
    assert published2["trusted_subtrees"] == mts2
    assert published2["retained_landmark"] == 3
    target2 = store.current.readlink()

    # Restart must preserve the authenticated log identity.
    restarted = RPStateStore(directory)
    loaded2 = restarted.load_current()
    assert loaded2["checkpoint"] == checkpoint2
    assert loaded2["trusted_subtrees"] == mts2
    assert loaded2["retained_landmark"] == 3
    assert restarted.current.readlink() == target2

    # A legacy generation without retained-landmark.json remains readable,
    # but its landmark identity is unavailable and is never inferred.
    legacy_name = restarted._generation_name(checkpoint2, mts2)
    legacy = restarted.generations / legacy_name
    legacy.mkdir()
    (legacy / "checkpoint.json").write_bytes(
        restarted._checkpoint_bytes(checkpoint2))
    (legacy / "trusted-subtrees.mts1").write_bytes(mts2)
    restarted.current.unlink()
    restarted.current.symlink_to(Path("generations") / legacy_name)
    legacy_loaded = restarted.load_current()
    assert legacy_loaded["checkpoint"] == checkpoint2
    assert legacy_loaded["trusted_subtrees"] == mts2
    assert legacy_loaded["retained_landmark"] is None
    restarted.current.unlink()
    restarted.current.symlink_to(target2)

    # Retained-landmark metadata is strictly log-bound and range-checked.
    before_bad_landmark = restarted.current.readlink()
    bad_number = 0

    def bad_landmark_generation(value):
        nonlocal_name = "bad-landmark-%d" % bad_landmark_generation.number
        bad_landmark_generation.number += 1
        path = restarted.generations / nonlocal_name
        path.mkdir()
        (path / "checkpoint.json").write_bytes(
            restarted._checkpoint_bytes(checkpoint2))
        (path / "trusted-subtrees.mts1").write_bytes(mts2)
        (path / "retained-landmark.json").write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        return path

    bad_landmark_generation.number = bad_number
    invalid_landmarks = [0, -1, True, 1 << 48]
    for landmark in invalid_landmarks:
        invalid = bad_landmark_generation({
            "log_number": 2,
            "retained_landmark": landmark,
        })
        rejected(
            lambda invalid=invalid: restarted._read_generation(invalid),
            "invalid retained landmark accepted",
        )
        assert restarted.current.readlink() == before_bad_landmark

    wrong_log = bad_landmark_generation({
        "log_number": 1,
        "retained_landmark": 3,
    })
    rejected(
        lambda: restarted._read_generation(wrong_log),
        "cross-log retained landmark accepted",
    )
    assert restarted.current.readlink() == before_bad_landmark

    malformed_landmark = bad_landmark_generation({
        "log_number": 2,
        "retained_landmark": 3,
    })
    (malformed_landmark / "retained-landmark.json").write_text(
        "{not-json\n", encoding="ascii")
    rejected(
        lambda: restarted._read_generation(malformed_landmark),
        "malformed retained-landmark JSON accepted",
    )
    assert restarted.current.readlink() == before_bad_landmark

    # Same tree size/root in another log is still a distinct RP generation.
    checkpoint1_same = {
        "log_number": 1,
        "tree_size": 8,
        "hash": shared_hash,
    }
    empty_mts1 = encode_trusted_subtrees([])
    published1 = restarted.publish(checkpoint1_same, empty_mts1)
    assert published1["checkpoint"] == checkpoint1_same
    assert restarted.current.readlink() != target2
    assert (restarted.directory / target2).is_dir()

    # Legacy/unbound checkpoints and invalid log identifiers fail closed.
    invalid_checkpoints = [
        {"tree_size": 8, "hash": shared_hash},
        {"log_number": 0, "tree_size": 8, "hash": shared_hash},
        {"log_number": 65536, "tree_size": 8, "hash": shared_hash},
        {"log_number": -1, "tree_size": 8, "hash": shared_hash},
        {"log_number": True, "tree_size": 8, "hash": shared_hash},
        {"log_number": "2", "tree_size": 8, "hash": shared_hash},
    ]
    before_invalid = restarted.current.readlink()
    for candidate in invalid_checkpoints:
        rejected(
            lambda candidate=candidate: restarted.publish(
                candidate, empty_mts1),
            "invalid or unbound checkpoint accepted",
        )
        assert restarted.current.readlink() == before_invalid

    # A checkpoint and its MTS1 must belong to the same issuance log.
    cross_log_mts1 = encode_trusted_subtrees([
        TrustedSubtree(1, 0, 8, b"\x77" * 32),
    ])
    rejected(
        lambda: restarted.publish(checkpoint2, cross_log_mts1),
        "cross-log MTS1 accepted",
    )
    assert restarted.current.readlink() == before_invalid

    # A structurally valid but cross-log generation appearing on disk must
    # also fail closed when read after publication/restart.
    cross_name = restarted._generation_name(checkpoint2, cross_log_mts1)
    cross_generation = restarted.generations / cross_name
    cross_generation.mkdir()
    (cross_generation / "checkpoint.json").write_bytes(
        restarted._checkpoint_bytes(checkpoint2)
    )
    (cross_generation / "trusted-subtrees.mts1").write_bytes(cross_log_mts1)
    rejected(
        lambda: restarted._read_generation(cross_generation),
        "cross-log generation accepted from disk",
    )
    assert restarted.current.readlink() == before_invalid

print("PASS: RP state log-domain binding and restart")
print("PASS: atomic fail-closed RP state publication")
