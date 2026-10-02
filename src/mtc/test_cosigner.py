"""Focused tests for the independent local external cosigner."""

from pathlib import Path
import tempfile
from unittest.mock import patch

import core
from cosigner import AcceptedCheckpoint, ExternalCosigner


def rejected(call, expected_state):
    try:
        call()
    except ValueError:
        pass
    else:
        raise AssertionError("view should have been rejected")
    assert signer.accepted == expected_state


def subtree_rejected(call, cosigner, expected_state):
    with patch("prepare.cosign") as forbidden_cosign:
        try:
            call()
        except ValueError:
            pass
        else:
            raise AssertionError("subtree should have been rejected")
    forbidden_cosign.assert_not_called()
    assert cosigner.accepted is expected_state


entries = [bytes([i]) for i in range(8)]
for invalid_log in [True, 0, 65536, "1", None]:
    try:
        ExternalCosigner(
            "32473.102", Path("external.key"), "32473.101",
            "ecdsa-p256", log=invalid_log)
    except ValueError as error:
        assert str(error) == "invalid issuance log number"
    else:
        raise AssertionError("invalid issuance log number was accepted")

signer = ExternalCosigner(
    "32473.102", Path("external.key"), "32473.101", "ecdsa-p256")

rejected(lambda: signer.cosign_accepted(), None)

first = AcceptedCheckpoint(3, core.root(entries[:3]))
assert signer.accept_view(first.tree_size, first.root_hash) == first
assert signer.accepted == first

with patch("prepare.cosign", return_value=(signer.identity, b"signature")) as cosign:
    assert signer.cosign_accepted(timestamp=123) == (
        signer.identity, b"signature")
cosign.assert_called_once_with(
    signer.identity, signer.key, signer.ca_id, 0, first.tree_size,
    first.root_hash, signer.family, 123, signer.log)

grown = AcceptedCheckpoint(8, core.root(entries))
proof = core.consistency(entries, first.tree_size)
assert signer.accept_view(grown.tree_size, grown.root_hash, proof) == grown
assert signer.accepted == grown

# Same checkpoint is idempotent and leaves the exact accepted object in place.
accepted_grown = signer.accepted
assert signer.accept_view(grown.tree_size, grown.root_hash) is accepted_grown

different_root = bytes([grown.root_hash[0] ^ 1]) + grown.root_hash[1:]
rejected(lambda: signer.accept_view(grown.tree_size, different_root), grown)
rejected(lambda: signer.accept_view(7, core.root(entries[:7])), grown)

larger_entries = entries + [b"8"]
valid_proof = core.consistency(larger_entries, grown.tree_size)
corrupt_proof = [bytes([valid_proof[0][0] ^ 1]) + valid_proof[0][1:]]
rejected(lambda: signer.accept_view(
    len(larger_entries), core.root(larger_entries), corrupt_proof), grown)

forked_entries = list(larger_entries)
forked_entries[0] = b"fork"
rejected(lambda: signer.accept_view(
    len(forked_entries), core.root(forked_entries),
    core.consistency(forked_entries, grown.tree_size)), grown)

# Rejected views cannot become the signed checkpoint.
with patch("prepare.cosign", return_value=(signer.identity, b"signature")) as cosign:
    signer.cosign_accepted()
assert cosign.call_args.args[4:6] == (grown.tree_size, grown.root_hash)

# A subtree cannot be signed before this cosigner has accepted a checkpoint.
uninitialized = ExternalCosigner(
    signer.identity, signer.key, signer.ca_id, signer.family)
subtree_rejected(
    lambda: uninitialized.cosign_subtree(0, 4, core.root(entries[:4]), []),
    uninitialized, None)

# Every canonical covering subtree is signed using the standalone parameters.
accepted_before_subtrees = signer.accepted
for start, end in core.cover(0, grown.tree_size):
    subtree_hash = core.root(entries[start:end])
    subtree_proof = core.subtree_consistency(entries, start, end)
    with patch(
            "prepare.cosign",
            return_value=(signer.identity, b"subtree-signature")) as cosign:
        assert signer.cosign_subtree(
            start, end, subtree_hash, subtree_proof) == (
                signer.identity, b"subtree-signature")
    cosign.assert_called_once_with(
        signer.identity, signer.key, signer.ca_id, start, end,
        subtree_hash, signer.family, 0, signer.log)
    assert signer.accepted is accepted_before_subtrees

start, end = core.cover(0, grown.tree_size)[0]
subtree_hash = core.root(entries[start:end])
subtree_proof = core.subtree_consistency(entries, start, end)

# A structurally valid subtree outside the canonical cover is still rejected.
noncover = (0, 2)
subtree_rejected(lambda: signer.cosign_subtree(
    *noncover, core.root(entries[slice(*noncover)]),
    core.subtree_consistency(entries, *noncover)), signer,
    accepted_before_subtrees)

corrupt_hash = bytes([subtree_hash[0] ^ 1]) + subtree_hash[1:]
subtree_rejected(lambda: signer.cosign_subtree(
    start, end, corrupt_hash, subtree_proof), signer,
    accepted_before_subtrees)

corrupt_subtree_proof = list(subtree_proof)
corrupt_subtree_proof[0] = (
    bytes([corrupt_subtree_proof[0][0] ^ 1])
    + corrupt_subtree_proof[0][1:])
subtree_rejected(lambda: signer.cosign_subtree(
    start, end, subtree_hash, corrupt_subtree_proof), signer,
    accepted_before_subtrees)
subtree_rejected(lambda: signer.cosign_subtree(
    start, end, subtree_hash, subtree_proof[:-1]), signer,
    accepted_before_subtrees)

# Proofs and roots from another view cannot authorize this accepted view.
other_entries = list(entries)
other_entries[-1] = b"other-view"
other_proof = core.subtree_consistency(other_entries, start, end)
subtree_rejected(lambda: signer.cosign_subtree(
    start, end, subtree_hash, other_proof), signer,
    accepted_before_subtrees)

other_signer = ExternalCosigner(
    signer.identity, signer.key, signer.ca_id, signer.family)
other_signer.accept_view(len(other_entries), core.root(other_entries))
other_accepted = other_signer.accepted
subtree_rejected(lambda: other_signer.cosign_subtree(
    start, end, subtree_hash, subtree_proof), other_signer,
    other_accepted)

# Optional state survives restart and retains consistency enforcement.
with tempfile.TemporaryDirectory(prefix="mtc-cosigner-state-") as temporary:
    state_path = Path(temporary) / "accepted.json"
    persistent = ExternalCosigner(
        signer.identity, signer.key, signer.ca_id, signer.family,
        state_path=state_path)
    persisted_first = AcceptedCheckpoint(3, core.root(entries[:3]))
    assert persistent.accept_view(
        persisted_first.tree_size, persisted_first.root_hash
    ) == persisted_first
    assert state_path.read_bytes() == (
        b'{"log_number":1,"tree_size":3,"root_hash":"'
        + persisted_first.root_hash.hex().encode("ascii") + b'"}\n')

    restarted = ExternalCosigner(
        signer.identity, signer.key, signer.ca_id, signer.family,
        state_path=state_path)
    assert restarted.accepted == persisted_first

    persisted_grown = AcceptedCheckpoint(len(entries), core.root(entries))
    assert restarted.accept_view(
        persisted_grown.tree_size, persisted_grown.root_hash,
        core.consistency(entries, persisted_first.tree_size)
    ) == persisted_grown
    valid_state = state_path.read_bytes()
    accepted_after_restart = restarted.accepted

    def persistent_rejected(call):
        try:
            call()
        except ValueError:
            pass
        else:
            raise AssertionError("persisted view should have been rejected")
        assert restarted.accepted is accepted_after_restart
        assert state_path.read_bytes() == valid_state

    persistent_rejected(lambda: restarted.accept_view(
        7, core.root(entries[:7])))
    persistent_rejected(lambda: restarted.accept_view(
        persisted_grown.tree_size, different_root))
    persistent_rejected(lambda: restarted.accept_view(
        len(larger_entries), core.root(larger_entries), corrupt_proof))

    # Subtree authorization uses the checkpoint loaded from disk.
    loaded = ExternalCosigner(
        signer.identity, signer.key, signer.ca_id, signer.family,
        state_path=state_path)
    loaded_start, loaded_end = core.cover(0, len(entries))[0]
    loaded_hash = core.root(entries[loaded_start:loaded_end])
    loaded_proof = core.subtree_consistency(
        entries, loaded_start, loaded_end)
    with patch(
            "prepare.cosign",
            return_value=(loaded.identity, b"persisted-signature")) as cosign:
        loaded.cosign_subtree(
            loaded_start, loaded_end, loaded_hash, loaded_proof)
    cosign.assert_called_once_with(
        loaded.identity, loaded.key, loaded.ca_id, loaded_start, loaded_end,
        loaded_hash, loaded.family, 0, loaded.log)
    assert loaded.accepted == persisted_grown

    # Persisted checkpoints are bound to exactly one issuance log.  Loading a
    # log-1 checkpoint as log 2 fails without modifying the state file.
    log_1_bytes = state_path.read_bytes()
    try:
        ExternalCosigner(
            signer.identity, signer.key, signer.ca_id, signer.family,
            log=2, state_path=state_path)
    except ValueError as error:
        assert str(error) == "invalid persisted cosigner state"
    else:
        raise AssertionError("state from another issuance log was accepted")
    assert state_path.read_bytes() == log_1_bytes

    # Legacy state is deliberately not guessed to belong to log 1.
    legacy_path = Path(temporary) / "legacy.json"
    legacy_bytes = (
        b'{"tree_size":8,"root_hash":"'
        + core.root(entries).hex().encode("ascii") + b'"}\n')
    legacy_path.write_bytes(legacy_bytes)
    try:
        ExternalCosigner(
            signer.identity, signer.key, signer.ca_id, signer.family,
            state_path=legacy_path)
    except ValueError as error:
        assert str(error) == "invalid persisted cosigner state"
    else:
        raise AssertionError("legacy state without log_number was accepted")
    assert legacy_path.read_bytes() == legacy_bytes

    # A fresh log 2 has an independent empty history and may accept a
    # checkpoint with the same tree size as log 1.
    log_2_path = Path(temporary) / "accepted-log-2.json"
    log_2_entries = [b"log-2-" + bytes([i]) for i in range(len(entries))]
    log_2_checkpoint = AcceptedCheckpoint(
        len(log_2_entries), core.root(log_2_entries))
    log_2 = ExternalCosigner(
        signer.identity, signer.key, signer.ca_id, signer.family,
        log=2, state_path=log_2_path)
    assert log_2.accepted is None
    assert log_2.accept_view(
        log_2_checkpoint.tree_size, log_2_checkpoint.root_hash,
        core.consistency(log_2_entries, 0)) == log_2_checkpoint
    assert log_2.accepted == log_2_checkpoint
    assert loaded.accepted == persisted_grown
    assert log_2_checkpoint.tree_size == persisted_grown.tree_size
    assert log_2_checkpoint.root_hash != persisted_grown.root_hash
    assert b'"log_number":2' in log_2_path.read_bytes()

    restarted_log_2 = ExternalCosigner(
        signer.identity, signer.key, signer.ca_id, signer.family,
        log=2, state_path=log_2_path)
    assert restarted_log_2.accepted == log_2_checkpoint

    corrupt_states = [
        b"not json",
        b'{}',
        b'{"log_number":0,"tree_size":8,"root_hash":"'
        + b"00" * 32 + b'"}',
        b'{"log_number":true,"tree_size":8,"root_hash":"'
        + b"00" * 32 + b'"}',
        b'{"tree_size":-1,"root_hash":"' + b"00" * 32 + b'"}',
        b'{"tree_size":281474976710656,"root_hash":"'
        + b"00" * 32 + b'"}',
        b'{"tree_size":8,"root_hash":"not-hex"}',
        b'{"tree_size":8,"root_hash":"' + b"00" * 31 + b'"}',
    ]
    for index, corrupt in enumerate(corrupt_states):
        corrupt_path = Path(temporary) / f"corrupt-{index}.json"
        corrupt_path.write_bytes(corrupt)
        try:
            ExternalCosigner(
                signer.identity, signer.key, signer.ca_id, signer.family,
                state_path=corrupt_path)
        except ValueError as error:
            assert str(error) == "invalid persisted cosigner state"
        else:
            raise AssertionError("corrupt persisted state was accepted")

print("PASS: independent local external cosigner")
