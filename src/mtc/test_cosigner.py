"""Focused tests for the independent local external cosigner."""

from pathlib import Path
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

print("PASS: independent local external cosigner")
