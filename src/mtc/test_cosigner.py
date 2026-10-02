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

print("PASS: independent local external cosigner")
