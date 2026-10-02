"""Coordinate a persistent MTC issuance log with an external cosigner."""

from core import root


def synchronize_cosigner(log, cosigner):
    """Advance a cosigner from its accepted checkpoint to the local log state."""
    checkpoint = cosigner.accepted_checkpoint()

    if checkpoint is None:
        old_state = {
            "tree_size": 0,
            "hash": root([]).hex(),
        }
    else:
        old_state = {
            "tree_size": checkpoint["tree_size"],
            "hash": checkpoint["root_hash"].hex(),
        }

    current, proof = log.prove_consistency(old_state)

    accepted = cosigner.accept_view(
        current["tree_size"],
        bytes.fromhex(current["hash"]),
        proof,
    )

    expected = {
        "tree_size": current["tree_size"],
        "root_hash": bytes.fromhex(current["hash"]),
    }
    if accepted != expected:
        raise ValueError("cosigner accepted unexpected checkpoint")

    return current, proof
