"""Coordinate a persistent MTC issuance log with an external cosigner."""

from core import root


def synchronize_cosigner(log, cosigner, *, log_number=None):
    """Advance a cosigner from its accepted checkpoint to the local log state."""
    checkpoint = cosigner.accepted_checkpoint()
    local_log_number = getattr(log, "log_number", None)
    cosigner_log_number = getattr(cosigner, "log", None)

    if log_number is None:
        log_number = (local_log_number if local_log_number is not None
                      else cosigner_log_number)
    if type(log_number) is not int or not 1 <= log_number <= 65535:
        raise ValueError("issuance log number is required for synchronization")
    if local_log_number is not None and local_log_number != log_number:
        raise ValueError("local issuance log number mismatch")
    if cosigner_log_number != log_number:
        raise ValueError("cosigner issuance log number mismatch")

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
    if hasattr(accepted, "tree_size") and hasattr(accepted, "root_hash"):
        accepted = {
            "tree_size": accepted.tree_size,
            "root_hash": accepted.root_hash,
        }

    expected = {
        "tree_size": current["tree_size"],
        "root_hash": bytes.fromhex(current["hash"]),
    }
    if accepted != expected:
        raise ValueError("cosigner accepted unexpected checkpoint")

    return current, proof
