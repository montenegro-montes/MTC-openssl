"""Local external cosigner with an independent accepted issuance-log view."""

from dataclasses import dataclass
from pathlib import Path

import core
import prepare


@dataclass(frozen=True)
class AcceptedCheckpoint:
    tree_size: int
    root_hash: bytes


class ExternalCosigner:
    def __init__(self, identity, key, ca_id, family, log=1):
        self.identity = identity
        self.key = Path(key)
        self.ca_id = ca_id
        self.family = family
        self.log = log
        self.accepted = None

    def accept_view(self, tree_size, root_hash, consistency_proof=()):
        """Accept a first or consistent later checkpoint, otherwise raise."""
        proof = list(consistency_proof)
        if self.accepted is None:
            if not core.verify_consistency(
                    0, tree_size, core.root([]), root_hash, proof):
                raise ValueError("invalid initial checkpoint")
        elif tree_size < self.accepted.tree_size:
            raise ValueError("checkpoint rollback")
        elif tree_size == self.accepted.tree_size:
            if root_hash != self.accepted.root_hash:
                raise ValueError("conflicting checkpoint at same tree size")
            if proof:
                raise ValueError("unexpected consistency proof for same checkpoint")
            return self.accepted
        elif not core.verify_consistency(
                self.accepted.tree_size, tree_size,
                self.accepted.root_hash, root_hash, proof):
            raise ValueError("inconsistent checkpoint")

        self.accepted = AcceptedCheckpoint(tree_size, root_hash)
        return self.accepted

    def cosign_accepted(self, timestamp=0):
        """Cosign the currently accepted whole-log checkpoint."""
        if self.accepted is None:
            raise ValueError("no accepted checkpoint")
        return prepare.cosign(
            self.identity, self.key, self.ca_id, 0,
            self.accepted.tree_size, self.accepted.root_hash,
            self.family, timestamp, self.log)
