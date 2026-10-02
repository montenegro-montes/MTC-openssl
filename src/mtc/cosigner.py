"""Local external cosigner with an independent accepted issuance-log view."""

from dataclasses import dataclass
import json
import os
from pathlib import Path
import tempfile

import core
import prepare


@dataclass(frozen=True)
class AcceptedCheckpoint:
    tree_size: int
    root_hash: bytes


class ExternalCosigner:
    def __init__(self, identity, key, ca_id, family, log=1, state_path=None):
        if type(log) is not int or not 1 <= log <= 65535:
            raise ValueError("invalid issuance log number")
        self.identity = identity
        self.key = Path(key)
        self.ca_id = ca_id
        self.family = family
        self.log = log
        self.state_path = Path(state_path) if state_path is not None else None
        self.accepted = self._load_state()

    def _load_state(self):
        if self.state_path is None or not self.state_path.exists():
            return None
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(state, dict) or set(state) != {
                    "log_number", "tree_size", "root_hash"}:
                raise ValueError
            log_number = state["log_number"]
            tree_size = state["tree_size"]
            root_hex = state["root_hash"]
            if type(log_number) is not int or not 1 <= log_number <= 65535:
                raise ValueError
            if log_number != self.log:
                raise ValueError
            if type(tree_size) is not int or not 0 <= tree_size < 1 << 48:
                raise ValueError
            if not isinstance(root_hex, str) or len(root_hex) != 64:
                raise ValueError
            root_hash = bytes.fromhex(root_hex)
            if len(root_hash) != 32:
                raise ValueError
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise ValueError("invalid persisted cosigner state") from error
        return AcceptedCheckpoint(tree_size, root_hash)

    def _persist(self, accepted):
        if self.state_path is None:
            return
        data = json.dumps({
            "log_number": self.log,
            "tree_size": accepted.tree_size,
            "root_hash": accepted.root_hash.hex(),
        }, separators=(",", ":")) + "\n"
        descriptor, temporary = tempfile.mkstemp(
            prefix=self.state_path.name + ".", dir=self.state_path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.state_path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

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

        accepted = AcceptedCheckpoint(tree_size, root_hash)
        self._persist(accepted)
        self.accepted = accepted
        return self.accepted

    def cosign_accepted(self, timestamp=0):
        """Cosign the currently accepted whole-log checkpoint."""
        if self.accepted is None:
            raise ValueError("no accepted checkpoint")
        return prepare.cosign(
            self.identity, self.key, self.ca_id, 0,
            self.accepted.tree_size, self.accepted.root_hash,
            self.family, timestamp, self.log)

    def cosign_subtree(self, start, end, subtree_hash,
                       subtree_consistency_proof, timestamp=0):
        """Cosign a canonical subtree proven against the accepted checkpoint."""
        if self.accepted is None:
            raise ValueError("no accepted checkpoint")
        if (start, end) not in core.cover(0, self.accepted.tree_size):
            raise ValueError("subtree is not in the canonical cover")
        if not core.verify_subtree_consistency(
                start, end, self.accepted.tree_size, subtree_hash,
                self.accepted.root_hash, subtree_consistency_proof):
            raise ValueError("subtree is inconsistent with accepted checkpoint")
        return prepare.cosign(
            self.identity, self.key, self.ca_id, start, end, subtree_hash,
            self.family, timestamp, self.log)
