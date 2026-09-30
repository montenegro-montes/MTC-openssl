"""Draft-06 Section 7.4 trusted-subtree validation.

This module validates landmark-subtree evidence against an already
authenticated reference checkpoint.  Checkpoint authentication and cosigner
policy enforcement remain the caller's responsibility.
"""

from dataclasses import dataclass

from core import root, subtree_consistency, verify_subtree_consistency
from landmarks import active, subtrees, validate_sequence


@dataclass(frozen=True)
class TrustedSubtree:
    log_number: int
    start: int
    end: int
    hash: bytes


@dataclass(frozen=True)
class SubtreeEvidence:
    start: int
    end: int
    hash: bytes
    proof: tuple


def build_evidence(log, sequence, now):
    """Build Section 4.4 evidence from the CA/log side."""
    validate_sequence(sequence)
    landmarks = active(sequence, now)

    if not landmarks:
        return []

    with log._locked():
        entries, _ = log._read()

        if landmarks[-1].tree_size > len(entries):
            raise ValueError("log does not contain latest active landmark")

        evidence = []
        for landmark in landmarks:
            for start, end in subtrees(sequence, landmark.number):
                if end > len(entries):
                    raise ValueError("landmark subtree exceeds log")
                evidence.append(
                    SubtreeEvidence(
                        start,
                        end,
                        root(entries[start:end]),
                        tuple(subtree_consistency(entries, start, end)),
                    )
                )

    return evidence


def validate_trusted_subtrees(
        log_number, sequence, now, reference_checkpoint, evidence,
        max_active_landmarks=None):
    """Validate Section 7.4 evidence and return trusted subtrees.

    reference_checkpoint must already have been authenticated and must satisfy
    the caller's Section 7.3 cosigner policy.
    """
    if type(log_number) is not int or not 1 <= log_number <= 0xffff:
        raise ValueError("log number")

    validate_sequence(sequence)
    landmarks = active(sequence, now)

    if max_active_landmarks is not None:
        if type(max_active_landmarks) is not int or max_active_landmarks < 0:
            raise ValueError("active landmark limit")
        # Section 7.4 permits discarding the newest landmarks to meet the limit.
        landmarks = landmarks[:max_active_landmarks]

    if not landmarks:
        if evidence:
            raise ValueError("unexpected subtree evidence")
        return []

    if (not isinstance(reference_checkpoint, dict)
            or set(reference_checkpoint) != {"tree_size", "hash"}):
        raise ValueError("reference checkpoint")

    tree_size = reference_checkpoint["tree_size"]
    root_hex = reference_checkpoint["hash"]

    if (type(tree_size) is not int or not 0 <= tree_size < 1 << 48
            or not isinstance(root_hex, str) or len(root_hex) != 64):
        raise ValueError("reference checkpoint")

    try:
        root_hash = bytes.fromhex(root_hex)
    except ValueError as exc:
        raise ValueError("reference checkpoint") from exc

    if len(root_hash) != 32:
        raise ValueError("reference checkpoint")

    # Section 7.4: checkpoint must cover the latest landmark being accepted.
    if tree_size < landmarks[-1].tree_size:
        raise ValueError("reference checkpoint precedes latest landmark")

    expected = []
    for landmark in landmarks:
        expected.extend(subtrees(sequence, landmark.number))

    if len(evidence) != len(expected):
        raise ValueError("subtree evidence count")

    trusted = []
    for item, (start, end) in zip(evidence, expected):
        if not isinstance(item, SubtreeEvidence):
            raise ValueError("subtree evidence")
        if (item.start, item.end) != (start, end):
            raise ValueError("subtree evidence interval")
        if len(item.hash) != 32:
            raise ValueError("subtree hash")

        if not verify_subtree_consistency(
                start, end, tree_size, item.hash, root_hash, item.proof):
            raise ValueError("subtree consistency proof")

        trusted.append(
            TrustedSubtree(log_number, start, end, item.hash)
        )

    return trusted
