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
    """Validate Section 7.4 evidence and return the trusted landmark prefix.

    reference_checkpoint must already have been authenticated and must satisfy
    the caller's Section 7.3 cosigner policy.

    A landmark is incorporated only when every covering subtree validates.
    If the reference checkpoint does not cover a landmark, or one of its
    Section 4.4 proofs does not validate, that landmark and all newer
    landmarks are discarded.
    """
    if type(log_number) is not int or not 1 <= log_number <= 0xffff:
        raise ValueError("log number")

    validate_sequence(sequence)
    all_landmarks = active(sequence, now)

    if max_active_landmarks is not None:
        if type(max_active_landmarks) is not int or max_active_landmarks < 0:
            raise ValueError("active landmark limit")
        landmarks = all_landmarks[:max_active_landmarks]
    else:
        landmarks = all_landmarks

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

    if not isinstance(evidence, (list, tuple)):
        raise ValueError("subtree evidence")

    # Evidence is keyed by interval so callers may supply evidence for all
    # active landmarks even when the acceptance limit retains only an older
    # prefix.
    by_interval = {}
    active_intervals = set()

    for landmark in all_landmarks:
        active_intervals.update(subtrees(sequence, landmark.number))

    for item in evidence:
        if not isinstance(item, SubtreeEvidence):
            raise ValueError("subtree evidence")

        interval = (item.start, item.end)
        if interval not in active_intervals:
            raise ValueError("unexpected subtree evidence interval")
        if interval in by_interval:
            raise ValueError("duplicate subtree evidence interval")
        if not isinstance(item.hash, bytes) or len(item.hash) != 32:
            raise ValueError("subtree hash")
        if not isinstance(item.proof, (list, tuple)):
            raise ValueError("subtree proof")

        by_interval[interval] = item

    trusted = []

    for landmark in landmarks:
        # Section 7.4 permits retaining the validated older prefix when the
        # reference checkpoint predates this landmark.
        if tree_size < landmark.tree_size:
            break

        landmark_trusted = []
        landmark_valid = True

        for start, end in subtrees(sequence, landmark.number):
            item = by_interval.get((start, end))

            # Missing or cryptographically invalid evidence makes this
            # landmark unusable; all newer landmarks are then discarded.
            if item is None:
                landmark_valid = False
                break

            try:
                valid = verify_subtree_consistency(
                    start, end, tree_size,
                    item.hash, root_hash, item.proof
                )
            except (TypeError, ValueError, IndexError):
                valid = False

            if not valid:
                landmark_valid = False
                break

            landmark_trusted.append(
                TrustedSubtree(log_number, start, end, item.hash)
            )

        if not landmark_valid:
            break

        # Never incorporate only part of a landmark.
        trusted.extend(landmark_trusted)

    return trusted
