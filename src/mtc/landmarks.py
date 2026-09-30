"""Draft-06 landmark sequence semantics.

This module models Section 6.4 landmarks only.  It does not authenticate
checkpoints, persist log state, distribute trusted subtrees, or implement
application-protocol certificate selection.
"""
from dataclasses import dataclass

from core import cover


MAX_U48 = (1 << 48) - 1


@dataclass(frozen=True)
class Landmark:
    number: int
    tree_size: int
    expiration: int


def validate_sequence(sequence):
    """Validate the mandatory draft-06 Section 6.4.1 sequence invariants."""
    if not sequence:
        raise ValueError("empty landmark sequence")

    first = sequence[0]
    if first != Landmark(0, 0, 0):
        raise ValueError("invalid landmark zero")

    for number, landmark in enumerate(sequence):
        if landmark.number != number:
            raise ValueError("non-consecutive landmark number")
        if not 0 <= landmark.tree_size <= MAX_U48:
            raise ValueError("landmark tree size")
        if landmark.expiration < 0:
            raise ValueError("landmark expiration")

        if number:
            previous = sequence[number - 1]
            if landmark.tree_size <= previous.tree_size:
                raise ValueError("non-increasing landmark tree size")
            if landmark.expiration < previous.expiration:
                raise ValueError("decreasing landmark expiration")

    return True


def subtrees(sequence, number):
    """Return the two covering subtrees for landmark number."""
    validate_sequence(sequence)

    if not 0 <= number < len(sequence):
        raise ValueError("landmark number")

    if number == 0:
        return cover(0, 0)

    return cover(sequence[number - 1].tree_size,
                 sequence[number].tree_size)


def active(sequence, now):
    """Return active landmarks in ascending landmark-number order."""
    validate_sequence(sequence)

    if now < 0:
        raise ValueError("time")

    return [
        landmark for landmark in sequence[1:]
        if landmark.expiration > now
    ]


def select(sequence, index):
    """Select the lowest-numbered landmark whose tree size exceeds index."""
    validate_sequence(sequence)

    if not 0 <= index <= MAX_U48:
        raise ValueError("entry index")

    for landmark in sequence[1:]:
        if landmark.tree_size > index:
            return landmark

    return None


def encode_publication(sequence, now):
    """Encode draft-06 Section 6.4.3 active-landmark publication."""
    validate_sequence(sequence)
    if now < 0:
        raise ValueError("time")

    latest = sequence[-1]
    lines = [str(latest.number)]

    # Publish newest-to-oldest through the first expired landmark.
    for landmark in reversed(sequence):
        lines.append(f"{landmark.tree_size} {landmark.expiration}")
        if landmark.expiration <= now:
            break
    else:
        raise ValueError("publication lacks expired landmark")

    return ("\n".join(lines) + "\n").encode("ascii")


def decode_publication(data, now):
    """Strictly decode draft-06 Section 6.4.3 publication format."""
    if now < 0:
        raise ValueError("time")
    if not isinstance(data, bytes):
        raise ValueError("publication type")
    if not data or not data.endswith(b"\n"):
        raise ValueError("publication newline")

    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("publication encoding") from exc

    lines = text[:-1].split("\n")
    if len(lines) < 2:
        raise ValueError("publication lines")

    def decimal(value):
        if not value or not value.isdigit():
            raise ValueError("publication integer")
        # Require canonical decimal integers.
        if len(value) > 1 and value[0] == "0":
            raise ValueError("publication integer")
        return int(value)

    latest = decimal(lines[0])
    if latest > MAX_U48:
        raise ValueError("latest landmark")

    records = []
    for line in lines[1:]:
        parts = line.split(" ")
        if len(parts) != 2 or not all(parts):
            raise ValueError("publication whitespace")
        tree_size = decimal(parts[0])
        expiration = decimal(parts[1])
        if tree_size > MAX_U48:
            raise ValueError("landmark tree size")
        records.append((tree_size, expiration))

    if len(records) > latest + 1:
        raise ValueError("too many landmark lines")

    for previous, current in zip(records, records[1:]):
        if current[0] >= previous[0]:
            raise ValueError("tree sizes not decreasing")
        if current[1] > previous[1]:
            raise ValueError("expirations not decreasing")

    if not any(expiration <= now for _, expiration in records):
        raise ValueError("publication lacks expired landmark")

    return latest, records
