"""Deterministic draft-06 Section 6.4 landmark-sequence tests."""
from core import cover

from landmarks import (
    MAX_U48,
    Landmark,
    active,
    relative_proof,
    select,
    subtrees,
    validate_sequence,
)


def reject(sequence):
    try:
        validate_sequence(sequence)
    except ValueError:
        return
    raise AssertionError(f"accepted invalid landmark sequence: {sequence!r}")


sequence = [
    Landmark(0, 0, 0),
    Landmark(1, 8, 100),
    Landmark(2, 16, 200),
]

assert validate_sequence(sequence)

# Section 6.4.1: landmark zero and covering subtrees.
assert subtrees(sequence, 0) == cover(0, 0)
assert subtrees(sequence, 1) == cover(0, 8)
assert subtrees(sequence, 2) == cover(8, 16)

# Expiration defines active landmarks; landmark zero is never active.
assert active(sequence, 0) == sequence[1:]
assert active(sequence, 99) == sequence[1:]
assert active(sequence, 100) == [sequence[2]]
assert active(sequence, 199) == [sequence[2]]
assert active(sequence, 200) == []

# Section 6.4.4: choose the lowest-numbered landmark with tree_size > index.
for index in range(8):
    assert select(sequence, index) == sequence[1]

for index in range(8, 16):
    assert select(sequence, index) == sequence[2]

assert select(sequence, 16) is None

# Section 6.4.4: construct the proof relative to the selected landmark subtree.
entries = [bytes([i]) for i in range(16)]
expected_relative = {
    0: (1, 0, 4),
    3: (1, 0, 4),
    4: (1, 4, 8),
    7: (1, 4, 8),
    8: (2, 8, 12),
    11: (2, 8, 12),
    12: (2, 12, 16),
    15: (2, 12, 16),
}

for index, expected in expected_relative.items():
    landmark, start, end, path = relative_proof(entries, index, sequence)
    assert (landmark.number, start, end) == expected
    assert len(path) == 2

try:
    relative_proof(entries, 16, sequence)
except ValueError as exc:
    assert str(exc) == "landmark not allocated"
else:
    raise AssertionError("constructed proof without allocated landmark")

try:
    relative_proof(entries[:8], 8, sequence)
except ValueError as exc:
    assert str(exc) == "landmark exceeds available log"
else:
    raise AssertionError("constructed proof beyond available log")

# Mandatory sequence-invariant rejection.
reject([])
reject([Landmark(0, 1, 0)])
reject([Landmark(0, 0, 1)])
reject([
    Landmark(0, 0, 0),
    Landmark(2, 8, 100),
])
reject([
    Landmark(0, 0, 0),
    Landmark(1, 8, 100),
    Landmark(2, 8, 200),
])
reject([
    Landmark(0, 0, 0),
    Landmark(1, 16, 200),
    Landmark(2, 8, 200),
])
reject([
    Landmark(0, 0, 0),
    Landmark(1, 8, 200),
    Landmark(2, 16, 199),
])
reject([
    Landmark(0, 0, 0),
    Landmark(1, MAX_U48 + 1, 100),
])

# API boundary rejection.
for number in (-1, len(sequence)):
    try:
        subtrees(sequence, number)
    except ValueError:
        pass
    else:
        raise AssertionError("accepted invalid landmark number")

for now in (-1,):
    try:
        active(sequence, now)
    except ValueError:
        pass
    else:
        raise AssertionError("accepted negative time")

for index in (-1, MAX_U48 + 1):
    try:
        select(sequence, index)
    except ValueError:
        pass
    else:
        raise AssertionError("accepted invalid entry index")

print("PASS: draft-06 landmark sequence and selection")


# Section 6.4.3: strict active-landmark publication format.
from landmarks import decode_publication, encode_publication

publication_sequence = [
    Landmark(0, 0, 0),
    Landmark(1, 8, 100),
    Landmark(2, 16, 200),
    Landmark(3, 32, 300),
]

# At time 250, L3 is active and L2 is the first expired landmark.
encoded = encode_publication(publication_sequence, 250)
assert encoded == b"3\n32 300\n16 200\n"

latest, records = decode_publication(encoded, 250)
assert latest == 3
assert records == [(32, 300), (16, 200)]

# If all non-zero landmarks are active, landmark zero provides the
# required expired boundary.
encoded = encode_publication(publication_sequence, 50)
assert encoded == b"3\n32 300\n16 200\n8 100\n0 0\n"
assert decode_publication(encoded, 50) == (
    3,
    [(32, 300), (16, 200), (8, 100), (0, 0)],
)

def reject_publication(data, now=250):
    try:
        decode_publication(data, now)
    except ValueError:
        return
    raise AssertionError(f"accepted invalid publication: {data!r}")


# Missing final newline and extraneous whitespace.
reject_publication(b"3\n32 300\n16 200")
reject_publication(b"3 \n32 300\n16 200\n")
reject_publication(b"3\n32  300\n16 200\n")
reject_publication(b"3\n32 300 \n16 200\n")
reject_publication(b"3\n 32 300\n16 200\n")

# Non-canonical or malformed integers.
reject_publication(b"03\n32 300\n16 200\n")
reject_publication(b"3\n032 300\n16 200\n")
reject_publication(b"3\n32 x\n16 200\n")

# Tree sizes must strictly decrease.
reject_publication(b"3\n32 300\n32 200\n")
reject_publication(b"3\n16 300\n32 200\n")

# Expirations must monotonically decrease in publication order.
reject_publication(b"3\n32 200\n16 300\n")

# At least one published landmark must be expired.
reject_publication(b"3\n32 300\n16 260\n", now=250)

# There cannot be more than latest_landmark + 1 records.
reject_publication(b"1\n16 300\n8 200\n0 0\n")

# uint48 bounds.
reject_publication(
    f"{MAX_U48 + 1}\n32 300\n16 200\n".encode()
)
reject_publication(
    f"3\n{MAX_U48 + 1} 300\n16 200\n".encode()
)

print("PASS: draft-06 landmark publication")
