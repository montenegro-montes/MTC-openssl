"""Tests for draft-07 Section 7.4 trusted subtrees."""

import tempfile
from dataclasses import replace
from pathlib import Path

from core import root
from landmarks import Landmark
from local_log import LocalLog
from trusted_subtrees import (
    SubtreeEvidence,
    TrustedSubtree,
    build_evidence,
    decode_trusted_subtrees,
    encode_trusted_subtrees,
    validate_trusted_subtrees,
)


def fail(fn, text):
    try:
        fn()
    except (ValueError, IndexError):
        return
    raise AssertionError(text)


def populated_log(count=16):
    temp = tempfile.TemporaryDirectory()
    log = LocalLog(Path(temp.name) / "log")
    for i in range(count):
        log.append(bytes([i]))
    return temp, log


sequence = [
    Landmark(0, 0, 0),
    Landmark(1, 8, 100),
    Landmark(2, 16, 200),
]

temp, log = populated_log()
try:
    evidence = build_evidence(log, sequence, now=50)
    checkpoint = log.state()

    trusted = validate_trusted_subtrees(
        1, sequence, 50, checkpoint, evidence
    )

    assert [(x.log_number, x.start, x.end) for x in trusted] == [
        (1, 0, 4),
        (1, 4, 8),
        (1, 8, 12),
        (1, 12, 16),
    ]

    with log._locked():
        entries, _ = log._read()

    assert trusted[0].hash == root(entries[0:4])
    assert trusted[1].hash == root(entries[4:8])
    assert trusted[2].hash == root(entries[8:12])
    assert trusted[3].hash == root(entries[12:16])

    # Section 7.4 permits retaining the older validated prefix when the
    # reference checkpoint does not yet cover a newer active landmark.
    prefix_temp, prefix_log = populated_log(8)
    try:
        checkpoint8 = prefix_log.state()
        evidence8 = build_evidence(
            prefix_log,
            [
                Landmark(0, 0, 0),
                Landmark(1, 8, 100),
            ],
            now=50,
        )
        prefix = validate_trusted_subtrees(
            1, sequence, 50, checkpoint8, evidence8
        )
        assert [(x.start, x.end) for x in prefix] == [
            (0, 4),
            (4, 8),
        ]
    finally:
        prefix_temp.cleanup()

    # A corrupted trusted-subtree hash must not validate.
    bad_hash = bytearray(evidence[0].hash)
    bad_hash[0] ^= 1
    corrupted_hash = [
        replace(evidence[0], hash=bytes(bad_hash)),
        *evidence[1:],
    ]
    assert validate_trusted_subtrees(
        1, sequence, 50, checkpoint, corrupted_hash
    ) == []

    # Failure in landmark 2 retains landmark 1 but discards landmark 2.
    assert evidence[2].proof
    bad_node = bytearray(evidence[2].proof[0])
    bad_node[0] ^= 1
    corrupted_proof = list(evidence)
    corrupted_proof[2] = replace(
        evidence[2],
        proof=(bytes(bad_node),) + evidence[2].proof[1:],
    )
    prefix = validate_trusted_subtrees(
        1, sequence, 50, checkpoint, corrupted_proof
    )
    assert [(x.start, x.end) for x in prefix] == [
        (0, 4),
        (4, 8),
    ]

    # Missing evidence in landmark 2 retains the complete older landmark 1.
    prefix = validate_trusted_subtrees(
        1, sequence, 50, checkpoint, evidence[:-1]
    )
    assert [(x.start, x.end) for x in prefix] == [
        (0, 4),
        (4, 8),
    ]

    # Missing evidence in landmark 1 prevents incorporation of it and all
    # newer landmarks.
    assert validate_trusted_subtrees(
        1, sequence, 50, checkpoint, evidence[1:]
    ) == []

    # Duplicate evidence remains structurally invalid.
    fail(
        lambda: validate_trusted_subtrees(
            1, sequence, 50, checkpoint, evidence + [evidence[-1]]
        ),
        "accepted duplicate evidence",
    )

    # Evidence ordering is irrelevant; intervals identify the proofs.
    reordered = validate_trusted_subtrees(
        1, sequence, 50, checkpoint, list(reversed(evidence))
    )
    assert [(x.start, x.end) for x in reordered] == [
        (0, 4),
        (4, 8),
        (8, 12),
        (12, 16),
    ]

    # Log numbers are configuration, not implicit constants.
    for bad_log in (0, -1, 1 << 16, "1"):
        fail(
            lambda bad_log=bad_log: validate_trusted_subtrees(
                bad_log, sequence, 50, checkpoint, evidence
            ),
            "accepted invalid log number",
        )

    # The CA-side builder cannot claim a landmark beyond its log.
    short_temp, short_log = populated_log(15)
    try:
        fail(
            lambda: build_evidence(short_log, sequence, now=50),
            "built evidence beyond local log",
        )
    finally:
        short_temp.cleanup()

    # Bounding active landmarks discards the newest ones, as Section 7.4 says.
    limited = validate_trusted_subtrees(
        1, sequence, 50, checkpoint, evidence,
        max_active_landmarks=1,
    )
    assert [(x.start, x.end) for x in limited] == [
        (0, 4),
        (4, 8),
    ]

    # At time 150 only landmark 2 remains active.
    later_evidence = build_evidence(log, sequence, now=150)
    later = validate_trusted_subtrees(
        1, sequence, 150, checkpoint, later_evidence
    )
    assert [(x.start, x.end) for x in later] == [
        (8, 12),
        (12, 16),
    ]

    # No active landmarks means no trusted subtrees and no evidence.
    assert build_evidence(log, sequence, now=250) == []
    assert validate_trusted_subtrees(
        1, sequence, 250, checkpoint, []
    ) == []

    # Evidence from a different same-sized tree must not validate against
    # this authenticated checkpoint.
    different_temp = tempfile.TemporaryDirectory()
    try:
        different = LocalLog(Path(different_temp.name) / "log")
        for i in range(16):
            different.append(b"x" + bytes([i]))
        foreign = build_evidence(different, sequence, now=50)
        assert validate_trusted_subtrees(
            1, sequence, 50, checkpoint, foreign
        ) == []
    finally:
        different_temp.cleanup()

finally:
    temp.cleanup()

# MTS1 uses the same positive, power-of-two, aligned intervals as Chromium.
valid_mts1 = encode_trusted_subtrees([
    TrustedSubtree(1, 0, 4, b"\x11" * 32),
])
assert decode_trusted_subtrees(valid_mts1) == [
    TrustedSubtree(1, 0, 4, b"\x11" * 32),
]

for start, end in ((0, 0), (0, 3)):
    invalid = TrustedSubtree(1, start, end, b"\x11" * 32)
    fail(
        lambda invalid=invalid: encode_trusted_subtrees([invalid]),
        "encoded invalid MTS1 subtree interval",
    )
    encoded = (
        b"MTS1\x00\x01\x00\x01"
        + start.to_bytes(6, "big")
        + end.to_bytes(6, "big")
        + b"\x11" * 32
    )
    fail(
        lambda encoded=encoded: decode_trusted_subtrees(encoded),
        "decoded invalid MTS1 subtree interval",
    )

print("PASS: draft-07 trusted subtrees")
