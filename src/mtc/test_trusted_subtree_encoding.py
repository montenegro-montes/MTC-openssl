#!/usr/bin/env python3

from trusted_subtrees import (
    MAX_TRUSTED_SUBTREES,
    TrustedSubtree,
    decode_trusted_subtrees,
    encode_trusted_subtrees,
)


def rejected(call):
    try:
        call()
    except (ValueError, OverflowError):
        return
    raise AssertionError("invalid MTS1 accepted")


h1 = bytes.fromhex("11" * 32)
h2 = bytes.fromhex("22" * 32)

items = [
    TrustedSubtree(1, 0, 4, h1),
    TrustedSubtree(1, 4, 8, h2),
]

data = encode_trusted_subtrees(items)

assert data[:4] == b"MTS1"
assert len(data) == 6 + 2 * 46
assert decode_trusted_subtrees(data) == items

# Empty configuration is structurally valid.
assert decode_trusted_subtrees(encode_trusted_subtrees([])) == []

# Encoder validation.
rejected(lambda: encode_trusted_subtrees(
    [TrustedSubtree(0, 0, 4, h1)]
))
rejected(lambda: encode_trusted_subtrees(
    [TrustedSubtree(0x10000, 0, 4, h1)]
))
rejected(lambda: encode_trusted_subtrees(
    [TrustedSubtree(1, -1, 4, h1)]
))
rejected(lambda: encode_trusted_subtrees(
    [TrustedSubtree(1, 0, 1 << 48, h1)]
))
rejected(lambda: encode_trusted_subtrees(
    [TrustedSubtree(1, 1, 4, h1)]
))
rejected(lambda: encode_trusted_subtrees(
    [TrustedSubtree(1, 0, 4, b"x" * 31)]
))
rejected(lambda: encode_trusted_subtrees(
    [
        TrustedSubtree(1, 0, 4, h1),
        TrustedSubtree(1, 0, 4, h2),
    ]
))
rejected(lambda: encode_trusted_subtrees(
    [TrustedSubtree(1, i, i + 1, h1)
     for i in range(MAX_TRUSTED_SUBTREES + 1)]
))

# Decoder framing validation.
rejected(lambda: decode_trusted_subtrees(b"BAD!" + data[4:]))
rejected(lambda: decode_trusted_subtrees(data[:-1]))
rejected(lambda: decode_trusted_subtrees(data + b"X"))

# Decoder semantic validation: log zero.
bad = bytearray(data)
bad[6:8] = b"\\x00\\x00"
rejected(lambda: decode_trusted_subtrees(bytes(bad)))

# Decoder semantic validation: invalid subtree interval [1,4).
bad = bytearray(data)
bad[8:14] = (1).to_bytes(6, "big")
bad[14:20] = (4).to_bytes(6, "big")
rejected(lambda: decode_trusted_subtrees(bytes(bad)))

# Decoder duplicate validation.
duplicate = encode_trusted_subtrees([
    TrustedSubtree(1, 0, 4, h1),
    TrustedSubtree(1, 4, 8, h2),
])
bad = bytearray(duplicate)
bad[52:54] = bad[6:8]
bad[54:60] = bad[8:14]
bad[60:66] = bad[14:20]
rejected(lambda: decode_trusted_subtrees(bytes(bad)))

# A structurally complete configuration above the implementation limit
# is rejected specifically because its count exceeds the bound.
entry = (
    (1).to_bytes(2, "big")
    + (0).to_bytes(6, "big")
    + (1).to_bytes(6, "big")
    + h1
)
bad = (
    b"MTS1"
    + (MAX_TRUSTED_SUBTREES + 1).to_bytes(2, "big")
    + entry * (MAX_TRUSTED_SUBTREES + 1)
)
rejected(lambda: decode_trusted_subtrees(bad))

print("PASS: MTS1 trusted subtree encoding and validation")
