"""Canonical textual/binary Trust Anchor Identifier components.

Total identifier length is deliberately caller policy.  This module only
enforces canonical uint64 base-128 components and textual representation.
"""

MAX_UINT64 = (1 << 64) - 1


def encode_identifier(identifier):
    if not isinstance(identifier, str):
        raise ValueError("identifier")
    parts = identifier.split(".")
    if any(not part or not part.isascii() or not part.isdecimal()
           or str(int(part)) != part for part in parts):
        raise ValueError("noncanonical textual ID")
    output = bytearray()
    for part in parts:
        value = int(part)
        if value > MAX_UINT64:
            raise ValueError("ID component overflow")
        encoded = [value & 127]
        value >>= 7
        while value:
            encoded.append((value & 127) | 128)
            value >>= 7
        output.extend(reversed(encoded))
    return bytes(output)


def decode_identifier(encoded):
    if not isinstance(encoded, (bytes, bytearray)) or not encoded:
        raise ValueError("invalid ID")
    parts = []
    value = 0
    first = True
    for byte in encoded:
        if first and byte == 0x80:
            raise ValueError("noncanonical ID")
        if value >= 1 << 57:
            raise ValueError("ID component overflow")
        value = (value << 7) | (byte & 127)
        first = not byte & 128
        if first:
            parts.append(value)
            value = 0
    if not first:
        raise ValueError("unfinished ID")
    identifier = ".".join(map(str, parts))
    if encode_identifier(identifier) != bytes(encoded):
        raise ValueError("noncanonical ID")
    return identifier
