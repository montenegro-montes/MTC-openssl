"""PCMA Stage-A formats over the repository's real Compact MTP1 proofs."""
from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass

HASH_BYTES = 32
CACHE_RECORD_BYTES = 69  # root(32) + level(1) + index(4) + hash(32)


class FormatError(ValueError):
    pass


@dataclass(frozen=True, order=True)
class NodeKey:
    root: bytes
    level: int
    index: int


@dataclass(frozen=True)
class MTP1:
    leaves: int
    leaf_index: int
    root: bytes
    siblings: tuple[bytes, ...]


def depth_for(leaves: int) -> int:
    if leaves < 1 or leaves > 1024:
        raise FormatError("tree size must be 1..1024")
    depth = 0
    while leaves > 1:
        leaves = (leaves + 1) // 2
        depth += 1
    return depth


def leaf_hash(credential: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + credential).digest()


def parent_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != HASH_BYTES or len(right) != HASH_BYTES:
        raise FormatError("Merkle hashes must be 32 bytes")
    return hashlib.sha256(b"\x01" + left + right).digest()


def decode_mtp1(data: bytes) -> MTP1:
    if len(data) < 45 or data[:4] != b"MTP1":
        raise FormatError("invalid MTP1 header")
    leaves, index = struct.unpack("!II", data[4:12])
    depth = data[44]
    if index >= leaves or depth != depth_for(leaves) or len(data) != 45 + 32 * depth:
        raise FormatError("invalid MTP1 dimensions")
    return MTP1(leaves, index, data[12:44], tuple(data[45+i*32:77+i*32] for i in range(depth)))


def proof_nodes(proof: MTP1) -> tuple[NodeKey, ...]:
    pos, width = proof.leaf_index, proof.leaves
    result = []
    for level in range(len(proof.siblings)):
        sibling = pos - 1 if pos & 1 else min(pos + 1, width - 1)
        result.append(NodeKey(proof.root, level, sibling))
        pos //= 2
        width = (width + 1) // 2
    return tuple(result)


def verify_mtp1(credential: bytes, proof: MTP1) -> dict[NodeKey, bytes]:
    current = leaf_hash(credential)
    pos, width = proof.leaf_index, proof.leaves
    authenticated = {NodeKey(proof.root, 0, pos): current}
    for level, sibling in enumerate(proof.siblings):
        sibling_pos = pos - 1 if pos & 1 else min(pos + 1, width - 1)
        if not (pos & 1) and pos + 1 == width and sibling != current:
            raise FormatError("noncanonical duplicated sibling")
        authenticated[NodeKey(proof.root, level, sibling_pos)] = sibling
        current = parent_hash(sibling, current) if pos & 1 else parent_hash(current, sibling)
        pos //= 2
        width = (width + 1) // 2
        authenticated[NodeKey(proof.root, level + 1, pos)] = current
    if current != proof.root:
        raise FormatError("MTP1 does not terminate at its declared root")
    return authenticated


def encode_advertisement(root: bytes, keys: list[NodeKey] | tuple[NodeKey, ...]) -> bytes:
    selected = sorted(set(keys), key=lambda key: (key.level, key.index))
    if len(root) != 32 or len(selected) > 65535 or any(k.root != root or not 0 <= k.level <= 255 or not 0 <= k.index < 2**32 for k in selected):
        raise FormatError("invalid PCA1 state")
    return b"PCA1" + root + struct.pack("!H", len(selected)) + b"".join(struct.pack("!BI", k.level, k.index) for k in selected)


def decode_advertisement(data: bytes) -> tuple[bytes, tuple[tuple[int, int], ...]]:
    if len(data) < 38 or data[:4] != b"PCA1":
        raise FormatError("invalid PCA1 header")
    count = struct.unpack("!H", data[36:38])[0]
    if len(data) != 38 + 5 * count:
        raise FormatError("invalid PCA1 length")
    entries = tuple(struct.unpack("!BI", data[38+i*5:43+i*5]) for i in range(count))
    if tuple(sorted(set(entries))) != entries:
        raise FormatError("PCA1 entries must be unique and canonical")
    return data[4:36], entries


def encode_mtp2(proof: MTP1, available: set[NodeKey]) -> tuple[bytes, int]:
    keys = proof_nodes(proof)
    transmitted = [key not in available for key in keys]
    bitmap_len = math.ceil(len(keys) / 8)
    bitmap = bytearray(bitmap_len)
    hashes = []
    for i, (send, value) in enumerate(zip(transmitted, proof.siblings)):
        if send:
            bitmap[i // 8] |= 1 << (7 - i % 8)
            hashes.append(value)
    header = b"MTP2" + struct.pack("!II", proof.leaves, proof.leaf_index) + proof.root + bytes([len(keys), bitmap_len])
    return header + bytes(bitmap) + b"".join(hashes), len(hashes)


def verify_mtp2(credential: bytes, data: bytes, cache: dict[NodeKey, bytes], trusted_root: bytes) -> dict[NodeKey, bytes]:
    if len(data) < 46 or data[:4] != b"MTP2":
        raise FormatError("invalid MTP2 header")
    leaves, index = struct.unpack("!II", data[4:12]); root = data[12:44]
    depth, bitmap_len = data[44], data[45]
    if root != trusted_root or index >= leaves or depth != depth_for(leaves) or bitmap_len != math.ceil(depth / 8):
        raise FormatError("MTP2 tree/root dimensions mismatch")
    if len(data) < 46 + bitmap_len:
        raise FormatError("truncated MTP2 bitmap")
    bitmap = data[46:46+bitmap_len]
    if depth % 8 and bitmap and bitmap[-1] & ((1 << (8-depth % 8)) - 1):
        raise FormatError("nonzero unused MTP2 bitmap bits")
    sent_count = sum((bitmap[i//8] >> (7-i%8)) & 1 for i in range(depth))
    if len(data) != 46 + bitmap_len + sent_count * 32:
        raise FormatError("MTP2 hash count mismatch")
    current = leaf_hash(credential); pos, width, offset = index, leaves, 46 + bitmap_len
    authenticated = {NodeKey(root, 0, pos): current}
    for level in range(depth):
        sibling_pos = pos - 1 if pos & 1 else min(pos + 1, width - 1)
        key = NodeKey(root, level, sibling_pos)
        sent = (bitmap[level//8] >> (7-level%8)) & 1
        if sent:
            sibling = data[offset:offset+32]; offset += 32
        else:
            sibling = cache.get(key)
            if sibling is None:
                raise FormatError("required cached node is missing")
        if not (pos & 1) and pos + 1 == width and sibling != current:
            raise FormatError("noncanonical duplicated sibling")
        authenticated[key] = sibling
        current = parent_hash(sibling, current) if pos & 1 else parent_hash(current, sibling)
        pos //= 2; width = (width + 1) // 2
        authenticated[NodeKey(root, level + 1, pos)] = current
    if current != trusted_root:
        raise FormatError("MTP2 verification did not reach trusted root")
    return authenticated
