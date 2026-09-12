"""Canonical PCA2 advertisements; Stage-A PCA1 is delegated unchanged."""
import sys
from functools import lru_cache
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'pcma'))
from core import (FormatError, NodeKey, depth_for, encode_advertisement,
                  decode_advertisement)

VERSION = 1
MODES = {'coordinates': 1, 'bitmap': 2, 'trimmed-bitmap': 3, 'ranges': 4, 'hybrid': 5}
SCHEMES = ('baseline', 'coordinates', 'bitmap', 'ranges', 'hybrid')


def uint(value):
    if not 0 <= value <= 65535:
        raise FormatError('integer out of range')
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, count):
        if self.pos + count > len(self.data):
            raise FormatError('truncated advertisement')
        value = self.data[self.pos:self.pos + count]
        self.pos += count
        return value

    def integer(self):
        start, value = self.pos, 0
        for shift in (0, 7, 14):
            byte = self.take(1)[0]
            value |= (byte & 127) << shift
            if not byte & 128:
                if self.data[start:self.pos] != uint(value):
                    raise FormatError('noncanonical integer')
                return value
        raise FormatError('oversized integer')


@lru_cache(maxsize=32)
def universe(n, root):
    """Level-major, index-minor nodes, excluding the trusted root."""
    depth_for(n)
    result, width = [], n
    for level in range(depth_for(n)):
        result.extend(NodeKey(root, level, i) for i in range(width))
        width = (width + 1) // 2
    return tuple(result)


@lru_cache(maxsize=32)
def positions_for(n, root):
    return {key: i for i, key in enumerate(universe(n, root))}


def state(n, root, keys):
    if len(root) != 32:
        raise FormatError('root must be 32 bytes')
    nodes = universe(n, root)
    positions = positions_for(n, root)
    keys = tuple(keys)
    if len(set(keys)) != len(keys):
        raise FormatError('duplicate state entries')
    if any(key not in positions for key in keys):
        raise FormatError('invalid root or coordinates')
    return nodes, sorted(positions[key] for key in keys)


def body(mode, ids, total):
    if mode == 'coordinates':
        return uint(len(ids)) + b''.join(uint(i) for i in ids)
    if mode in ('bitmap', 'trimmed-bitmap'):
        bits = bytearray((total + 7) // 8)
        for i in ids:
            bits[i // 8] |= 1 << (i % 8)
        if mode == 'trimmed-bitmap':
            bits = bits.rstrip(b'\0')
            return uint(len(bits)) + bits
        return bytes(bits)
    if mode == 'ranges':
        ranges = []
        for i in ids:
            if ranges and ranges[-1][0] + ranges[-1][1] == i:
                ranges[-1][1] += 1
            else:
                ranges.append([i, 1])
        return uint(len(ranges)) + b''.join(uint(start) + uint(length) for start, length in ranges)
    raise FormatError('unknown encoding mode')


def encode(scheme, n, root, keys):
    keys = tuple(keys)
    nodes, ids = state(n, root, keys)
    if scheme == 'baseline':
        return encode_advertisement(root, keys)
    if scheme not in MODES:
        raise FormatError('unknown encoding mode')
    header = b'PCA2' + bytes([VERSION, MODES[scheme]]) + root + uint(n)
    if scheme == 'hybrid':
        # Length first, then numerical mode is the deterministic tie break.
        candidates = [bytes([MODES[m]]) + body(m, ids, len(nodes))
                      for m in ('coordinates', 'bitmap', 'trimmed-bitmap', 'ranges')]
        return header + min(candidates, key=lambda b: (len(b), b[0]))
    return header + body(scheme, ids, len(nodes))


def decode(data, n, root, scheme):
    nodes, _ = state(n, root, ())
    if scheme == 'baseline':
        decoded_root, entries = decode_advertisement(data)
        keys = tuple(NodeKey(decoded_root, level, index) for level, index in entries)
        state(n, root, keys)
        if decoded_root != root:
            raise FormatError('wrong root')
        return frozenset(keys)
    r = Reader(data)
    if r.take(4) != b'PCA2' or r.take(1)[0] != VERSION:
        raise FormatError('unknown format/version')
    mode = r.take(1)[0]
    if scheme not in MODES or mode != MODES[scheme]:
        raise FormatError('unknown or unexpected encoding mode')
    if r.take(32) != root or r.integer() != n:
        raise FormatError('wrong root/tree')
    if scheme == 'hybrid':
        mode = r.take(1)[0]
    if mode == 1:
        count = r.integer()
        if count > len(nodes):
            raise FormatError('too many nodes')
        ids = [r.integer() for _ in range(count)]
    elif mode in (2, 3):
        size = (len(nodes) + 7) // 8
        length = size if mode == 2 else r.integer()
        if length > size:
            raise FormatError('oversized bitmap')
        bits = r.take(length)
        ids = [i for i in range(length * 8) if bits[i // 8] & (1 << (i % 8))]
    elif mode == 4:
        count = r.integer()
        if count > len(nodes):
            raise FormatError('too many ranges')
        ids = []
        for _ in range(count):
            start, length = r.integer(), r.integer()
            if not length or start + length > len(nodes) or (ids and start <= ids[-1] + 1):
                raise FormatError('invalid range')
            ids.extend(range(start, start + length))
    else:
        raise FormatError('unknown encoding mode')
    if r.pos != len(data) or any(i >= len(nodes) for i in ids):
        raise FormatError('trailing data or invalid coordinates/padding')
    if ids != sorted(set(ids)):
        raise FormatError('duplicate or unordered entries')
    keys = frozenset(nodes[i] for i in ids)
    if encode(scheme, n, root, keys) != data:
        raise FormatError('noncanonical representation')
    return keys
