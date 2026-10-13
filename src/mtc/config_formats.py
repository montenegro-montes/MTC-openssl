"""Strict codecs for the experimental MCA2, MCP2, and MTB2 local formats.

These are local storage formats, not draft-07 wire structures.
"""

from dataclasses import dataclass

from core import (H, content, cover, decode_subtree_signature_block,
                  encode_subtree_signature_block, items, oid,
                  parse_mtc_ca_certificate, seq, uint)
from trust_anchor_ids import decode_identifier, encode_identifier


MAX_UINT16 = (1 << 16) - 1
MAX_UINT24 = (1 << 24) - 1
MAX_UINT48 = (1 << 48) - 1
MAX_UINT64 = (1 << 64) - 1


@dataclass(frozen=True)
class MCA2Authority:
    ca_id: str
    signers: tuple
    log_number: int
    min_serial: int
    max_serial: int


@dataclass(frozen=True)
class MCP2Checkpoint:
    tree_size: int
    timestamp: int
    root_hash: bytes
    signatures: tuple
    subtrees: tuple


@dataclass(frozen=True)
class MTB2Bundle:
    authority: MCA2Authority
    checkpoint: MCP2Checkpoint
    signaling_landmark: int | None = None


def reconcile_mtc_ca_certificate(authority, certificate):
    """Require duplicated MCA2 fields to match the authoritative MTC CA cert."""
    if not isinstance(authority,MCA2Authority) or not authority.signers:
        raise ValueError("MTC CA reconciliation")
    parsed=parse_mtc_ca_certificate(certificate)
    ca_signer_id,ca_spki=authority.signers[0]
    expected_algorithm=_signature_algorithm_for_spki(ca_spki)
    if (parsed["ca_id"]!=authority.ca_id or ca_signer_id!=authority.ca_id
            or parsed["spki"]!=ca_spki
            or parsed["signature_algorithm"]!=expected_algorithm
            or parsed["min_serial"]!=authority.min_serial
            or parsed["max_serial"]!=authority.max_serial):
        raise ValueError("MTC CA certificate and MCA2 disagree")
    return parsed


def _signature_algorithm_for_spki(spki):
    """Return the parameter-free MTC signing AlgorithmIdentifier for an SPKI."""
    try:
        fields=items(content(spki,0x30))
        if len(fields)!=2 or fields[0][0]!=0x30 or fields[1][0]!=3:raise ValueError
        algorithm=items(content(fields[0][2],0x30))
        if not algorithm or algorithm[0][0]!=6:raise ValueError
        if algorithm[0][2]==oid('1.2.840.10045.2.1'):
            if len(algorithm)!=2 or algorithm[1][0]!=6:raise ValueError
            curves={
                oid('1.2.840.10045.3.1.7'):'1.2.840.10045.4.3.2',
                oid('1.3.132.0.34'):'1.2.840.10045.4.3.3',
                oid('1.3.132.0.35'):'1.2.840.10045.4.3.4',
            }
            signature_oid=curves[algorithm[1][2]]
        else:
            if len(algorithm)!=1:raise ValueError
            signature_oid={
                oid(value):value for value in (
                    '2.16.840.1.101.3.4.3.17','2.16.840.1.101.3.4.3.18',
                    '2.16.840.1.101.3.4.3.19','2.16.840.1.101.3.4.3.20',
                    '2.16.840.1.101.3.4.3.22','2.16.840.1.101.3.4.3.24')
            }[algorithm[0][2]]
        return seq(oid(signature_oid))
    except (IndexError,KeyError,TypeError,ValueError):
        raise ValueError('unsupported MTC CA SPKI algorithm') from None


class _Reader:
    def __init__(self, data, label):
        if not isinstance(data, bytes):
            raise ValueError(label)
        self.data = data
        self.offset = 0
        self.label = label

    def take(self, length):
        if length < 0 or length > len(self.data) - self.offset:
            raise ValueError(f"truncated {self.label}")
        value = self.data[self.offset:self.offset + length]
        self.offset += length
        return value

    def number(self, width):
        return int.from_bytes(self.take(width), "big")

    def vector(self, width):
        return self.take(self.number(width))

    def finish(self):
        if self.offset != len(self.data):
            raise ValueError(f"trailing {self.label} data")


def _integer(value, maximum, label):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(label)
    return value


def _identifier(value, label):
    if not isinstance(value, str):
        raise ValueError(label)
    try:
        raw = value.encode("ascii")
        parts = value.split(".")
        if (not 1 <= len(raw) <= 255 or any(
                not part or not part.isascii() or not part.isdecimal()
                or str(int(part)) != part or int(part) > MAX_UINT64
                for part in parts)):
            raise ValueError
        encoded = encode_identifier(value)
        if not 1 <= len(encoded) <= 255:
            raise ValueError
    except (UnicodeError, ValueError, OverflowError):
        raise ValueError(label) from None
    return raw


def _spki(value):
    if not isinstance(value, bytes) or not value or len(value) > MAX_UINT24:
        raise ValueError("SPKI")
    return value


def encode_mca2(authority):
    if not isinstance(authority, MCA2Authority):
        raise ValueError("MCA2 authority")
    ca_id = _identifier(authority.ca_id, "CA ID")
    try:
        signer_values = tuple(authority.signers)
    except TypeError:
        raise ValueError("MCA2 signers") from None
    if len(signer_values) > MAX_UINT16:
        raise ValueError("too many MCA2 signers")
    encoded = bytearray(b"MCA2" + uint(len(ca_id), 1) + ca_id
                        + uint(len(signer_values), 2))
    seen = set()
    for value in signer_values:
        if not isinstance(value, tuple) or len(value) != 2:
            raise ValueError("MCA2 signer")
        identity, spki = value
        identity_bytes = _identifier(identity, "signer ID")
        if identity in seen:
            raise ValueError("duplicate MCA2 signer")
        seen.add(identity)
        spki = _spki(spki)
        encoded += (uint(len(identity_bytes), 1) + identity_bytes
                    + uint(len(spki), 3) + spki)
    log_number = _integer(authority.log_number, MAX_UINT16, "log number")
    if not log_number:
        raise ValueError("log number")
    minimum = _integer(authority.min_serial, MAX_UINT64, "min serial")
    maximum = _integer(authority.max_serial, MAX_UINT64, "max serial")
    if maximum < minimum:
        raise ValueError("serial range")
    return bytes(encoded + uint(log_number, 2) + uint(minimum, 8)
                 + uint(maximum, 8))


def decode_mca2(data):
    reader = _Reader(data, "MCA2")
    if reader.take(4) != b"MCA2":
        raise ValueError("MCA2 magic")
    try:
        ca_id = reader.vector(1).decode("ascii")
    except UnicodeError:
        raise ValueError("CA ID") from None
    _identifier(ca_id, "CA ID")
    signer_count = reader.number(2)
    signers = []
    seen = set()
    for _ in range(signer_count):
        try:
            identity = reader.vector(1).decode("ascii")
        except UnicodeError:
            raise ValueError("signer ID") from None
        _identifier(identity, "signer ID")
        if identity in seen:
            raise ValueError("duplicate MCA2 signer")
        seen.add(identity)
        signers.append((identity, _spki(reader.vector(3))))
    log_number = reader.number(2)
    minimum = reader.number(8)
    maximum = reader.number(8)
    reader.finish()
    authority = MCA2Authority(ca_id, tuple(signers), log_number, minimum, maximum)
    if not log_number or maximum < minimum:
        raise ValueError("MCA2 authority")
    return authority


def _encode_signature_block(values):
    try:
        values = tuple(values)
        for identity, signature in values:
            _identifier(identity, "signer ID")
            if not isinstance(signature, bytes) or len(signature) > MAX_UINT16:
                raise ValueError("signature")
        encoded = encode_subtree_signature_block(values)
    except (TypeError, ValueError, OverflowError):
        raise ValueError("MCP2 signatures") from None
    if len(encoded) > MAX_UINT24:
        raise ValueError("MCP2 signatures")
    return encoded


def _decode_signature_block(block):
    return decode_subtree_signature_block(block)


def _subtree(value):
    if not isinstance(value, tuple) or len(value) != 3:
        raise ValueError("MCP2 subtree")
    start, end, subtree_hash = value
    _integer(start, MAX_UINT48, "subtree start")
    _integer(end, MAX_UINT48, "subtree end")
    if start > end or not isinstance(subtree_hash, bytes) or len(subtree_hash) != 32:
        raise ValueError("MCP2 subtree")
    return start, end, subtree_hash


def _validate_checkpoint(checkpoint):
    if not isinstance(checkpoint, MCP2Checkpoint):
        raise ValueError("MCP2 checkpoint")
    size = _integer(checkpoint.tree_size, MAX_UINT48, "tree size")
    if not size:
        raise ValueError("tree size")
    _integer(checkpoint.timestamp, MAX_UINT64, "timestamp")
    if not isinstance(checkpoint.root_hash, bytes) or len(checkpoint.root_hash) != 32:
        raise ValueError("root hash")
    try:
        subtrees = tuple(map(_subtree, checkpoint.subtrees))
    except TypeError:
        raise ValueError("MCP2 subtrees") from None
    if len(subtrees) != 2 or tuple((start, end) for start, end, _ in subtrees) != tuple(cover(0, size)):
        raise ValueError("MCP2 covering subtrees")
    left, right = subtrees
    if size == 1:
        if right[2] != H(b"") or left[2] != checkpoint.root_hash:
            raise ValueError("MCP2 covering hashes")
    elif H(b"\x01" + left[2] + right[2]) != checkpoint.root_hash:
        raise ValueError("MCP2 covering hashes")
    signature_block = _encode_signature_block(checkpoint.signatures)
    return signature_block, subtrees


def encode_mcp2(checkpoint):
    signature_block, subtrees = _validate_checkpoint(checkpoint)
    encoded = bytearray(b"MCP2" + uint(checkpoint.tree_size, 6)
                        + uint(checkpoint.timestamp, 8) + checkpoint.root_hash
                        + uint(len(signature_block), 3) + signature_block)
    for start, end, subtree_hash in subtrees:
        encoded += uint(start, 6) + uint(end, 6) + subtree_hash
    return bytes(encoded)


def decode_mcp2(data):
    reader = _Reader(data, "MCP2")
    if reader.take(4) != b"MCP2":
        raise ValueError("MCP2 magic")
    size = reader.number(6)
    timestamp = reader.number(8)
    root_hash = reader.take(32)
    signature_values = _decode_signature_block(reader.vector(3))
    subtrees = tuple((reader.number(6), reader.number(6), reader.take(32))
                     for _ in range(2))
    reader.finish()
    checkpoint = MCP2Checkpoint(size, timestamp, root_hash,
                                signature_values, subtrees)
    _validate_checkpoint(checkpoint)
    return checkpoint


def encode_mtb2(bundle):
    if not isinstance(bundle, MTB2Bundle):
        raise ValueError("MTB2 bundle")
    authority = encode_mca2(bundle.authority)
    checkpoint = encode_mcp2(bundle.checkpoint)
    encoded = bytearray(b"MTB2" + uint(len(authority), 4) + authority
                        + uint(len(checkpoint), 4) + checkpoint)
    if bundle.signaling_landmark is None:
        encoded += b"\x00"
    else:
        landmark = _integer(bundle.signaling_landmark, MAX_UINT48,
                            "signaling landmark")
        if not landmark:
            raise ValueError("signaling landmark")
        encoded += b"\x01" + uint(landmark, 6)
    return bytes(encoded)


def decode_mtb2(data):
    reader = _Reader(data, "MTB2")
    if reader.take(4) != b"MTB2":
        raise ValueError("MTB2 magic")
    authority = decode_mca2(reader.vector(4))
    checkpoint = decode_mcp2(reader.vector(4))
    kind = reader.number(1)
    if kind == 0:
        landmark = None
    elif kind == 1:
        landmark = reader.number(6)
        if not landmark:
            raise ValueError("signaling landmark")
    else:
        raise ValueError("signaling kind")
    reader.finish()
    bundle = MTB2Bundle(authority, checkpoint, landmark)
    return bundle
