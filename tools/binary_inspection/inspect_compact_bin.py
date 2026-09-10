#!/usr/bin/env python3
"""Read, describe, and structurally validate Compact laboratory binary files."""
import argparse
import datetime as dt
import hashlib
import struct
from pathlib import Path


def need(data, offset, size, label):
    if offset + size > len(data):
        raise ValueError(f"truncated {label}: need {size} bytes at offset {offset}")
    return data[offset:offset + size]


def u16(data, offset):
    return struct.unpack("!H", need(data, offset, 2, "uint16"))[0]


def u32(data, offset):
    return struct.unpack("!I", need(data, offset, 4, "uint32"))[0]


def u64(data, offset):
    return struct.unpack("!Q", need(data, offset, 8, "uint64"))[0]


def timestamp(value):
    return dt.datetime.fromtimestamp(value, dt.timezone.utc).isoformat()


def parse_credential(data):
    if data[:4] != b"MTC2":
        raise ValueError("not an MTC2 Compact credential")
    name_length = u16(data, 4)
    expected = 55 + name_length
    if len(data) != expected:
        raise ValueError(f"invalid MTC2 length: expected {expected}, got {len(data)}")
    offset = 6
    name = need(data, offset, name_length, "DNS name").decode("ascii")
    offset += name_length
    not_before = u64(data, offset); offset += 8
    not_after = u64(data, offset); offset += 8
    spki_hash = need(data, offset, 32, "SPKI hash"); offset += 32
    purpose = data[offset]
    return {
        "format": "MTC2 Compact credential",
        "DNS name": name,
        "not before": f"{not_before} ({timestamp(not_before)})",
        "not after": f"{not_after} ({timestamp(not_after)})",
        "SHA-256 of DER SPKI": spki_hash.hex(),
        "purpose": f"{purpose} ({'serverAuth' if purpose == 1 else 'unknown'})",
    }


def parse_proof(data, credential=None):
    if data[:4] != b"MTP1":
        raise ValueError("not an MTP1 Compact proof")
    if len(data) < 45:
        raise ValueError("truncated MTP1 header")
    leaf_count = u32(data, 4)
    leaf_index = u32(data, 8)
    root = data[12:44]
    depth = data[44]
    expected = 45 + 32 * depth
    if len(data) != expected:
        raise ValueError(f"invalid MTP1 length: expected {expected}, got {len(data)}")
    if leaf_count == 0 or leaf_index >= leaf_count:
        raise ValueError("leaf index is outside the declared tree")
    siblings = [data[45+i*32:45+(i+1)*32] for i in range(depth)]
    result = {
        "format": "MTP1 Compact Merkle proof",
        "leaf count": leaf_count,
        "leaf index": leaf_index,
        "tree root": root.hex(),
        "proof depth": depth,
        "sibling hashes": [value.hex() for value in siblings],
        "structural validation": "PASS",
    }
    if credential is not None:
        node = hashlib.sha256(b"\x00" + credential).digest()
        position = leaf_index
        for sibling in siblings:
            pair = sibling + node if position & 1 else node + sibling
            node = hashlib.sha256(b"\x01" + pair).digest()
            position //= 2
        result["credential inclusion validation"] = "PASS" if node == root else "FAIL"
        if node != root:
            raise ValueError("credential does not match the proof root")
    return result


def parse_signed_root(data):
    if data[:4] != b"MTR2":
        raise ValueError("not an MTR2 signed root")
    if len(data) < 90:
        raise ValueError("truncated MTR2 root")
    signature_length = u16(data, 88)
    expected = 90 + signature_length
    if len(data) != expected:
        raise ValueError(f"invalid MTR2 length: expected {expected}, got {len(data)}")
    not_before, not_after = u64(data, 40), u64(data, 48)
    return {
        "format": "MTR2 Compact signed root",
        "leaf count": u32(data, 4),
        "tree root": data[8:40].hex(),
        "not before": f"{not_before} ({timestamp(not_before)})",
        "not after": f"{not_after} ({timestamp(not_after)})",
        "SHA-256 of authority DER SPKI": data[56:88].hex(),
        "signed header bytes": 88,
        "signature bytes": signature_length,
        "structural validation": "PASS",
    }


def parse_bundle(data):
    if data[:4] != b"MCB2":
        raise ValueError("not an MCB2 Compact bundle")
    credential_length = u16(data, 4)
    offset = 6
    credential = need(data, offset, credential_length, "credential"); offset += credential_length
    proof_length = u16(data, offset); offset += 2
    proof = need(data, offset, proof_length, "proof"); offset += proof_length
    root_length = u16(data, offset); offset += 2
    signed_root = need(data, offset, root_length, "signed root"); offset += root_length
    if offset != len(data):
        raise ValueError(f"unexpected trailing bytes at offset {offset}")
    credential_info = parse_credential(credential)
    proof_info = parse_proof(proof, credential)
    if signed_root:
        root_info = parse_signed_root(signed_root)
        if root_info["tree root"] != proof_info["tree root"]:
            raise ValueError("signed-root hash does not match proof root")
    else:
        root_info = "not embedded (normal persisted bundle; supplied separately)"
    return {
        "format": "MCB2 Compact bundle",
        "credential bytes": credential_length,
        "proof bytes": proof_length,
        "signed-root bytes": root_length,
        "credential": credential_info,
        "proof": proof_info,
        "signed root": root_info,
        "structural and inclusion validation": "PASS",
    }


def render(value, indent=0):
    prefix = "  " * indent
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                print(f"{prefix}{key}:")
                render(item, indent + 1)
            else:
                print(f"{prefix}{key}: {item}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            print(f"{prefix}[{index}] {item}")


def inspect(path, credential_path=None):
    data = path.read_bytes()
    magic = data[:4]
    credential = credential_path.read_bytes() if credential_path else None
    parsers = {
        b"MTC2": lambda value: parse_credential(value),
        b"MTP1": lambda value: parse_proof(value, credential),
        b"MCB2": lambda value: parse_bundle(value),
        b"MTR2": lambda value: parse_signed_root(value),
    }
    if magic not in parsers:
        label = magic.decode("ascii", "replace")
        raise ValueError(f"unsupported magic {label!r} ({magic.hex()})")
    print(f"File: {path}")
    print(f"Size: {len(data)} bytes")
    print(f"SHA-256: {hashlib.sha256(data).hexdigest()}")
    render(parsers[magic](data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--credential", type=Path,
                        help="MTC2 credential used to verify one MTP1 proof")
    args = parser.parse_args()
    if args.credential and len(args.files) != 1:
        parser.error("--credential requires exactly one proof file")
    failed = False
    for index, path in enumerate(args.files):
        if index:
            print()
        try:
            inspect(path, args.credential)
        except (OSError, ValueError, UnicodeError) as error:
            failed = True
            print(f"File: {path}\nValidation: FAIL\nError: {error}")
    raise SystemExit(1 if failed else 0)


if __name__ == "__main__":
    main()
