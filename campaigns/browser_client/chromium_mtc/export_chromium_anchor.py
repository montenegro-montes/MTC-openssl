#!/usr/bin/env python3
"""Export an existing local MCF1 landmark trust configuration for Chromium.

MCF1 remains a local laboratory storage format. This exporter does not turn
MCF1 into a protocol format; it only creates an explicit interoperability
configuration for the controlled Chromium Plants-05 experiment.
"""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src/mtc"))

import core
from trust_ids import configured_ids


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError("truncated MCF1 field")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def number(self, n):
        return int.from_bytes(self.take(n), "big")

    def vector(self, n=2):
        return self.take(self.number(n))

    def finish(self):
        if self.pos != len(self.data):
            raise ValueError("trailing bytes in MCF1")


def parse_landmark(raw):
    r = Reader(raw)

    if r.take(4) != b"MCF1":
        raise ValueError("not an MCF1 configuration")

    ca_id = r.vector(1).decode("ascii")

    signer_count = r.number(1)
    if signer_count != 2:
        raise ValueError("expected exactly two configured signers")

    signers = []
    for _ in range(signer_count):
        signer_id = r.vector(1).decode("ascii")
        spki = r.vector(2)
        signers.append({
            "id": signer_id,
            "id_hex": core.relid(signer_id).hex(),
            "spki_der_base64": base64.b64encode(spki).decode("ascii"),
            "spki_sha256": hashlib.sha256(spki).hexdigest(),
        })

    if signers[0]["id"] != ca_id:
        raise ValueError("first signer is not the configured CA")

    log_number = r.number(2)
    min_serial = r.number(8)
    max_serial = r.number(8)

    if not log_number:
        raise ValueError("invalid log number")
    if min_serial > max_serial:
        raise ValueError("invalid serial interval")

    landmark_number = r.number(4)
    tree_size = r.number(6)
    timestamp = r.number(8)
    checkpoint_root = r.take(32)

    # Checkpoint signatures are retained in MCF1 but Chromium only needs the
    # resulting trusted landmark subtrees after out-of-band trust validation.
    checkpoint_signatures = r.vector(2)

    subtree_count = r.number(1)
    subtrees = []
    for _ in range(subtree_count):
        start = r.number(6)
        end = r.number(6)
        digest = r.take(32)
        subtrees.append({
            "start": start,
            "end": end,
            "hash": digest.hex(),
        })

    r.finish()

    if landmark_number == 0:
        raise ValueError("invalid landmark number")
    if tree_size == 0:
        raise ValueError("invalid tree size")
    if max_serial != min_serial + tree_size - 1:
        raise ValueError("serial interval does not match tree size")

    expected_ranges = core.cover(0, tree_size)
    observed_ranges = [(s["start"], s["end"]) for s in subtrees]
    if observed_ranges != expected_ranges:
        raise ValueError(
            f"wrong subtree cover: {observed_ranges!r} != {expected_ranges!r}"
        )

    hashes = [bytes.fromhex(s["hash"]) for s in subtrees]
    if len(hashes) == 1:
        reconstructed_root = hashes[0]
    elif len(hashes) == 2:
        reconstructed_root = core.H(b"\1" + hashes[0] + hashes[1])
    else:
        raise ValueError(
            "current laboratory landmark format expects one or two subtrees"
        )

    if reconstructed_root != checkpoint_root:
        raise ValueError("trusted subtrees do not reconstruct checkpoint root")

    ids = configured_ids(raw, "landmark")

    return {
        "format": "chromium-mtc-plants05-lab",
        "version": 1,
        "spec": "plants-05",
        "source_format": "MCF1",
        "ca_id": ca_id,
        "ca_id_hex": core.relid(ca_id).hex(),
        "signers": signers,
        "log_number": log_number,
        "min_serial": min_serial,
        "min_serial_hex": f"0x{min_serial:016x}",
        "max_serial": max_serial,
        "max_serial_hex": f"0x{max_serial:016x}",
        "landmark": {
            "number": landmark_number,
            "tree_size": tree_size,
            "timestamp": timestamp,
            "checkpoint_root": checkpoint_root.hex(),
            "checkpoint_signatures_bytes": len(checkpoint_signatures),
            "requested_trust_anchor_id": ids["requested_id"],
            "requested_trust_anchor_id_hex":
                core.relid(ids["requested_id"]).hex(),
            "selected_trust_anchor_id": ids["selected_id"],
            "selected_trust_anchor_id_hex":
                core.relid(ids["selected_id"]).hex(),
            "trusted_subtrees": subtrees,
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trust", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()

    raw = args.trust.read_bytes()
    config = parse_landmark(raw)

    config["source"] = {
        "trust_file": args.trust.name,
        "trust_file_bytes": len(raw),
        "trust_file_sha256": hashlib.sha256(raw).hexdigest(),
    }

    manifest = args.trust.with_name("manifest.json")
    if manifest.is_file():
        metadata = json.loads(manifest.read_text())
        config["profile"] = metadata.get(
            "profile", metadata.get("crypto_family")
        )
        config["draft"] = metadata.get("draft")
        config["trust_anchor_draft"] = metadata.get("trust_anchor_draft")
        config["implementation_algorithm"] = metadata.get(
            "implementation_algorithm"
        )
        config["merkle_hash"] = metadata.get("merkle_hash")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(config, indent=2) + "\n")

    print(args.output)
    print(
        f"CA={config['ca_id']} "
        f"N={config['landmark']['tree_size']} "
        f"requested={config['landmark']['requested_trust_anchor_id']}"
    )


if __name__ == "__main__":
    main()
