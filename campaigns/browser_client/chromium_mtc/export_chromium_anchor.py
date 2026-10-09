#!/usr/bin/env python3
"""Export an existing local MTB2 landmark trust configuration for Chromium.

MTB2 remains a local laboratory storage format. This exporter does not turn
MTB2 into a protocol format; it only creates an explicit interoperability
configuration for the controlled Chromium Plants-06 experiment.
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
from config_formats import decode_mtb2


def parse_anchor(raw):
    bundle = decode_mtb2(raw)
    authority = bundle.authority
    ca_id = authority.ca_id
    if len(authority.signers) != 2:
        raise ValueError("expected exactly two configured signers")
    signers = []
    for signer_id, spki in authority.signers:
        signers.append({
            "id": signer_id,
            "id_hex": core.relid(signer_id).hex(),
            "spki_der_base64": base64.b64encode(spki).decode("ascii"),
            "spki_sha256": hashlib.sha256(spki).hexdigest(),
        })

    if signers[0]["id"] != ca_id:
        raise ValueError("first signer is not the configured CA")

    log_number = authority.log_number
    min_serial, max_serial = authority.min_serial, authority.max_serial
    return bundle, {
        "format": "chromium-mtc-plants06-lab",
        "version": 1,
        "spec": "plants-06",
        "source_format": "MTB2",
        "ca_id": ca_id,
        "ca_id_hex": core.relid(ca_id).hex(),
        "signers": signers,
        "log_number": authority.log_number,
        "min_serial": authority.min_serial,
        "min_serial_hex": f"0x{authority.min_serial:016x}",
        "max_serial": authority.max_serial,
        "max_serial_hex": f"0x{authority.max_serial:016x}",
    }


def parse_landmark(raw):
    bundle, config = parse_anchor(raw)
    checkpoint = bundle.checkpoint
    ca_id = config["ca_id"]
    log_number = config["log_number"]
    min_serial, max_serial = config["min_serial"], config["max_serial"]
    landmark_number = bundle.signaling_landmark
    tree_size, timestamp = checkpoint.tree_size, checkpoint.timestamp
    checkpoint_root = checkpoint.root_hash
    # Checkpoint signatures are retained in MTB2 but Chromium only needs the
    # resulting trusted landmark subtrees after out-of-band trust validation.
    checkpoint_signatures = core.encode_subtree_signature_block(
        checkpoint.signatures)
    subtrees = [{
            "start": start,
            "end": end,
            "hash": digest.hex(),
        } for start, end, digest in checkpoint.subtrees]
    if landmark_number is None:
        raise ValueError("MTB2 has no signaling landmark")
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

    individual = f"{ca_id}.1.{log_number}.{landmark_number}"
    group = f"{ca_id}.2.{log_number}.{landmark_number}"

    config["landmark"] = {
            "number": landmark_number,
            "tree_size": tree_size,
            "timestamp": timestamp,
            "checkpoint_root": checkpoint_root.hex(),
            "checkpoint_signatures_bytes": len(checkpoint_signatures),
            "requested_trust_anchor_id": group,
            "requested_trust_anchor_id_hex":
                core.relid(group).hex(),
            "selected_trust_anchor_id": individual,
            "selected_trust_anchor_id_hex":
                core.relid(individual).hex(),
            "trusted_subtrees": subtrees,
    }
    return config


def parse_standalone(raw):
    _, config = parse_anchor(raw)
    config["trust_mode"] = "standalone"
    return config


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trust", type=Path, required=True)
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("--trust-mode", choices=("landmark", "standalone"),
                    default="landmark")
    args = ap.parse_args()

    raw = args.trust.read_bytes()
    config = (parse_standalone(raw) if args.trust_mode == "standalone"
              else parse_landmark(raw))

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
        f"mode={args.trust_mode} "
        + (f"N={config['landmark']['tree_size']} "
           f"requested={config['landmark']['requested_trust_anchor_id']}"
           if args.trust_mode == "landmark" else "")
    )


if __name__ == "__main__":
    main()
