#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path

from config import ARTIFACT_ROOT, SOURCE_ROOT, PROFILES

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "mtc"))

from prepare import prepare


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--profile",
        choices=PROFILES,
        required=True,
    )

    parser.add_argument(
        "--n",
        type=int,
        required=True,
    )

    parser.add_argument("--output", type=Path)

    args = parser.parse_args()

    if not 1 <= args.n <= 1024:
        raise SystemExit("N must be between 1 and 1024")

    source = (
        SOURCE_ROOT
        / "server-mtc-source"
        / args.profile
    )

    cosigners = (
        SOURCE_ROOT
        / "server-cosigners"
        / args.profile
    )

    output = (
        args.output.resolve()
        if args.output
        else (
            ARTIFACT_ROOT
            / "server-mtc"
            / f"batch{args.n}"
            / args.profile
        )
    )

    if output.exists():
        raise SystemExit(
            f"Refusing to overwrite existing output: {output}"
        )

    originals = [
        source / f"server-{i:04d}.pem"
        for i in range(args.n)
    ]

    missing = [p for p in originals if not p.is_file()]
    if missing:
        raise SystemExit(
            f"Missing server source certificate: {missing[0]}"
        )

    signer_keys = [
        cosigners / "cosigner-0.key",
        cosigners / "cosigner-1.key",
    ]

    missing = [p for p in signer_keys if not p.is_file()]
    if missing:
        raise SystemExit(
            f"Missing server cosigner key: {missing[0]}"
        )

    output.parent.mkdir(parents=True, exist_ok=True)

    meta = prepare(
        output,
        source,
        args.profile,
        args.n,
        originals=originals,
        signer_keys=signer_keys,
        metadata={
            "experiment": "mutual-auth-crossover",
            "role": "server",
            "profile": args.profile,
            "tree_size": args.n,
            "source_chain_profile": "ca-server",
            "source_population": str(source),
            "population_selection":
                f"server-0000..server-{args.n - 1:04d}",
            "baseline_leaf": str(source / "server-0000.pem"),
        },
    )

    print(json.dumps({
        "profile": args.profile,
        "n": args.n,
        "output": str(output),
        "ca_spki_sha256": meta["ca_spki_sha256"],
        "cosigner_spki_sha256":
            meta["cosigner_spki_sha256"],
        "certificate_bytes":
            meta["sizes"]["landmark"]["mtc_certificate_bytes"],
        "proof_bytes":
            meta["sizes"]["landmark"]["mtc_inclusion_proof_bytes"],
    }, indent=2))


if __name__ == "__main__":
    main()
