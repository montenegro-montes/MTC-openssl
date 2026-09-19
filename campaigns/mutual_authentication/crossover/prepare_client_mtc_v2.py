#!/usr/bin/env python3

import argparse
import json
import sys
from pathlib import Path

from config import ARTIFACT_ROOT, PROFILES, MTC_N_VALUES

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

    allowed = MTC_N_VALUES[args.profile]

    if args.n not in allowed:
        raise SystemExit(
            f"N={args.n} not allowed for {args.profile}; "
            f"expected one of {allowed}"
        )

    source = (
        ARTIFACT_ROOT
        / "client-x509"
        / args.profile
        / "ca-server"
    )

    cosigners = (
        ARTIFACT_ROOT
        / "client-cosigners"
        / args.profile
    )

    output = (
        args.output.resolve()
        if args.output
        else (
            ARTIFACT_ROOT
            / "client-mtc"
            / f"batch{args.n}"
            / args.profile
        )
    )

    if output.exists():
        raise SystemExit(
            f"Refusing to overwrite existing output: {output}"
        )

    originals = [
        source / f"client-{i:04d}.pem"
        for i in range(args.n)
    ]

    missing = [p for p in originals if not p.is_file()]
    if missing:
        raise SystemExit(
            f"Missing client source certificate: {missing[0]}"
        )

    signer_keys = [
        cosigners / "cosigner-0.key",
        cosigners / "cosigner-1.key",
    ]

    missing = [p for p in signer_keys if not p.is_file()]
    if missing:
        raise SystemExit(
            f"Missing client cosigner key: {missing[0]}"
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
            "experiment": "mutual-auth-crossover-v2",
            "role": "client",
            "profile": args.profile,
            "tree_size": args.n,
            "source_chain_profile": "ca-server",
            "source_population": str(source),
            "population_selection":
                f"client-0000..client-{args.n - 1:04d}",
            "baseline_leaf": str(source / "client-0000.pem"),
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
