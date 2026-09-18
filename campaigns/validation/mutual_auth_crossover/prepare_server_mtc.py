#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src" / "mtc"))

from prepare import prepare


SOURCE = (
    REPO
    / "artifacts"
    / "validation"
    / "mutual-auth-crossover"
    / "server-source"
    / "ecdsa-p521-ca-server"
)

COSIGNERS = (
    REPO
    / "artifacts"
    / "validation"
    / "mutual-auth-crossover"
    / "server-cosigners"
    / "ecdsa-p521"
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--n",
        type=int,
        required=True,
        choices=[16, 32, 64, 128],
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    n = args.n
    output = args.output.resolve()

    if output.exists():
        raise SystemExit(
            f"Refusing to overwrite existing output: {output}"
        )

    originals = [
        SOURCE / f"server-{i:04d}.pem"
        for i in range(n)
    ]

    missing = [p for p in originals if not p.exists()]
    if missing:
        raise SystemExit(
            f"Missing source certificate: {missing[0]}"
        )

    signer_keys = [
        COSIGNERS / "cosigner-0.key",
        COSIGNERS / "cosigner-1.key",
    ]

    missing = [p for p in signer_keys if not p.exists()]
    if missing:
        raise SystemExit(
            f"Missing cosigner key: {missing[0]}"
        )

    prepare(
        output,
        SOURCE,
        "ecdsa-p521",
        n,
        originals=originals,
        signer_keys=signer_keys,
        metadata={
            "experiment": "mutual-auth-crossover",
            "role": "server",
            "chain_profile": "ca-server",
            "source_population": str(SOURCE),
            "population_selection":
                f"server-0000..server-{n-1:04d}",
            "baseline_leaf":
                str(SOURCE / "server-0000.pem"),
        },
    )

    print(output)


if __name__ == "__main__":
    main()