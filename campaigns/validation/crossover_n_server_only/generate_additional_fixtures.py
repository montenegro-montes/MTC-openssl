#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src/mtc"))

from prepare import prepare


SIZES = {
    "ecdsa-p256": [8],
    "ecdsa-p384": [8, 32],
    "ecdsa-p521": [32, 128],
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    source = args.source.resolve()
    output = args.output.resolve()

    if output.exists():
        raise SystemExit(f"Refusing to overwrite existing output: {output}")

    os.umask(0o077)
    output.mkdir(parents=True)

    generated = []

    for profile, sizes in SIZES.items():
        source_population = source / "population" / profile
        source_mtc16 = source / "batch16" / "mtc" / profile

        if not source_population.is_dir():
            raise SystemExit(f"Missing population: {source_population}")

        signer_keys = [
            source_mtc16 / "cosigner-0.key",
            source_mtc16 / "cosigner-1.key",
        ]

        for p in signer_keys:
            if not p.is_file():
                raise SystemExit(f"Missing signer key: {p}")

        max_n = max(sizes)

        # Preserve the same source population needed by this refinement.
        dst_population = output / "population" / profile
        dst_population.mkdir(parents=True)

        for i in range(max_n):
            src = source_population / f"{i}.pem"
            dst = dst_population / f"{i}.pem"
            if not src.is_file():
                raise SystemExit(f"Missing source certificate: {src}")
            shutil.copy2(src, dst)

        # Leaf 0 private key is required by the TLS measurement runner.
        shutil.copy2(
            source_population / "0.key",
            dst_population / "0.key",
        )

        reference_manifest = json.loads(
            (source_mtc16 / "manifest.json").read_text()
        )

        for n in sizes:
            mtc_out = output / f"batch{n}" / "mtc" / profile
            mtc_out.parent.mkdir(parents=True, exist_ok=True)

            originals = [
                source_population / f"{i}.pem"
                for i in range(n)
            ]

            meta = prepare(
                mtc_out,
                source / "population",
                profile,
                n,
                originals=originals,
                signer_keys=signer_keys,
                metadata={
                    "experiment": "crossover_n_server_only_additional_fixtures",
                    "source_fixture_root": str(source),
                    "source_batch16_manifest_sha256": sha256(
                        source_mtc16 / "manifest.json"
                    ),
                },
            )

            if meta["ca_spki_sha256"] != reference_manifest["ca_spki_sha256"]:
                raise SystemExit(
                    f"{profile} N={n}: CA SPKI changed"
                )

            if meta["cosigner_spki_sha256"] != reference_manifest["cosigner_spki_sha256"]:
                raise SystemExit(
                    f"{profile} N={n}: cosigner SPKI changed"
                )

            generated.append({
                "profile": profile,
                "tree_size": n,
                "path": str(mtc_out),
                "ca_spki_sha256": meta["ca_spki_sha256"],
                "cosigner_spki_sha256": meta["cosigner_spki_sha256"],
                "landmark_certificate_bytes":
                    meta["sizes"]["landmark"]["mtc_certificate_bytes"],
                "proof_bytes":
                    meta["sizes"]["landmark"]["mtc_inclusion_proof_bytes"],
            })

    manifest = {
        "experiment": "crossover_n_server_only_additional_fixtures",
        "source": str(source),
        "cells": generated,
    }

    (output / "refinement-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n"
    )

    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
