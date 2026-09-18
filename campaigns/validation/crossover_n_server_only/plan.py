#!/usr/bin/env python3
"""Print the planned crossover-by-N server-only matrix."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
if str(THIS_DIR) not in sys.path:
    sys.path.insert(0, str(THIS_DIR))

from config import MTC_CHAIN_PROFILE, PROFILES, TLS, TREE_SIZES, X509_CHAIN_PROFILES


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", action="append", choices=PROFILES)
    parser.add_argument("--tree-size", action="append", type=int)
    parser.add_argument("--chain-profile", action="append", choices=X509_CHAIN_PROFILES)
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--campaigns", type=int, default=1)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    profiles = args.profile or PROFILES
    tree_sizes = args.tree_size or TREE_SIZES
    chain_profiles = args.chain_profile or X509_CHAIN_PROFILES

    unknown_n = sorted(set(tree_sizes) - set(TREE_SIZES))
    if unknown_n:
        raise SystemExit(f"Unexpected tree sizes for pilot config: {unknown_n}")

    cells = []

    for profile in profiles:
        for chain_profile in chain_profiles:
            cells.append({
                "auth_family": "x509",
                "profile": profile,
                "chain_profile": chain_profile,
                "tree_size": "",
                "mtc_mode": "",
            })

        for n in tree_sizes:
            cells.append({
                "auth_family": "mtc-experimental",
                "profile": profile,
                "chain_profile": MTC_CHAIN_PROFILE,
                "tree_size": n,
                "mtc_mode": "landmark",
            })

    plan = {
        "experiment": "crossover_n_server_only",
        "description": "Server-only byte-level crossover between X.509 and MTC landmark authentication as Merkle population size N varies.",
        "tls": TLS,
        "profiles": profiles,
        "x509_chain_profiles": chain_profiles,
        "mtc_chain_profile": MTC_CHAIN_PROFILE,
        "tree_sizes": tree_sizes,
        "runs": args.runs,
        "warmups": args.warmups,
        "campaigns": args.campaigns,
        "x509_cells": len(profiles) * len(chain_profiles),
        "mtc_cells": len(profiles) * len(tree_sizes),
        "total_cells": len(cells),
        "cells": cells,
    }

    text = json.dumps(plan, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n")
        print(args.output)
    else:
        print(text)


if __name__ == "__main__":
    main()
