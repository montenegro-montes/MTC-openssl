#!/usr/bin/env python3
"""Run MTC-experimental landmark measurements for chain-depth comparison."""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

from config import IMAGE, MTC_CHAIN_PROFILES, PROFILES, TLS

REPO = Path(__file__).resolve().parents[3]
COMPOSE = [
    "docker",
    "compose",
    "-f",
    str(REPO / "docker/validation/compose.chain-depth-mtc.yaml"),
]

MTC_IMAGE = "mt-tls-mtc:local"
CHAIN_PROFILE = "mtc-landmark"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")


def cell_name(profile: str, campaign: int) -> str:
    return f"{profile}-{CHAIN_PROFILE}-c{campaign}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mtc-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", action="append", choices=PROFILES)
    parser.add_argument("--campaigns", type=int, default=1)
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--seed", type=int, default=63000)
    parser.add_argument("--image", default=MTC_IMAGE)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    mtc_root = args.mtc_root.resolve()
    output = args.output.resolve()

    if output.exists():
        parser.error("Output exists; results are immutable")
    if args.campaigns < 1 or args.runs < 1 or args.warmups < 0:
        parser.error("campaigns >= 1, runs >= 1, warmups >= 0")
    if CHAIN_PROFILE not in MTC_CHAIN_PROFILES:
        parser.error("mtc-landmark missing from MTC_CHAIN_PROFILES")

    profiles = args.profile or list(PROFILES)
    chain = MTC_CHAIN_PROFILES[CHAIN_PROFILE]

    image_id = json.loads(
        subprocess.check_output(["docker", "image", "inspect", args.image], text=True)
    )[0]["Id"]
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    git_status = subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO, text=True)

    cells = []
    for profile in profiles:
        mtc_dir = mtc_root / "batch16" / "mtc" / profile
        population_key = mtc_root / "population" / profile / "0.key"
        manifest = mtc_dir / "manifest.json"

        for required in [manifest, mtc_dir / "landmark-0000.pem", mtc_dir / "trust.bin", population_key]:
            if not required.is_file():
                raise SystemExit(f"Missing MTC fixture file: {required}")

        fixture_meta = json.loads(manifest.read_text())
        if fixture_meta["profile"] != profile:
            raise SystemExit(f"MTC fixture profile mismatch: {manifest}")
        if fixture_meta["status"] != "MTC-experimental":
            raise SystemExit(f"MTC fixture status mismatch: {manifest}")
        if int(fixture_meta["tree_size"]) != int(chain["tree_size"]):
            raise SystemExit(f"MTC tree_size mismatch: {manifest}")
        if "landmark" not in fixture_meta.get("mtc_modes", []):
            raise SystemExit(f"MTC landmark mode missing: {manifest}")

        fixture_hash = digest(manifest)

        for campaign in range(1, args.campaigns + 1):
            cells.append(
                {
                    "profile": profile,
                    "chain_profile": CHAIN_PROFILE,
                    "campaign": campaign,
                    "cell": cell_name(profile, campaign),
                    "fixture_hash": fixture_hash,
                    "fixture_manifest": str(manifest),
                    "auth_family": chain["auth_family"],
                    "depth_including_root": chain["depth_including_root"],
                    "chain_depth": chain["chain_depth"],
                    "transmitted_certificates": chain["transmitted_certificates"],
                    "tree_size": chain["tree_size"],
                    "mtc_mode": chain["mtc_mode"],
                }
            )

    plan = {
        "schema": 1,
        "experiment": "chain_depth_server_only",
        "auth_family": "mtc-experimental",
        "chain_profile": CHAIN_PROFILE,
        "profiles": profiles,
        "campaigns": args.campaigns,
        "runs": args.runs,
        "warmups": args.warmups,
        "seed": args.seed,
        "tls": TLS,
        "image_id": image_id,
        "git_commit": commit,
        "git_status": git_status,
        "mtc_root": str(mtc_root),
        "output": str(output),
        "cells": cells,
    }

    if not args.execute:
        print(json.dumps(plan, indent=2))
        return

    output.mkdir(parents=True)
    write_json(output / "manifest.json", plan)

    for cell in cells:
        profile = cell["profile"]
        campaign_id = cell["cell"]
        seed = args.seed + cell["campaign"] + list(PROFILES).index(profile) * 1000

        env = os.environ.copy()
        env.update(
            CHAIN_DEPTH_MTC_IMAGE=image_id,
            MTC_ROOT=str(mtc_root),
            CHAIN_DEPTH_RESULTS=str(output),
            CERT_PROFILE=profile,
            CERT_CAMPAIGN=campaign_id,
            FIXTURE_SHA256=cell["fixture_hash"],
            SOURCE_COMMIT=commit,
            IMAGE_ID=image_id,
        )

        try:
            subprocess.run(COMPOSE + ["up", "-d", "--force-recreate", "--wait", "server"], env=env, check=True)
            subprocess.run(
                COMPOSE
                + [
                    "run",
                    "--rm",
                    "client",
                    "python3",
                    "/repo/campaigns/scaling/chain_depth_server_only/measure_mtc.py",
                    "--runs",
                    str(args.runs),
                    "--warmups",
                    str(args.warmups),
                    "--scenario",
                    f"{profile}-{CHAIN_PROFILE}",
                    "--campaign",
                    campaign_id,
                    "--seed",
                    str(seed),
                ],
                env=env,
                check=True,
            )
        finally:
            subprocess.run(COMPOSE + ["down"], env=env, check=False)

    subprocess.run(
        [
            "python3",
            str(REPO / "campaigns/scaling/chain_depth_server_only/validate.py"),
            str(output),
        ],
        check=True,
    )

    print(output)


if __name__ == "__main__":
    main()
