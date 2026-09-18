#!/usr/bin/env python3
"""Run server-only chain-depth sensitivity measurements for X.509 fixtures."""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

from config import CHAIN_PROFILES, IMAGE, PROFILES, TLS, X509_CHAIN_PROFILES

REPO = Path(__file__).resolve().parents[3]
COMPOSE = [
    "docker",
    "compose",
    "-f",
    str(REPO / "docker/validation/compose.chain-depth-server-only.yaml"),
]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")


def cell_name(profile: str, chain_profile: str, campaign: int) -> str:
    return f"{profile}-{chain_profile}-c{campaign}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", action="append", choices=PROFILES)
    parser.add_argument("--chain-profile", action="append", choices=X509_CHAIN_PROFILES)
    parser.add_argument("--campaigns", type=int, default=1)
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--seed", type=int, default=62000)
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    fixtures = args.fixtures.resolve()
    output = args.output.resolve()

    if output.exists():
        parser.error("Output exists; results are immutable")
    if args.campaigns < 1 or args.runs < 1 or args.warmups < 0:
        parser.error("campaigns >= 1, runs >= 1, warmups >= 0")

    profiles = args.profile or list(PROFILES)
    chain_profiles = args.chain_profile or list(X509_CHAIN_PROFILES)

    image_id = json.loads(
        subprocess.check_output(["docker", "image", "inspect", args.image], text=True)
    )[0]["Id"]
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    git_status = subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO, text=True)

    cells = []
    for profile in profiles:
        for chain_profile in chain_profiles:
            fixture = fixtures / profile / chain_profile
            manifest = fixture / "manifest.json"
            if not manifest.is_file():
                raise SystemExit(f"Missing fixture manifest: {manifest}")
            fixture_meta = json.loads(manifest.read_text())
            expected = CHAIN_PROFILES[chain_profile]
            if fixture_meta["profile"] != profile or fixture_meta["chain_profile"] != chain_profile:
                raise SystemExit(f"Fixture identity mismatch: {manifest}")
            for key in ("depth_including_root", "chain_depth", "transmitted_certificates"):
                if int(fixture_meta[key]) != int(expected[key]):
                    raise SystemExit(f"Fixture {key} mismatch: {manifest}")
            fixture_hash = digest(manifest)

            for campaign in range(1, args.campaigns + 1):
                cells.append(
                    {
                        "profile": profile,
                        "chain_profile": chain_profile,
                        "campaign": campaign,
                        "cell": cell_name(profile, chain_profile, campaign),
                        "fixture_hash": fixture_hash,
                        "fixture_manifest": str(manifest),
                        "depth_including_root": expected["depth_including_root"],
                        "chain_depth": expected["chain_depth"],
                        "transmitted_certificates": expected["transmitted_certificates"],
                    }
                )

    plan = {
        "schema": 1,
        "experiment": "chain_depth_server_only",
        "auth_family": "x509",
        "profiles": profiles,
        "chain_profiles": chain_profiles,
        "campaigns": args.campaigns,
        "runs": args.runs,
        "warmups": args.warmups,
        "seed": args.seed,
        "tls": TLS,
        "image_id": image_id,
        "git_commit": commit,
        "git_status": git_status,
        "fixtures": str(fixtures),
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
        chain_profile = cell["chain_profile"]
        campaign_id = cell["cell"]
        seed = args.seed + cell["campaign"] + list(PROFILES).index(profile) * 1000 + list(X509_CHAIN_PROFILES).index(chain_profile) * 100

        env = os.environ.copy()
        env.update(
            CHAIN_DEPTH_IMAGE=image_id,
            CHAIN_DEPTH_FIXTURES=str(fixtures),
            CHAIN_DEPTH_RESULTS=str(output),
            CERT_PROFILE=profile,
            CHAIN_PROFILE=chain_profile,
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
                    "/repo/campaigns/validation/chain_depth_server_only/measure.py",
                    "--runs",
                    str(args.runs),
                    "--warmups",
                    str(args.warmups),
                    "--scenario",
                    f"{profile}-{chain_profile}",
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
            str(REPO / "campaigns/validation/chain_depth_server_only/validate.py"),
            str(output),
        ],
        check=True,
    )

    print(output)


if __name__ == "__main__":
    main()
