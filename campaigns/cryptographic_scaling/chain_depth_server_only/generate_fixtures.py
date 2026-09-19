#!/usr/bin/env python3
"""Host-side immutable fixture generator for server-only chain-depth sensitivity."""

import argparse
import json
import subprocess
from pathlib import Path

from config import IMAGE, PROFILES, X509_CHAIN_PROFILES

REPO = Path(__file__).resolve().parents[3]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", action="append", choices=PROFILES)
    parser.add_argument("--chain-profile", action="append", choices=X509_CHAIN_PROFILES)
    parser.add_argument("--image", default=IMAGE)
    parser.add_argument("--plan", action="store_true")
    args = parser.parse_args()

    output = args.output.resolve()
    if output.exists():
        parser.error("Output exists; choose a new immutable fixture root")

    profiles = args.profile or list(PROFILES)
    chain_profiles = args.chain_profile or list(X509_CHAIN_PROFILES)

    commands = []
    for profile in profiles:
        for chain_profile in chain_profiles:
            commands.append(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{REPO}:/repo:ro",
                    "-v",
                    f"{output.parent}:/output",
                    args.image,
                    "python3",
                    "/repo/campaigns/cryptographic_scaling/chain_depth_server_only/fixture_builder.py",
                    "--output",
                    f"/output/{output.name}/{profile}/{chain_profile}",
                    "--profile",
                    profile,
                    "--chain-profile",
                    chain_profile,
                ]
            )

    plan = {
        "schema": 1,
        "experiment": "chain_depth_server_only",
        "output": str(output),
        "image": args.image,
        "profiles": profiles,
        "chain_profiles": chain_profiles,
        "commands": commands,
    }

    if args.plan:
        print(json.dumps(plan, indent=2))
        return

    output.parent.mkdir(parents=True, exist_ok=True)
    image_id = json.loads(
        subprocess.check_output(["docker", "image", "inspect", args.image], text=True)
    )[0]["Id"]
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()

    for command in commands:
        command[command.index(args.image)] = image_id
        command[3:3] = [
            "-e",
            "FIXTURE_IMAGE_ID=" + image_id,
            "-e",
            "FIXTURE_SOURCE_COMMIT=" + commit,
        ]
        subprocess.run(command, check=True)

    print(output)


if __name__ == "__main__":
    main()
