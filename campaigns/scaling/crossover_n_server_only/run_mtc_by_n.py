#!/usr/bin/env python3
"""Run MTC-experimental landmark measurements for crossover-by-N."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from config import MTC_CHAIN_PROFILE, PROFILES, TLS, TREE_SIZES, TREE_SIZES_BY_PROFILE

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
from campaigns.common.image_chain import ensure

COMPOSE = [
    "docker",
    "compose",
    "-f",
    str(REPO / "docker/validation/compose.crossover-n-mtc.yaml"),
]

MTC_IMAGE = os.environ.get("MTC_PROFILE_IMAGE", "mt-tls-mtc-profile:local")


def require_profile_metrics(image: str) -> None:
    """Check the existing image before fixtures/results or measured connections."""
    probe = r"""
from pathlib import Path
import subprocess
import sys
help_result = subprocess.run(['/opt/mtc/openssl.sh', 's_server', '-help'],
                             capture_output=True, timeout=15)
help_text = help_result.stdout + help_result.stderr
binary = Path('/opt/openssl-mtc/bin/openssl').read_bytes()
required = (b'PROFILE_METRICS', b'PROFILE_METRICS_DIR', b'client_random',
            b'certificate_message_bytes', b'handshake_cpu_ms', b'peer_auth')
raise SystemExit(0 if b'-lab_metrics' in help_text and
                 all(token in binary for token in required) else 1)
"""
    try:
        result = subprocess.run(
            ['docker', 'run', '--rm', '--network', 'none', '--entrypoint',
             'python3', image, '-c', probe], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f'Cannot check PROFILE_METRICS capability: {error}') from error
    if result.returncode:
        raise SystemExit(
            'Image does not satisfy the required PROFILE_METRICS preflight: '
            + image + '. This campaign requires instrumented s_server and s_client, '
            'per-connection server JSON and Certificate-message/CPU metrics. '
            'The current base image provides client-only NATIVE_METRICS, which is '
            'not interchangeable. Build docker/validation/Dockerfile.profile as '
            'mt-tls-mtc-profile:local and select it with --image; '
            'do not remove server metrics or substitute missing measurements.')


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")


def cell_name(profile: str, tree_size: int, campaign: int) -> str:
    return f"{profile}-{MTC_CHAIN_PROFILE}-n{tree_size}-c{campaign}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mtc-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", action="append", choices=PROFILES)
    parser.add_argument("--tree-size", action="append", type=int)
    parser.add_argument("--campaigns", type=int, default=1)
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--seed", type=int, default=73000)
    parser.add_argument("--image", default=MTC_IMAGE)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    mtc_root = args.mtc_root.resolve()
    output = args.output.resolve()
    profiles = args.profile or list(PROFILES)
    requested_tree_sizes = args.tree_size

    if requested_tree_sizes:
        unknown = sorted(n for n in set(requested_tree_sizes) if n < 1 or n > 1024)
        if unknown:
            parser.error(f"Unexpected tree sizes: {unknown}")

    if output.exists():
        parser.error("Output exists; results are immutable")
    if args.campaigns < 1 or args.runs < 1 or args.warmups < 0:
        parser.error("campaigns >= 1, runs >= 1, warmups >= 0")

    if args.execute and args.image == "mt-tls-mtc-profile:local":
        args.image = ensure("profile")["target"]["Id"]

    image_id = json.loads(
        subprocess.check_output(["docker", "image", "inspect", args.image], text=True)
    )[0]["Id"]
    if args.execute:
        require_profile_metrics(image_id)
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).stdout.strip() if False else subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    git_status = subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO, text=True)

    cells = []
    for profile in profiles:
        allowed_tree_sizes = requested_tree_sizes or TREE_SIZES_BY_PROFILE[profile]

        profile_tree_sizes = allowed_tree_sizes

        for tree_size in profile_tree_sizes:
            mtc_dir = mtc_root / f"batch{tree_size}" / "mtc" / profile
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
            if int(fixture_meta["tree_size"]) != int(tree_size):
                raise SystemExit(f"MTC tree_size mismatch: {manifest}")
            if "landmark" not in fixture_meta.get("mtc_modes", []):
                raise SystemExit(f"MTC landmark mode missing: {manifest}")

            fixture_hash = digest(manifest)

            for campaign in range(1, args.campaigns + 1):
                cells.append(
                    {
                        "profile": profile,
                        "chain_profile": MTC_CHAIN_PROFILE,
                        "campaign": campaign,
                        "cell": cell_name(profile, tree_size, campaign),
                        "fixture_hash": fixture_hash,
                        "fixture_manifest": str(manifest),
                        "auth_family": "mtc-experimental",
                        "depth_including_root": "",
                        "chain_depth": 1,
                        "transmitted_certificates": 1,
                        "tree_size": tree_size,
                        "mtc_mode": "landmark",
                    }
                )

    plan = {
        "schema": 1,
        "experiment": "crossover_n_server_only",
        "auth_family": "mtc-experimental",
        "chain_profile": MTC_CHAIN_PROFILE,
        "profiles": profiles,
        "tree_sizes_by_profile": TREE_SIZES_BY_PROFILE,
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
        tree_size = int(cell["tree_size"])
        campaign_id = cell["cell"]
        seed = args.seed + cell["campaign"] + list(PROFILES).index(profile) * 1000 + tree_size

        env = os.environ.copy()
        env.update(
            CROSSOVER_N_MTC_IMAGE=image_id,
            MTC_ROOT=str(mtc_root),
            CROSSOVER_N_RESULTS=str(output),
            CERT_PROFILE=profile,
            CERT_PROFILE_NAME=profile,
            CERT_CAMPAIGN=campaign_id,
            MTC_TREE_SIZE=str(tree_size),
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
                    "/repo/campaigns/scaling/crossover_n_server_only/measure_mtc_by_n.py",
                    "--runs",
                    str(args.runs),
                    "--warmups",
                    str(args.warmups),
                    "--scenario",
                    f"{profile}-{MTC_CHAIN_PROFILE}-n{tree_size}",
                    "--campaign",
                    campaign_id,
                    "--seed",
                    str(seed),
                ],
                env=env,
                check=True,
            )
        finally:
            # Preserve startup errors before Compose removes the failed container.
            cell_output = output / campaign_id
            cell_output.mkdir(parents=True, exist_ok=True)
            try:
                with (cell_output / "server-compose.log").open("w") as log:
                    subprocess.run(COMPOSE + ["logs", "--no-color", "server"],
                                   env=env, stdout=log, stderr=subprocess.STDOUT,
                                   check=False, timeout=15)
            except (OSError, subprocess.TimeoutExpired) as error:
                (cell_output / "log-capture-error.txt").write_text(str(error) + "\n")
            finally:
                subprocess.run(COMPOSE + ["down"], env=env, check=False)

    print(output)


if __name__ == "__main__":
    main()
