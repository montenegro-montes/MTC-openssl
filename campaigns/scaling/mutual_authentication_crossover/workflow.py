#!/usr/bin/env python3
"""Canonical nine-profile mutual-authentication crossover workflow."""
import argparse
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PROFILES = (
    "ecdsa-p256", "ecdsa-p384", "ecdsa-p521",
    "mldsa44", "mldsa65", "mldsa87",
    "slhdsa128s", "slhdsa192s", "slhdsa256s",
)


def call(args, env):
    print("+", " ".join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), cwd=REPO, env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-fixtures", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--analysis", type=Path, required=True)
    parser.add_argument("--simple-crossover", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    plan = {
        "profiles": list(PROFILES), "tree_sizes": [1, 4, 16, 64, 256, 1024],
        "x509_cases": 18, "mtc_cases": 54, "cases_per_round": 72,
        "measured_observations": 72 * args.runs,
        "warmup_observations": 72 * args.warmups,
    }
    print(plan)
    if not args.execute:
        return
    for path in (args.server_fixtures, args.fixtures, args.results, args.analysis, args.report):
        if path.exists():
            raise SystemExit(f"refusing to overwrite: {path}")
    if not (args.simple_crossover / "crossover.csv").is_file():
        raise SystemExit("simple crossover.csv is required")
    env = os.environ.copy()
    env["MUTUAL_CROSSOVER_SERVER_FIXTURES"] = str(args.server_fixtures.resolve())
    env["MUTUAL_CROSSOVER_FIXTURES"] = str(args.fixtures.resolve())
    call([sys.executable, "campaigns/scaling/chain_depth_server_only/generate_fixtures.py",
          "--output", args.server_fixtures, "--image", "mt-tls-mtc:local",
          "--chain-profile", "direct-server", "--chain-profile", "ca-server"], env)
    for profile in PROFILES:
        call([sys.executable, HERE / "generate_client_population.py", "--profile", profile,
              "--chain-profile", "direct-server", "--count", 1], env)
        call([sys.executable, HERE / "generate_client_population.py", "--profile", profile,
              "--chain-profile", "ca-server", "--count", 1024], env)
        call([sys.executable, HERE / "generate_server_population.py", "--profile", profile,
              "--count", 1024], env)
    call([sys.executable, HERE / "generate_cosigners.py", "--output", args.fixtures], env)
    call([sys.executable, HERE / "prepare_all.py"], env)
    call(["docker", "build", "-f", HERE / "Dockerfile.mutual_metrics",
          "-t", "mt-tls-mtc-mutual:local", "."], env)
    for profile in PROFILES:
        call([sys.executable, HERE / "preflight.py", "--profile", profile, "--n", 16,
              "--root", args.results.parent / f"{args.results.name}-preflight-{profile}"], env)
    call([sys.executable, HERE / "run.py", "--root", args.results,
          "--runs", args.runs, "--warmups", args.warmups], env)
    call([sys.executable, HERE / "summarize.py", "--input", args.results,
          "--output", args.analysis], env)
    call([sys.executable, HERE / "compare_simple_mutual.py", "--simple", args.simple_crossover,
          "--mutual", args.analysis, "--output", args.analysis / "simple-vs-mutual-crossover.csv"], env)
    call([REPO / "bin/artifacts/mt-report", args.analysis, "--output", args.report], env)


if __name__ == "__main__":
    main()
