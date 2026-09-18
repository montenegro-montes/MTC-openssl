#!/usr/bin/env python3
"""Inventory existing MTC fixtures for crossover-by-N experiments."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from config import PROFILES, TREE_SIZES


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", action="append", choices=PROFILES)
    parser.add_argument("--tree-size", action="append", type=int)
    args = parser.parse_args()

    fixtures_root = args.fixtures_root.resolve()
    output = args.output.resolve()
    profiles = args.profile or PROFILES
    tree_sizes = args.tree_size or TREE_SIZES

    if output.exists():
        parser.error("Output exists; choose a new immutable path")

    output.mkdir(parents=True)

    rows = []
    errors = []

    for n in tree_sizes:
        for profile in profiles:
            fixture = fixtures_root / f"batch{n}" / "mtc" / profile
            population = fixtures_root / "population" / profile
            manifest = fixture / "manifest.json"

            row = {
                "profile": profile,
                "tree_size": n,
                "fixture_dir": str(fixture),
                "population_dir": str(population),
                "manifest": str(manifest),
                "exists": fixture.is_dir(),
                "manifest_exists": manifest.is_file(),
                "landmark_pem_exists": (fixture / "landmark-0000.pem").is_file(),
                "trust_bin_exists": (fixture / "trust.bin").is_file(),
                "server_key_exists": (population / "0.key").is_file(),
                "tree_size_manifest": "",
                "status": "",
                "mtc_modes": "",
            }

            if manifest.is_file():
                try:
                    meta = json.loads(manifest.read_text())
                    row["tree_size_manifest"] = meta.get("tree_size", "")
                    row["status"] = meta.get("status", "")
                    row["mtc_modes"] = ",".join(meta.get("mtc_modes", []))

                    if meta.get("tree_size") != n:
                        errors.append(f"{profile} N={n}: manifest tree_size mismatch")
                    if meta.get("profile") != profile:
                        errors.append(f"{profile} N={n}: manifest profile mismatch")
                    if meta.get("status") != "MTC-experimental":
                        errors.append(f"{profile} N={n}: manifest status mismatch")
                    if "landmark" not in meta.get("mtc_modes", []):
                        errors.append(f"{profile} N={n}: landmark mode missing")
                except Exception as exc:
                    errors.append(f"{profile} N={n}: cannot parse manifest: {exc}")

            for key in [
                "exists",
                "manifest_exists",
                "landmark_pem_exists",
                "trust_bin_exists",
                "server_key_exists",
            ]:
                if not row[key]:
                    errors.append(f"{profile} N={n}: missing {key}")

            rows.append(row)

    csv_path = output / "inventory.csv"
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    report = {
        "passed": not errors,
        "fixtures_root": str(fixtures_root),
        "profiles": profiles,
        "tree_sizes": tree_sizes,
        "checked_cells": len(rows),
        "errors": errors,
        "inventory_csv": str(csv_path),
    }

    (output / "inventory.json").write_text(json.dumps(report, indent=2) + "\n")

    print(json.dumps(report, indent=2))

    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
