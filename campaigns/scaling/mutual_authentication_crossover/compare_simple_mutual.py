#!/usr/bin/env python3
"""Join simple D=2 and mutual CA/CA crossover intervals without interpolation."""
import argparse
import csv
from pathlib import Path


def rows(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--simple", type=Path, required=True)
    parser.add_argument("--mutual", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    simple = {
        row["algorithm"]: row
        for row in rows(args.simple / "crossover.csv")
        if row["x509_depth"] == "2"
    }
    mutual = {
        row["profile"]: row
        for row in rows(args.mutual / "crossover-n.csv")
        if row["chain_profile"] == "ca-server"
    }
    if simple.keys() != mutual.keys():
        raise SystemExit(f"profile mismatch: simple={sorted(simple)} mutual={sorted(mutual)}")
    result = []
    for profile in sorted(simple):
        left, right = simple[profile], mutual[profile]
        if left["status"] == "CROSSED":
            simple_interval = f"({left['mtc_previous_N']},{left['mtc_cross_N']})"
        elif left["status"] == "OUTSIDE_SEARCH_RANGE":
            simple_interval = f">{left['mtc_previous_N']}"
        else:
            simple_interval = left["status"]
        result.append({
            "profile": profile,
            "simple_authentication_x509_depth": 2,
            "simple_crossover_interval": simple_interval,
            "mutual_authentication_x509_case": "CA/CA",
            "mutual_crossover_interval": right["crossover_interval"],
            "simple_x509_certificate_bytes": left["x509_bytes"],
            "mutual_x509_certificate_total_bytes": right["x509_certificate_total_bytes"],
        })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        raise SystemExit(f"output exists: {args.output}")
    with args.output.open("x", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=result[0].keys())
        writer.writeheader(); writer.writerows(result)
    print(args.output)


if __name__ == "__main__":
    main()
