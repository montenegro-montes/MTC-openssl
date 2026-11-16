#!/usr/bin/env python3
"""Summarize new native and separate Chromium blocks for Figures 4 and 5.

Input CSVs remain in their campaign directories. The output contains only
profile, case, counts, and timing means; it does not include source paths.
"""

import argparse
import csv
import json
from collections import defaultdict
from decimal import Decimal
from pathlib import Path


PROFILES = ("ecdsa-p384", "mldsa65", "slhdsa192s")
CHROMIUM_PROFILES = PROFILES[:2]
CASES = ("x509", "landmark", "standalone")
NATIVE_CASE = {"x509-simple-d3": "x509", "mtc-simple-landmark": "landmark",
               "mtc-simple-standalone": "standalone"}
CHROMIUM_CASE = {"x509": "x509", "mtc-landmark": "landmark",
                 "mtc-standalone": "standalone"}
FIELDS = ("client", "profile", "case", "n", "credential_validation_mean_ms",
          "certificate_verify_mean_ms", "authentication_total_mean_ms",
          "figure_label_ms")


def read_csv(path):
    with path.open(newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"credential_validation_total_ns", "certificate_verify_crypto_ns"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(f"Missing timing columns in {path}")
        return list(reader)


def add(grouped, client, profile, case, row):
    credential = Decimal(row["credential_validation_total_ns"])
    verify = Decimal(row["certificate_verify_crypto_ns"])
    if credential < 0 or verify < 0:
        raise ValueError(f"Negative timing in {client} {profile} {case}")
    grouped[(client, profile, case)].append((credential, verify))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--chromium", type=Path, action="append", required=True,
                        help="Repeat once for each Chromium profile block")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    grouped = defaultdict(list)

    native_summary = json.loads((args.native.parent / "summary.json").read_text())
    if native_summary["key_establishment"]["openssl_group"] != "X25519MLKEM768" \
            or native_summary["x509_trust_path"]["depth_including_root"] != 3:
        raise ValueError("Native run has a different TLS group or X.509 depth")
    for row in read_csv(args.native):
        if row["phase"] != "measured" or row["profile"] not in PROFILES:
            continue
        case = NATIVE_CASE.get(row["case"])
        if case:
            add(grouped, "s_client", row["profile"], case, row)

    seen_profiles = set()
    for path in args.chromium:
        summary = json.loads((path.parent / "summary.json").read_text())
        if summary.get("overall_pass") is not True or summary.get("depth") != 3 \
                or summary.get("key_establishment") != "x25519-mlkem768":
            raise ValueError(f"Chromium run did not pass or has another configuration: {path}")
        profiles = set(summary.get("profiles", [])) & set(CHROMIUM_PROFILES)
        if not profiles or profiles & seen_profiles:
            raise ValueError(f"Missing or duplicated Chromium profile block: {path}")
        seen_profiles.update(profiles)
        for row in read_csv(path):
            profile = row["signature_profile"]
            if profile not in profiles:
                continue
            case = CHROMIUM_CASE.get(row["case"])
            if not case:
                continue
            if row["status"] != "PASS" or row["pair_complete"].lower() != "true":
                raise ValueError(f"Chromium measured row did not pass: {profile} {case}")
            add(grouped, "chromium", profile, case, row)
    if seen_profiles != set(CHROMIUM_PROFILES):
        raise ValueError("Both Chromium profile blocks are required")

    output = []
    for client, profiles in (("s_client", PROFILES), ("chromium", CHROMIUM_PROFILES)):
        for profile in profiles:
            for case in CASES:
                values = grouped[(client, profile, case)]
                if len(values) != 100:
                    raise ValueError(f"Expected 100 measurements for {client} {profile} {case}: {len(values)}")
                credential = sum(v[0] for v in values) / Decimal(100_000_000)
                verify = sum(v[1] for v in values) / Decimal(100_000_000)
                total = credential + verify
                output.append(dict(client=client, profile=profile, case=case, n=100,
                                   credential_validation_mean_ms=f"{credential:.6f}",
                                   certificate_verify_mean_ms=f"{verify:.6f}",
                                   authentication_total_mean_ms=f"{total:.6f}",
                                   figure_label_ms=f"{total:.3f}"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        raise ValueError(f"Output exists; use a new path: {args.output}")
    with args.output.open("x", newline="") as stream:
        writer = csv.DictWriter(stream, FIELDS)
        writer.writeheader()
        writer.writerows(output)
    print(f"PASS: {len(output)} figure bars written to {args.output}")


if __name__ == "__main__":
    main()
