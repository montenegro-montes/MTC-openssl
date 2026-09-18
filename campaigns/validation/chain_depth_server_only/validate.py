#!/usr/bin/env python3
"""Validate chain-depth server-only measurement outputs."""

import argparse
import csv
import json
import math
from pathlib import Path

from config import CHAIN_PROFILES, PROFILES

METRICS = (
    "handshake_wall_ms",
    "client_cpu_ms",
    "server_cpu_ms",
    "authentication_processing_wall_ms",
    "authentication_processing_cpu_ms",
    "certificate_message_bytes",
    "certificate_verify_message_bytes",
    "tls_bio_read_bytes",
    "tls_bio_written_bytes",
)


def validate_cell(cell_dir: Path, expected_runs: int, expected_warmups: int):
    errors = []
    data = cell_dir / "data"

    try:
        status = json.loads((data / "validation.json").read_text())
        if status.get("passed") is not True:
            errors.append("validation.json is not passed")
        if status.get("measured_handshakes") != expected_runs:
            errors.append("measured_handshakes mismatch")
        if status.get("warmup_handshakes") != expected_warmups:
            errors.append("warmup_handshakes mismatch")

        for filename, expected_count, expected_warm in [
            ("observations.csv", expected_runs, 0),
            ("warmups.csv", expected_warmups, 1),
        ]:
            with (data / filename).open() as f:
                rows = list(csv.DictReader(f))

            if len(rows) != expected_count:
                errors.append(f"{filename}: row count mismatch")
                continue

            seen = set()
            for row in rows:
                profile = row["profile"]
                chain_profile = row["chain_profile"]

                if profile not in PROFILES:
                    errors.append(f"{filename}: unknown profile {profile}")
                    continue
                if chain_profile not in CHAIN_PROFILES:
                    errors.append(f"{filename}: unknown chain_profile {chain_profile}")
                    continue

                expected_chain = CHAIN_PROFILES[chain_profile]

                if row["success"] != "1":
                    errors.append(f"{filename}: unsuccessful row")
                if int(row["is_warmup"]) != expected_warm:
                    errors.append(f"{filename}: warmup flag mismatch")
                if row["auth_family"] != "x509":
                    errors.append(f"{filename}: auth_family mismatch")
                if int(row["depth_including_root"]) != expected_chain["depth_including_root"]:
                    errors.append(f"{filename}: depth_including_root mismatch")
                if int(row["chain_depth"]) != expected_chain["chain_depth"]:
                    errors.append(f"{filename}: chain_depth mismatch")
                if int(row["transmitted_certificates"]) != expected_chain["transmitted_certificates"]:
                    errors.append(f"{filename}: transmitted_certificates mismatch")

                client_random = row["client_random"]
                if (
                    len(client_random) != 64
                    or any(c not in "0123456789abcdefABCDEF" for c in client_random)
                    or client_random in seen
                ):
                    errors.append(f"{filename}: invalid/duplicate client_random")
                seen.add(client_random)

                for metric in METRICS:
                    value = float(row[metric])
                    if not math.isfinite(value) or value < 0:
                        errors.append(f"{filename}: invalid metric {metric}")

                log_name = f'{"warmup" if expected_warm else "sample"}-{int(row["round"]):04d}.log'
                log_path = data / "logs" / log_name
                if not log_path.is_file():
                    errors.append(f"{filename}: missing log {log_name}")
                elif "Verify return code: 0 (ok)" not in log_path.read_text():
                    errors.append(f"{filename}: missing verify-ok in log {log_name}")

                server_metric = data / "server-metrics" / (client_random + ".json")
                if not server_metric.is_file():
                    errors.append(f"{filename}: missing server metric")
                else:
                    server = json.loads(server_metric.read_text())
                    if server.get("reused"):
                        errors.append(f"{filename}: reused session on server")
                    if int(server["certificate_message_bytes"]) != int(row["certificate_message_bytes"]):
                        errors.append(f"{filename}: server/client certificate bytes mismatch")

    except Exception as exc:
        errors.append(str(exc))

    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    manifest = json.loads((args.output / "manifest.json").read_text())
    expected_runs = int(manifest["runs"])
    expected_warmups = int(manifest["warmups"])

    all_errors = {}
    for cell in manifest["cells"]:
        cell_dir = args.output / cell["cell"]
        errors = validate_cell(cell_dir, expected_runs, expected_warmups)
        if errors:
            all_errors[cell["cell"]] = sorted(set(errors))

    report = {
        "passed": not all_errors,
        "checked_cells": len(manifest["cells"]),
        "errors": all_errors,
    }

    print(json.dumps(report, indent=2))
    if all_errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
