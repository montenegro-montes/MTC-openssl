#!/usr/bin/env python3
"""Summarize server-only MTC crossover as Merkle population N varies."""

from __future__ import annotations

import argparse
import csv
import json
import statistics
from pathlib import Path

THRESHOLDS = [0.0, 0.01, 0.05, 0.10]
CHAIN_ORDER = [
    "direct-server",
    "ca-server",
    "root-intermediate-server",
]


def read_csv(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fields):
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def mtc_summary(root):
    groups = {}

    for path in root.glob("*/data/observations.csv"):
        for row in read_csv(path):
            if row.get("is_warmup") == "1":
                continue
            key = (row["profile"], int(row["tree_size"]))
            groups.setdefault(key, []).append(row)

    result = []

    for (profile, n), rows in sorted(groups.items()):
        result.append({
            "profile": profile,
            "tree_size": n,
            "n": len(rows),
            "certificate_message_bytes_median": int(statistics.median(
                int(r["certificate_message_bytes"]) for r in rows
            )),
            "mtc_certificate_bytes_median": int(statistics.median(
                int(r["mtc_certificate_bytes"]) for r in rows
            )),
            "proof_bytes_median": int(statistics.median(
                int(r["mtc_inclusion_proof_bytes"]) for r in rows
            )),
            "handshake_wall_ms_median": statistics.median(
                float(r["handshake_wall_ms"]) for r in rows
            ),
        })

    return result


def x509_summary(path):
    rows = read_csv(path)
    result = {}

    for row in rows:
        if row["auth_family"] != "x509":
            continue

        key = (row["profile"], row["chain_profile"])
        result[key] = {
            "bytes": int(float(row["cert_msg_bytes_median"])),
            "wall_ms": float(row["handshake_wall_ms_median"]),
        }

    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mtc-results", type=Path, required=True)
    parser.add_argument("--x509-summary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    output = args.output.resolve()

    if output.exists():
        parser.error("Output exists; summaries are immutable")

    output.mkdir(parents=True)

    mtc = mtc_summary(args.mtc_results.resolve())
    x509 = x509_summary(args.x509_summary.resolve())

    write_csv(
        output / "mtc-by-n.csv",
        mtc,
        [
            "profile",
            "tree_size",
            "n",
            "certificate_message_bytes_median",
            "mtc_certificate_bytes_median",
            "proof_bytes_median",
            "handshake_wall_ms_median",
        ],
    )

    comparisons = []

    for m in mtc:
        profile = m["profile"]
        mtc_bytes = m["certificate_message_bytes_median"]

        for chain in CHAIN_ORDER:
            baseline = x509.get((profile, chain))
            if baseline is None:
                continue

            x509_bytes = baseline["bytes"]
            delta = x509_bytes - mtc_bytes
            gain = delta / x509_bytes

            comparisons.append({
                "profile": profile,
                "chain_profile": chain,
                "tree_size": m["tree_size"],
                "x509_bytes": x509_bytes,
                "mtc_bytes": mtc_bytes,
                "delta_x509_minus_mtc_bytes": delta,
                "relative_saving": gain,
                "relative_saving_pct": gain * 100,
            })

    write_csv(
        output / "mtc-vs-x509-by-n.csv",
        comparisons,
        [
            "profile",
            "chain_profile",
            "tree_size",
            "x509_bytes",
            "mtc_bytes",
            "delta_x509_minus_mtc_bytes",
            "relative_saving",
            "relative_saving_pct",
        ],
    )

    crossover_rows = []

    keys = sorted({
        (r["profile"], r["chain_profile"])
        for r in comparisons
    })

    for profile, chain in keys:
        rows = sorted(
            (
                r for r in comparisons
                if r["profile"] == profile
                and r["chain_profile"] == chain
            ),
            key=lambda r: r["tree_size"],
        )

        favorable = [
            r for r in rows
            if r["delta_x509_minus_mtc_bytes"] > 0
        ]

        first_unfavorable = next(
            (
                r for r in rows
                if r["delta_x509_minus_mtc_bytes"] <= 0
            ),
            None,
        )

        last_favorable = favorable[-1] if favorable else None

        crossover_rows.append({
            "profile": profile,
            "chain_profile": chain,
            "last_tested_favorable_n":
                last_favorable["tree_size"] if last_favorable else "",
            "next_tested_unfavorable_n":
                first_unfavorable["tree_size"]
                if first_unfavorable else "",
            "crossover_interval":
                (
                    f"({last_favorable['tree_size']},"
                    f"{first_unfavorable['tree_size']})"
                    if last_favorable and first_unfavorable
                    else (
                        f">{rows[-1]['tree_size']}"
                        if last_favorable and not first_unfavorable
                        else f"<={rows[0]['tree_size']}"
                    )
                ),
        })

    write_csv(
        output / "crossover-n.csv",
        crossover_rows,
        [
            "profile",
            "chain_profile",
            "last_tested_favorable_n",
            "next_tested_unfavorable_n",
            "crossover_interval",
        ],
    )

    sensitivity = []

    for profile, chain in keys:
        rows = sorted(
            (
                r for r in comparisons
                if r["profile"] == profile
                and r["chain_profile"] == chain
            ),
            key=lambda r: r["tree_size"],
        )

        for threshold in THRESHOLDS:
            favorable = [
                r for r in rows
                if r["relative_saving"] >= threshold
            ]

            last_favorable = favorable[-1] if favorable else None

            next_unfavorable = None
            if last_favorable is not None:
                next_unfavorable = next(
                    (
                        r for r in rows
                        if r["tree_size"] > last_favorable["tree_size"]
                        and r["relative_saving"] < threshold
                    ),
                    None,
                )

            if last_favorable is None:
                interval = f"<={rows[0]['tree_size']}"
            elif next_unfavorable is None:
                interval = f">{rows[-1]['tree_size']}"
            else:
                interval = (
                    f"({last_favorable['tree_size']},"
                    f"{next_unfavorable['tree_size']})"
                )

            sensitivity.append({
                "profile": profile,
                "chain_profile": chain,
                "threshold_pct": threshold * 100,
                "last_tested_n_meeting_threshold":
                    last_favorable["tree_size"] if last_favorable else "",
                "next_tested_n_failing_threshold":
                    next_unfavorable["tree_size"]
                    if next_unfavorable else "",
                "effective_crossover_interval": interval,
                "saving_pct_at_last_tested_n":
                    last_favorable["relative_saving_pct"]
                    if last_favorable else "",
            })

    write_csv(
        output / "crossover-sensitivity.csv",
        sensitivity,
        [
            "profile",
            "chain_profile",
            "threshold_pct",
            "last_tested_n_meeting_threshold",
            "next_tested_n_failing_threshold",
            "effective_crossover_interval",
            "saving_pct_at_last_tested_n",
        ],
    )

    manifest = {
        "experiment": "crossover_n_server_only",
        "mtc_results": str(args.mtc_results.resolve()),
        "x509_summary": str(args.x509_summary.resolve()),
        "thresholds": THRESHOLDS,
        "definition": {
            "raw": "largest tested N for which MTC Certificate-message bytes are smaller than X.509",
            "effective": "largest tested N maintaining at least threshold relative byte saving",
        },
        "outputs": [
            "mtc-by-n.csv",
            "mtc-vs-x509-by-n.csv",
            "crossover-n.csv",
            "crossover-sensitivity.csv",
        ],
    }

    (output / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n"
    )

    print(output)


if __name__ == "__main__":
    main()
