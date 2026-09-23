#!/usr/bin/env python3

import argparse
import csv
import json
import statistics
from pathlib import Path
from config import MTC_N_VALUES, PROFILES

THRESHOLDS = [0.0, 0.01, 0.05, 0.10]

CHAIN_ORDER = [
    "direct-server",
    "ca-server",
]


def read_csv(path):
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fields,
        )
        writer.writeheader()
        writer.writerows(rows)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--output",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    input_root = args.input.resolve()
    output_root = args.output.resolve()

    observations_path = (
        input_root / "observations.csv"
    )

    require(
        observations_path.is_file(),
        f"missing {observations_path}",
    )

    if output_root.exists():
        raise SystemExit(
            f"output already exists: {output_root}"
        )

    output_root.mkdir(parents=True)

    rows = read_csv(observations_path)
    source_summary = json.loads((input_root / "summary.json").read_text())
    expected_x509 = 2 * len(PROFILES)
    expected_mtc = sum(len(values) for values in MTC_N_VALUES.values())
    expected_rows = source_summary["runs_per_case"] * (expected_x509 + expected_mtc)

    require(
        len(rows) == expected_rows,
        f"expected {expected_rows} observations, got {len(rows)}",
    )

    # --------------------------------------------------------
    # X.509 baselines
    # --------------------------------------------------------

    x509_groups = {}

    for row in rows:
        if row["auth_family"] != "x509":
            continue

        key = (
            row["profile"],
            row["x509_chain_profile"],
        )

        x509_groups.setdefault(
            key,
            [],
        ).append(row)

    x509 = {}

    x509_rows = []

    for key, group in sorted(
        x509_groups.items()
    ):
        profile, chain = key

        values = [
            int(r["certificate_total_bytes"])
            for r in group
        ]

        require(
            len(set(values)) == 1,
            (
                f"{profile}/{chain}: "
                f"X.509 bytes not invariant: "
                f"{sorted(set(values))}"
            ),
        )

        server_values = [
            int(r["server_certificate_bytes"])
            for r in group
        ]

        client_values = [
            int(r["client_certificate_bytes"])
            for r in group
        ]

        handshake_values = [
            int(r["handshake_total_bytes"])
            for r in group
        ]

        wall_values = [
            float(r["client_handshake_wall_ms"])
            for r in group
        ]

        value = values[0]

        x509[key] = value

        x509_rows.append({
            "profile": profile,
            "chain_profile": chain,
            "n": len(group),

            "server_certificate_bytes":
                int(statistics.median(
                    server_values
                )),

            "client_certificate_bytes":
                int(statistics.median(
                    client_values
                )),

            "certificate_total_bytes":
                value,

            "handshake_total_bytes_median":
                statistics.median(
                    handshake_values
                ),

            "handshake_total_bytes_min":
                min(handshake_values),

            "handshake_total_bytes_max":
                max(handshake_values),

            "client_handshake_wall_ms_median":
                statistics.median(
                    wall_values
                ),
        })

    require(
        len(x509_rows) == expected_x509,
        f"expected {expected_x509} X.509 baselines, got {len(x509_rows)}",
    )

    write_csv(
        output_root / "x509-baselines.csv",
        x509_rows,
        [
            "profile",
            "chain_profile",
            "n",
            "server_certificate_bytes",
            "client_certificate_bytes",
            "certificate_total_bytes",
            "handshake_total_bytes_median",
            "handshake_total_bytes_min",
            "handshake_total_bytes_max",
            "client_handshake_wall_ms_median",
        ],
    )

    # --------------------------------------------------------
    # MTC by profile / N
    # --------------------------------------------------------

    mtc_groups = {}

    for row in rows:
        if row["auth_family"] != "mtc-experimental":
            continue

        key = (
            row["profile"],
            int(row["tree_size"]),
        )

        mtc_groups.setdefault(
            key,
            [],
        ).append(row)

    mtc_rows = []

    for (profile, n), group in sorted(
        mtc_groups.items()
    ):
        total_values = [
            int(r["certificate_total_bytes"])
            for r in group
        ]

        require(
            len(set(total_values)) == 1,
            (
                f"{profile}/N={n}: "
                f"MTC bytes not invariant: "
                f"{sorted(set(total_values))}"
            ),
        )

        server_values = [
            int(r["server_certificate_bytes"])
            for r in group
        ]

        client_values = [
            int(r["client_certificate_bytes"])
            for r in group
        ]

        handshake_values = [
            int(r["handshake_total_bytes"])
            for r in group
        ]

        wall_values = [
            float(r["client_handshake_wall_ms"])
            for r in group
        ]

        mtc_rows.append({
            "profile": profile,
            "tree_size": n,
            "n": len(group),

            "server_certificate_bytes":
                int(statistics.median(
                    server_values
                )),

            "client_certificate_bytes":
                int(statistics.median(
                    client_values
                )),

            "certificate_total_bytes":
                total_values[0],

            "handshake_total_bytes_median":
                statistics.median(
                    handshake_values
                ),

            "handshake_total_bytes_min":
                min(handshake_values),

            "handshake_total_bytes_max":
                max(handshake_values),

            "client_handshake_wall_ms_median":
                statistics.median(
                    wall_values
                ),
        })

    require(
        len(mtc_rows) == expected_mtc,
        f"expected {expected_mtc} MTC cells, got {len(mtc_rows)}",
    )

    write_csv(
        output_root / "mtc-by-n.csv",
        mtc_rows,
        [
            "profile",
            "tree_size",
            "n",
            "server_certificate_bytes",
            "client_certificate_bytes",
            "certificate_total_bytes",
            "handshake_total_bytes_median",
            "handshake_total_bytes_min",
            "handshake_total_bytes_max",
            "client_handshake_wall_ms_median",
        ],
    )

    # --------------------------------------------------------
    # Compare each MTC point against both X.509 comparators.
    # --------------------------------------------------------

    comparisons = []

    for mtc in mtc_rows:
        profile = mtc["profile"]
        n = mtc["tree_size"]
        mtc_bytes = int(
            mtc["certificate_total_bytes"]
        )

        for chain in CHAIN_ORDER:
            baseline = x509.get(
                (profile, chain)
            )

            require(
                baseline is not None,
                f"missing baseline {profile}/{chain}",
            )

            delta = baseline - mtc_bytes
            gain = delta / baseline

            comparisons.append({
                "profile": profile,
                "chain_profile": chain,
                "tree_size": n,

                "x509_certificate_total_bytes":
                    baseline,

                "mtc_certificate_total_bytes":
                    mtc_bytes,

                "delta_x509_minus_mtc_bytes":
                    delta,

                "relative_saving":
                    gain,

                "relative_saving_pct":
                    gain * 100,
            })

    write_csv(
        output_root / "mtc-vs-x509-by-n.csv",
        comparisons,
        [
            "profile",
            "chain_profile",
            "tree_size",
            "x509_certificate_total_bytes",
            "mtc_certificate_total_bytes",
            "delta_x509_minus_mtc_bytes",
            "relative_saving",
            "relative_saving_pct",
        ],
    )

    # --------------------------------------------------------
    # Raw crossover
    # --------------------------------------------------------

    keys = sorted({
        (
            r["profile"],
            r["chain_profile"],
        )
        for r in comparisons
    })

    crossover_rows = []

    for profile, chain in keys:
        series = sorted(
            [
                r
                for r in comparisons
                if r["profile"] == profile
                and r["chain_profile"] == chain
            ],
            key=lambda r: r["tree_size"],
        )

        favorable = [
            r
            for r in series
            if r[
                "delta_x509_minus_mtc_bytes"
            ] > 0
        ]

        last_favorable = (
            favorable[-1]
            if favorable
            else None
        )

        first_unfavorable = next(
            (
                r
                for r in series
                if r[
                    "delta_x509_minus_mtc_bytes"
                ] <= 0
            ),
            None,
        )

        if (
            last_favorable is not None
            and first_unfavorable is not None
        ):
            interval = (
                f"({last_favorable['tree_size']},"
                f"{first_unfavorable['tree_size']})"
            )

        elif last_favorable is not None:
            interval = (
                f">{series[-1]['tree_size']}"
            )

        else:
            interval = (
                f"<={series[0]['tree_size']}"
            )

        crossover_rows.append({
            "profile": profile,
            "chain_profile": chain,

            "x509_certificate_total_bytes":
                series[0][
                    "x509_certificate_total_bytes"
                ],

            "last_tested_favorable_n":
                (
                    last_favorable["tree_size"]
                    if last_favorable
                    else ""
                ),

            "mtc_bytes_at_last_favorable":
                (
                    last_favorable[
                        "mtc_certificate_total_bytes"
                    ]
                    if last_favorable
                    else ""
                ),

            "delta_bytes_at_last_favorable":
                (
                    last_favorable[
                        "delta_x509_minus_mtc_bytes"
                    ]
                    if last_favorable
                    else ""
                ),

            "saving_pct_at_last_favorable":
                (
                    last_favorable[
                        "relative_saving_pct"
                    ]
                    if last_favorable
                    else ""
                ),

            "next_tested_unfavorable_n":
                (
                    first_unfavorable["tree_size"]
                    if first_unfavorable
                    else ""
                ),

            "mtc_bytes_at_next_unfavorable":
                (
                    first_unfavorable[
                        "mtc_certificate_total_bytes"
                    ]
                    if first_unfavorable
                    else ""
                ),

            "delta_bytes_at_next_unfavorable":
                (
                    first_unfavorable[
                        "delta_x509_minus_mtc_bytes"
                    ]
                    if first_unfavorable
                    else ""
                ),

            "crossover_interval":
                interval,
        })

    write_csv(
        output_root / "crossover-n.csv",
        crossover_rows,
        [
            "profile",
            "chain_profile",
            "x509_certificate_total_bytes",
            "last_tested_favorable_n",
            "mtc_bytes_at_last_favorable",
            "delta_bytes_at_last_favorable",
            "saving_pct_at_last_favorable",
            "next_tested_unfavorable_n",
            "mtc_bytes_at_next_unfavorable",
            "delta_bytes_at_next_unfavorable",
            "crossover_interval",
        ],
    )

    # --------------------------------------------------------
    # Effective crossover sensitivity
    # --------------------------------------------------------

    sensitivity = []

    for profile, chain in keys:
        series = sorted(
            [
                r
                for r in comparisons
                if r["profile"] == profile
                and r["chain_profile"] == chain
            ],
            key=lambda r: r["tree_size"],
        )

        for threshold in THRESHOLDS:
            # Raw 0% crossover means strictly smaller than X.509.
            # Positive thresholds retain points meeting or exceeding
            # the requested minimum relative saving.
            if threshold == 0.0:
                favorable = [
                    r
                    for r in series
                    if r["relative_saving"] > 0
                ]
            else:
                favorable = [
                    r
                    for r in series
                    if r["relative_saving"] >= threshold
                ]

            last_favorable = (
                favorable[-1]
                if favorable
                else None
            )

            next_unfavorable = None

            if last_favorable is not None:
                next_unfavorable = next(
                    (
                        r
                        for r in series
                        if (
                            r["tree_size"]
                            > last_favorable[
                                "tree_size"
                            ]
                            and
                            r[
                                "relative_saving"
                            ]
                            < threshold
                        )
                    ),
                    None,
                )
            if last_favorable is None:
                if series[0]["tree_size"] == 1:
                    interval = "none"
                else:
                    interval = (
                        f"<={series[0]['tree_size']}"
                    )
            
            elif next_unfavorable is None:
                interval = (
                    f">{series[-1]['tree_size']}"
                )

            else:
                interval = (
                    f"({last_favorable['tree_size']},"
                    f"{next_unfavorable['tree_size']})"
                )

            sensitivity.append({
                "profile": profile,
                "chain_profile": chain,

                "threshold_pct":
                    threshold * 100,

                "last_tested_n_meeting_threshold":
                    (
                        last_favorable["tree_size"]
                        if last_favorable
                        else ""
                    ),

                "next_tested_n_failing_threshold":
                    (
                        next_unfavorable["tree_size"]
                        if next_unfavorable
                        else ""
                    ),

                "effective_crossover_interval":
                    interval,

                "saving_pct_at_last_tested_n":
                    (
                        last_favorable[
                            "relative_saving_pct"
                        ]
                        if last_favorable
                        else ""
                    ),

                "delta_bytes_at_last_tested_n":
                    (
                        last_favorable[
                            "delta_x509_minus_mtc_bytes"
                        ]
                        if last_favorable
                        else ""
                    ),
            })

    write_csv(
        output_root / "crossover-sensitivity.csv",
        sensitivity,
        [
            "profile",
            "chain_profile",
            "threshold_pct",
            "last_tested_n_meeting_threshold",
            "next_tested_n_failing_threshold",
            "effective_crossover_interval",
            "saving_pct_at_last_tested_n",
            "delta_bytes_at_last_tested_n",
        ],
    )

    manifest = {
        "experiment":
            "mutual-auth-crossover",

        "source":
            str(input_root),

        "observation_count":
            len(rows),

        "primary_metric":
            "certificate_total_bytes",

        "definition": {
            "certificate_total_bytes":
                (
                    "server TLS Certificate "
                    "handshake-message bytes + "
                    "client TLS Certificate "
                    "handshake-message bytes"
                ),

            "raw_crossover":
                (
                    "largest tested N for which "
                    "MTC mutual Certificate total "
                    "bytes are smaller than X.509 "
                    "mutual Certificate total bytes"
                ),

            "effective_crossover":
                (
                    "largest tested N retaining "
                    "at least the requested relative "
                    "byte saving"
                ),
        },

        "thresholds":
            THRESHOLDS,

        "outputs": [
            "x509-baselines.csv",
            "mtc-by-n.csv",
            "mtc-vs-x509-by-n.csv",
            "crossover-n.csv",
            "crossover-sensitivity.csv",
        ],
    }

    (
        output_root / "manifest.json"
    ).write_text(
        json.dumps(
            manifest,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        "=== MUTUAL AUTH CROSSOVER SUMMARY PASS ==="
    )
    print(
        f"observations = {len(rows)}"
    )
    print(
        f"x509 baselines = {len(x509_rows)}"
    )
    print(
        f"mtc cells = {len(mtc_rows)}"
    )
    print(
        f"comparisons = {len(comparisons)}"
    )
    print(
        f"crossover cases = {len(crossover_rows)}"
    )
    print(output_root)


if __name__ == "__main__":
    main()
