#!/usr/bin/env python3
"""Summarize chain-depth server-only X.509 vs MTC landmark results."""

import argparse
import csv
import json
import statistics as st
from pathlib import Path


CHAIN_ORDER = ["direct-server", "ca-server", "root-intermediate-server"]

CHAIN_LABELS = {
    "direct-server": "Direct",
    "ca-server": "CA",
    "root-intermediate-server": "Root+Int.",
}

PRETTY_PROFILE = {
    "ecdsa-p256": "ECDSA P-256",
    "ecdsa-p384": "ECDSA P-384",
    "ecdsa-p521": "ECDSA P-521",
    "mldsa44": "ML-DSA-44",
    "mldsa65": "ML-DSA-65",
    "mldsa87": "ML-DSA-87",
    "slhdsa128s": "SLH-DSA-128s",
    "slhdsa192s": "SLH-DSA-192s",
    "slhdsa256s": "SLH-DSA-256s",
}


def read_observation_groups(roots):
    groups = {}

    for root in roots:
        for csv_path in sorted(root.glob("*/data/observations.csv")):
            with csv_path.open() as f:
                rows = list(csv.DictReader(f))

            if not rows:
                continue

            r0 = rows[0]
            key = (
                r0["profile"],
                r0["auth_family"],
                r0["chain_profile"],
                r0.get("tree_size", ""),
                r0.get("mtc_mode", ""),
            )
            groups.setdefault(key, []).extend(rows)

    return groups


def write_summary(groups, output):
    summary_rows = []

    for key, rows in sorted(groups.items()):
        profile, auth_family, chain_profile, tree_size, mtc_mode = key

        cert_bytes = [int(float(r["certificate_message_bytes"])) for r in rows]
        wall = [float(r["handshake_wall_ms"]) for r in rows]
        client_cpu = [float(r["client_cpu_ms"]) for r in rows if r.get("client_cpu_ms")]
        server_cpu = [float(r["server_cpu_ms"]) for r in rows if r.get("server_cpu_ms")]

        summary_rows.append(
            {
                "profile": profile,
                "auth_family": auth_family,
                "chain_profile": chain_profile,
                "tree_size": tree_size,
                "mtc_mode": mtc_mode,
                "n": len(rows),
                "cert_msg_bytes_median": int(st.median(cert_bytes)),
                "cert_msg_bytes_min": min(cert_bytes),
                "cert_msg_bytes_max": max(cert_bytes),
                "handshake_wall_ms_median": f"{st.median(wall):.6f}",
                "handshake_wall_ms_mean": f"{st.mean(wall):.6f}",
                "client_cpu_ms_median": f"{st.median(client_cpu):.6f}" if client_cpu else "",
                "server_cpu_ms_median": f"{st.median(server_cpu):.6f}" if server_cpu else "",
            }
        )

    path = output / "summary.csv"
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(summary_rows[0]))
        writer.writeheader()
        writer.writerows(summary_rows)

    return summary_rows, path


def write_savings(summary_rows, output):
    by_profile = {}

    for row in summary_rows:
        by_profile.setdefault(row["profile"], {})[row["chain_profile"]] = row

    saving_rows = []

    for profile, values in sorted(by_profile.items()):
        if "mtc-landmark" not in values:
            raise SystemExit(f"Missing mtc-landmark row for {profile}")

        mtc = values["mtc-landmark"]
        mtc_bytes = int(mtc["cert_msg_bytes_median"])
        mtc_wall = float(mtc["handshake_wall_ms_median"])

        for baseline in CHAIN_ORDER:
            if baseline not in values:
                raise SystemExit(f"Missing {baseline} row for {profile}")

            base = values[baseline]
            base_bytes = int(base["cert_msg_bytes_median"])
            base_wall = float(base["handshake_wall_ms_median"])

            delta_bytes = base_bytes - mtc_bytes
            relative = 100 * delta_bytes / base_bytes
            delta_wall = base_wall - mtc_wall

            saving_rows.append(
                {
                    "profile": profile,
                    "baseline": baseline,
                    "baseline_bytes": base_bytes,
                    "mtc_bytes": mtc_bytes,
                    "delta_baseline_minus_mtc_bytes": delta_bytes,
                    "relative_saving_vs_baseline_pct": f"{relative:.2f}",
                    "baseline_wall_ms_median": f"{base_wall:.6f}",
                    "mtc_wall_ms_median": f"{mtc_wall:.6f}",
                    "delta_baseline_minus_mtc_wall_ms": f"{delta_wall:.6f}",
                }
            )

    path = output / "mtc-savings.csv"
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(saving_rows[0]))
        writer.writeheader()
        writer.writerows(saving_rows)

    return saving_rows, path


def latex_escape_percent(text):
    return text.replace("%", r"\%")


def write_savings_table(saving_rows, output):
    by_profile = {}
    for r in saving_rows:
        by_profile.setdefault(r["profile"], {})[r["baseline"]] = r

    def fmt_cell(r):
        delta = int(r["delta_baseline_minus_mtc_bytes"])
        pct = float(r["relative_saving_vs_baseline_pct"])
        sign = "+" if delta > 0 else ""
        return f"{sign}{delta} B ({sign}{pct:.2f}\\%)"

    lines = [
        r"\begin{table*}[t]",
        r"\centering",
        r"\caption{Byte-level savings of MTC landmark authentication relative to X.509 chain-depth baselines. Positive values indicate fewer Certificate-message bytes with MTC.}",
        r"\label{tab:mtc-chain-depth-savings}",
        r"\begin{tabular}{lrrrr}",
        r"\toprule",
        r"Profile & MTC bytes & Direct & CA & Root+Int. \\",
        r"\midrule",
    ]

    for profile in sorted(by_profile):
        values = by_profile[profile]
        direct = values["direct-server"]
        ca = values["ca-server"]
        root = values["root-intermediate-server"]
        mtc_bytes = direct["mtc_bytes"]

        lines.append(
            f"{PRETTY_PROFILE.get(profile, profile)} & {mtc_bytes} & "
            f"{fmt_cell(direct)} & "
            f"{fmt_cell(ca)} & "
            f"{fmt_cell(root)} \\\\"
        )

    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table*}",
    ]

    path = output / "mtc-savings-table.tex"
    path.write_text("\n".join(lines) + "\n")
    return path


def write_crossover_table(saving_rows, output):
    by_profile = {}
    for r in saving_rows:
        by_profile.setdefault(r["profile"], {})[r["baseline"]] = r

    lines = [
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{First X.509 chain-depth baseline at which MTC landmark authentication becomes byte-efficient.}",
        r"\label{tab:mtc-chain-depth-crossover}",
        r"\begin{tabular}{llr}",
        r"\toprule",
        r"Profile & First byte-efficient baseline & Saving at crossover \\",
        r"\midrule",
    ]

    crossover_rows = []

    for profile in sorted(by_profile):
        crossover = None

        for baseline in CHAIN_ORDER:
            row = by_profile[profile][baseline]
            if int(row["delta_baseline_minus_mtc_bytes"]) > 0:
                crossover = row
                break

        if crossover is None:
            baseline_label = "None"
            saving = "--"
            crossover_from = "none"
        else:
            baseline_label = CHAIN_LABELS[crossover["baseline"]]
            delta = int(crossover["delta_baseline_minus_mtc_bytes"])
            pct = float(crossover["relative_saving_vs_baseline_pct"])
            saving = f"+{delta} B (+{pct:.2f}\\%)"
            crossover_from = crossover["baseline"]

        lines.append(
            f"{PRETTY_PROFILE.get(profile, profile)} & {baseline_label} & {saving} \\\\"
        )

        crossover_rows.append(
            {
                "profile": profile,
                "crossover_from": crossover_from,
                "saving_at_crossover": saving,
            }
        )

    lines += [
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ]

    tex_path = output / "mtc-crossover-table.tex"
    tex_path.write_text("\n".join(lines) + "\n")

    csv_path = output / "mtc-crossover.csv"
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(crossover_rows[0]))
        writer.writeheader()
        writer.writerows(crossover_rows)

    return tex_path, csv_path


def write_readme(output, x509_results, mtc_results):
    readme = f"""# Chain-depth server-only sensitivity summary

This summary compares X.509 server-only authentication at three chain profiles against MTC-experimental landmark authentication with tree size N=16.

## Inputs

- X.509 results: `{x509_results}`
- MTC results: `{mtc_results}`

## Profiles

X.509 chain profiles:

- `direct-server`
- `ca-server`
- `root-intermediate-server`

MTC profile:

- `mtc-landmark`
- `tree_size=16`
- `mtc_mode=landmark`

## Output files

- `summary.csv`: median and mean measurements per profile/authentication mode.
- `mtc-savings.csv`: byte and latency deltas of MTC landmark relative to each X.509 baseline.
- `mtc-crossover.csv`: first X.509 baseline where MTC becomes byte-efficient.
- `mtc-savings-table.tex`: LaTeX table with all byte savings.
- `mtc-crossover-table.tex`: compact LaTeX crossover table.
- `manifest.json`: provenance for the summary.

## Byte-level crossover

The byte-level crossover is defined as the first X.509 baseline, ordered from `direct-server` to `ca-server` to `root-intermediate-server`, for which:

```text
baseline Certificate-message bytes > MTC landmark Certificate-message bytes
Main interpretation
MTC landmark N=16 becomes increasingly advantageous as the X.509 chain grows. For small ECDSA certificates, the crossover depends on curve size and chain depth. For ML-DSA and SLH-DSA profiles, MTC is already byte-efficient at the direct-server baseline.
Latency should be interpreted separately from bytes. In particular, SLH-DSA remains dominated by expensive signature operations, so large byte savings do not necessarily translate into proportional handshake-time reductions.
Notes for paper use
This result should be described as a server-only authentication sensitivity experiment. It should not be mixed with mutual authentication, trust-anchor retry, or latency/loss/bandwidth network experiments.
The MTC row corresponds to the experimental landmark mode with pre-distributed trust.bin. Therefore, the comparison is a byte-level authentication transport comparison, not a claim that the complete trust-distribution problem disappears.
"""
    path = output / "README-results.md"
    path.write_text(readme)
    return path
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--x509-results", type=Path, required=True)
    parser.add_argument("--mtc-results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    x509_results = args.x509_results.resolve()
    mtc_results = args.mtc_results.resolve()
    output = args.output.resolve()

    if output.exists():
        raise SystemExit("Output exists; summaries are immutable")

    output.mkdir(parents=True)

    groups = read_observation_groups([x509_results, mtc_results])
    summary_rows, summary_csv = write_summary(groups, output)
    saving_rows, savings_csv = write_savings(summary_rows, output)
    savings_table = write_savings_table(saving_rows, output)
    crossover_table, crossover_csv = write_crossover_table(saving_rows, output)
    readme = write_readme(output, x509_results, mtc_results)

    manifest = {
        "experiment": "chain_depth_server_only",
        "x509_results": str(x509_results),
        "mtc_results": str(mtc_results),
        "summary_csv": str(summary_csv),
        "savings_csv": str(savings_csv),
        "crossover_csv": str(crossover_csv),
        "savings_table_tex": str(savings_table),
        "crossover_table_tex": str(crossover_table),
        "readme": str(readme),
        "profiles": sorted({row["profile"] for row in summary_rows}),
        "x509_chain_profiles": CHAIN_ORDER,
        "mtc_chain_profile": "mtc-landmark",
        "tree_size": 16,
        "mtc_mode": "landmark",
    }

    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    print(output)
    print(summary_csv)
    print(savings_csv)
    print(crossover_csv)
    print(savings_table)
    print(crossover_table)
    print(readme)


if __name__ == "__main__":
    main()
