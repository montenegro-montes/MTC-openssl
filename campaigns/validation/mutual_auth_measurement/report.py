#!/usr/bin/env python3
import argparse
import csv
from pathlib import Path


def fmt(value):
    if value is None or value == "":
        return ""
    try:
        return f"{float(value):.3f}"
    except ValueError:
        return str(value)


def read_rows(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def build_report(root, rows):
    lines = []
    lines.append("# Mutual authentication measurement report")
    lines.append("")
    lines.append(f"Result root: `{root}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(
        "| Case | Count | Median wall ms | Δ wall ms | Median total bytes | Δ bytes | Byte ratio | "
        "Client MTC setup ms | Client MTC verify ms | Server MTC setup ms | Server MTC verify ms | "
        "Total MTC setup ms | Total MTC verify ms |"
    )
    lines.append(
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    )

    for row in rows:
        lines.append(
            "| {case} | {count} | {wall} | {delta_wall} | {bytes_total} | {delta_bytes} | {ratio} | "
            "{client_setup} | {client_verify} | {server_setup} | {server_verify} | {mtc_setup} | {mtc_verify} |".format(
                case=row["case_name"],
                count=row["count"],
                wall=fmt(row["handshake_wall_ms_median"]),
                delta_wall=fmt(row["delta_vs_baseline_wall_ms_median"]),
                bytes_total=fmt(row["bytes_total_median"]),
                delta_bytes=fmt(row["delta_vs_baseline_bytes_total_median"]),
                ratio=fmt(row["ratio_vs_baseline_bytes_total_median"]),
                client_setup=fmt(row.get("client_mtc_setup_ms_median")),
                client_verify=fmt(row.get("client_mtc_verify_ms_median")),
                server_setup=fmt(row.get("server_mtc_setup_ms_median")),
                server_verify=fmt(row.get("server_mtc_verify_ms_median")),
                mtc_setup=fmt(row.get("mtc_setup_ms_median")),
                mtc_verify=fmt(row.get("mtc_verify_ms_median")),
            )
        )

    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append(
        "The strongest signal in this campaign is the handshake byte footprint. "
        "The host-side wall-clock measurements are useful as auxiliary validation, "
        "but they include process, Docker and client/server orchestration overhead."
    )
    lines.append("")
    lines.append(
        "The MTC timing columns are extracted from the experimental MTC instrumentation. "
        "Client-side and server-side MTC timings are reported separately. "
        "The total MTC setup and verification columns aggregate the available endpoint "
        "observations for each handshake."
    )
    lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()

    root = args.root
    summary_csv = root / "analysis-summary.csv"
    if not summary_csv.exists():
        raise SystemExit(f"ABORT: missing {summary_csv}")

    rows = read_rows(summary_csv)
    report = build_report(root, rows)

    out = root / "report.md"
    out.write_text(report, encoding="utf-8")
    print(f"PASS wrote {out}")


if __name__ == "__main__":
    main()
