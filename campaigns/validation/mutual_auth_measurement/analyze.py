#!/usr/bin/env python3
import argparse
import csv
import json
import statistics
from pathlib import Path


BASELINE = "x509_server_x509_client"


def as_float(value):
    if value is None or value == "":
        return None
    return float(value)


def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def mean(values):
    values = [v for v in values if v is not None]
    return statistics.mean(values) if values else None


def load_observations(path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f))


def summarize(rows):
    by_case = {}
    for row in rows:
        by_case.setdefault(row["case_name"], []).append(row)

    summary = {}
    for case, case_rows in by_case.items():
        wall = [as_float(r["handshake_wall_ms"]) for r in case_rows]
        read = [as_float(r["bytes_read"]) for r in case_rows]
        written = [as_float(r["bytes_written"]) for r in case_rows]
        client_mtc_setup = [as_float(r.get("client_mtc_setup_ms")) for r in case_rows]
        client_mtc_verify = [as_float(r.get("client_mtc_verify_ms")) for r in case_rows]
        server_mtc_setup = [as_float(r.get("server_mtc_setup_ms")) for r in case_rows]
        server_mtc_verify = [as_float(r.get("server_mtc_verify_ms")) for r in case_rows]
        mtc_setup = [as_float(r.get("mtc_setup_ms")) for r in case_rows]
        mtc_verify = [as_float(r.get("mtc_verify_ms")) for r in case_rows]

        summary[case] = {
            "count": len(case_rows),
            "handshake_wall_ms_median": median(wall),
            "handshake_wall_ms_mean": mean(wall),
            "bytes_read_median": median(read),
            "bytes_written_median": median(written),
            "bytes_total_median": (
                median(read) + median(written)
                if median(read) is not None and median(written) is not None
                else None
            ),
            "client_mtc_setup_ms_median": median(client_mtc_setup),
            "client_mtc_verify_ms_median": median(client_mtc_verify),
            "server_mtc_setup_ms_median": median(server_mtc_setup),
            "server_mtc_verify_ms_median": median(server_mtc_verify),
            "mtc_setup_ms_median": median(mtc_setup),
            "mtc_verify_ms_median": median(mtc_verify),
        }

    return summary


def add_deltas(summary):
    if BASELINE not in summary:
        raise SystemExit(f"baseline case missing: {BASELINE}")

    base = summary[BASELINE]
    base_wall = base["handshake_wall_ms_median"]
    base_read = base["bytes_read_median"]
    base_written = base["bytes_written_median"]
    base_total = base["bytes_total_median"]

    for case, data in summary.items():
        data["delta_vs_baseline_wall_ms_median"] = (
            data["handshake_wall_ms_median"] - base_wall
            if data["handshake_wall_ms_median"] is not None and base_wall is not None
            else None
        )
        data["delta_vs_baseline_bytes_read_median"] = (
            data["bytes_read_median"] - base_read
            if data["bytes_read_median"] is not None and base_read is not None
            else None
        )
        data["delta_vs_baseline_bytes_written_median"] = (
            data["bytes_written_median"] - base_written
            if data["bytes_written_median"] is not None and base_written is not None
            else None
        )
        data["delta_vs_baseline_bytes_total_median"] = (
            data["bytes_total_median"] - base_total
            if data["bytes_total_median"] is not None and base_total is not None
            else None
        )
        data["ratio_vs_baseline_bytes_total_median"] = (
            data["bytes_total_median"] / base_total
            if data["bytes_total_median"] is not None and base_total not in (None, 0)
            else None
        )

    return summary


def write_csv(path, summary):
    fields = [
        "case_name",
        "count",
        "handshake_wall_ms_median",
        "handshake_wall_ms_mean",
        "delta_vs_baseline_wall_ms_median",
        "bytes_read_median",
        "bytes_written_median",
        "bytes_total_median",
        "delta_vs_baseline_bytes_read_median",
        "delta_vs_baseline_bytes_written_median",
        "delta_vs_baseline_bytes_total_median",
        "ratio_vs_baseline_bytes_total_median",
        "client_mtc_setup_ms_median",
        "client_mtc_verify_ms_median",
        "server_mtc_setup_ms_median",
        "server_mtc_verify_ms_median",
        "mtc_setup_ms_median",
        "mtc_verify_ms_median",
    ]

    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for case_name, data in summary.items():
            row = {"case_name": case_name}
            row.update(data)
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()

    root = args.root
    observations = root / "observations.csv"
    if not observations.exists():
        raise SystemExit(f"missing observations.csv: {observations}")

    rows = load_observations(observations)
    summary = add_deltas(summarize(rows))

    out_json = root / "analysis-summary.json"
    out_csv = root / "analysis-summary.csv"

    out_json.write_text(json.dumps({
        "result": "PASS",
        "baseline": BASELINE,
        "case_count": len(summary),
        "cases": summary,
    }, indent=2), encoding="utf-8")

    write_csv(out_csv, summary)

    print(f"PASS wrote {out_json}")
    print(f"PASS wrote {out_csv}")


if __name__ == "__main__":
    main()
