#!/usr/bin/env python3

import argparse
import csv
import hashlib
import json
import statistics
from pathlib import Path


CONDITIONS = ("local", "latency-100", "constrained")

TIMING_FIELDS = {
    "tcp": (
        "tcp_connect_wall_ms_native",
        "tcp_connect_wall_ms",
        "native_minus_pcap_tcp_ms",
    ),
    "tls": (
        "handshake_wall_ms",
        "tls_from_pcap_wall_ms",
        "native_minus_pcap_tls_ms",
    ),
    "full": (
        "connection_establishment_wall_ms_native",
        "connection_handshake_wall_ms",
        "native_minus_pcap_full_ms",
    ),
}


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_jsonl(path: Path):
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSONL at {path}:{line_no}"
                ) from exc
    return rows


def sha256(path: Path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def median_required(rows, field):
    values = [row.get(field) for row in rows]

    if any(value is None for value in values):
        raise RuntimeError(
            f"Missing {field} in one or more successful paired observations"
        )

    if not values:
        raise RuntimeError(f"No values available for {field}")

    return statistics.median(values)


def build_condition_summary(root: Path, condition: str, all_rows):
    rows = [
        row for row in all_rows
        if row.get("condition") == condition
    ]

    status_path = root / f"full-{condition}-status.json"

    if not status_path.is_file():
        raise RuntimeError(f"Missing status file: {status_path}")

    status = load_json(status_path)

    expected_pairs = status.get("successful_native_pcap_pairs")

    if expected_pairs is None:
        raise RuntimeError(
            f"{status_path} does not contain successful_native_pcap_pairs"
        )

    if len(rows) != expected_pairs:
        raise RuntimeError(
            f"{condition}: paired-observations contains {len(rows)} rows "
            f"but status reports {expected_pairs} successful pairs"
        )

    paired_summary = status.get("paired_summary")

    if not isinstance(paired_summary, dict):
        raise RuntimeError(
            f"{status_path} does not contain paired_summary"
        )

    result = {
        "condition": condition,
        "measured_attempts": status.get("measured_attempts"),
        "successful_tls_observations":
            status.get("successful_tls_observations"),
        "successful_native_pcap_pairs":
            status.get("successful_native_pcap_pairs"),
        "incomplete_or_unpairable_observations":
            status.get("incomplete_or_unpairable_observations"),
    }

    timings = {}

    for name, (native_field, pcap_field, delta_key) in TIMING_FIELDS.items():

        delta = paired_summary.get(delta_key)

        if not isinstance(delta, dict):
            raise RuntimeError(
                f"{status_path} missing paired summary {delta_key}"
            )

        timings[name] = {
            "native_field": native_field,
            "pcap_field": pcap_field,

            # Absolute medians are derived from the accepted
            # successful paired observations.
            "native_median_ms":
                median_required(rows, native_field),

            "pcap_median_ms":
                median_required(rows, pcap_field),

            # Paired differences and bootstrap intervals are reused
            # from the canonical campaign status. They are NOT
            # reconstructed from the marginal medians.
            "median_delta_ms":
                delta["median_delta_ms"],

            "ci95_lower_ms":
                delta["ci95_lower_ms"],

            "ci95_upper_ms":
                delta["ci95_upper_ms"],

            "n_successful_pairs":
                delta["n_successful_pairs"],

            "bootstrap_seed":
                delta["bootstrap_seed"],

            "bootstrap_resamples":
                delta["bootstrap_resamples"],

            "bootstrap_unit":
                delta["bootstrap_unit"],
        }

    result["timings"] = timings
    result["status_sha256"] = sha256(status_path)

    return result


def generate_validation_summary(root: Path):
    root = root.resolve()

    pairs_path = root / "paired-observations.jsonl"
    csv_path = root / "validation-summary.csv"
    json_path = root / "validation-summary.json"

    if not pairs_path.is_file():
        raise RuntimeError(
            f"Missing aggregated paired observations: {pairs_path}"
        )

    # Preserve immutable-output semantics.
    for output in (csv_path, json_path):
        if output.exists():
            raise RuntimeError(
                f"Refusing to overwrite existing summary: {output}"
            )

    rows = load_jsonl(pairs_path)

    summaries = [
        build_condition_summary(root, condition, rows)
        for condition in CONDITIONS
    ]

    document = {
        "experiment": "native-pcap-validation",
        "artifact": "validation-summary",
        "source_population":
            "PCAP-enabled successful paired observations",
        "difference_sign": "native_minus_pcap",
        "full_timing_reconstructed": False,
        "native_pcap_values_interchangeable": False,
        "source_paired_observations":
            str(pairs_path.relative_to(root)),
        "source_paired_observations_sha256":
            sha256(pairs_path),
        "conditions": summaries,
    }

    csv_fields = [
        "condition",
        "measured_attempts",
        "successful_tls_observations",
        "successful_native_pcap_pairs",
        "incomplete_or_unpairable_observations",

        "native_tcp_median_ms",
        "pcap_tcp_median_ms",
        "delta_tcp_median_ms",
        "delta_tcp_ci95_lower_ms",
        "delta_tcp_ci95_upper_ms",

        "native_tls_median_ms",
        "pcap_tls_median_ms",
        "delta_tls_median_ms",
        "delta_tls_ci95_lower_ms",
        "delta_tls_ci95_upper_ms",

        "native_full_median_ms",
        "pcap_full_median_ms",
        "delta_full_median_ms",
        "delta_full_ci95_lower_ms",
        "delta_full_ci95_upper_ms",
    ]

    csv_rows = []

    for item in summaries:
        csv_row = {
            "condition": item["condition"],
            "measured_attempts": item["measured_attempts"],
            "successful_tls_observations":
                item["successful_tls_observations"],
            "successful_native_pcap_pairs":
                item["successful_native_pcap_pairs"],
            "incomplete_or_unpairable_observations":
                item["incomplete_or_unpairable_observations"],
        }

        for timing in ("tcp", "tls", "full"):
            value = item["timings"][timing]

            csv_row[f"native_{timing}_median_ms"] = (
                value["native_median_ms"]
            )
            csv_row[f"pcap_{timing}_median_ms"] = (
                value["pcap_median_ms"]
            )
            csv_row[f"delta_{timing}_median_ms"] = (
                value["median_delta_ms"]
            )
            csv_row[f"delta_{timing}_ci95_lower_ms"] = (
                value["ci95_lower_ms"]
            )
            csv_row[f"delta_{timing}_ci95_upper_ms"] = (
                value["ci95_upper_ms"]
            )

        csv_rows.append(csv_row)

    # Both outputs are checked above before either is written.
    with csv_path.open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=csv_fields)
        writer.writeheader()
        writer.writerows(csv_rows)

    with json_path.open("x", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")

    print(f"wrote {csv_path}")
    print(f"wrote {json_path}")

    return csv_path, json_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "root",
        type=Path,
        help="Completed native/PCAP full validation root",
    )
    args = parser.parse_args()

    generate_validation_summary(args.root)


if __name__ == "__main__":
    main()