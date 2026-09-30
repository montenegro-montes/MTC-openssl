"""MTC Trust Anchor ID retry validation campaign.

Validates two transaction shapes:

- happy: direct authentication, one connection, zero retries.
- retry: first connection fails because of Trust Anchor ID mismatch,
  followed by exactly one new authenticated connection.

This is a native retry-validation experiment. It does not use PCAP timing.
"""

import argparse
import json
import math
import os
import random
import statistics
import subprocess
import sys
import time
import uuid
from pathlib import Path


REPO = Path(__file__).resolve().parents[4]

DEFAULT_PEER = Path("/tmp/mtc-retry-peer-measure")

HOSTNAME = "server"

SCENARIOS = {}


def configure_scenarios(peer, trust):
    """Derive scenario IDs from authenticated native trust evidence."""
    inspected = subprocess.run(
        [str(peer), "inspect", str(trust), "landmark"],
        check=True, capture_output=True, text=True,
    )
    records = [
        json.loads(line.removeprefix("MTC_RETRY_TRUST "))
        for line in inspected.stdout.splitlines()
        if line.startswith("MTC_RETRY_TRUST ")
    ]
    if len(records) != 1:
        raise RuntimeError("native trust inspection did not return one identity")
    sys.path.insert(0, str(REPO / "src/mtc"))
    import retry as retry_controller
    trusted = retry_controller.decode_id(bytes.fromhex(records[0]["trusted_id_hex"]))
    parts = trusted.split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    mismatched = ".".join(parts)
    SCENARIOS.clear()
    SCENARIOS.update({
        "happy": {"initial_id": trusted, "expected_attempts": 1, "expected_retries": 0},
        "retry": {"initial_id": mismatched, "expected_attempts": 2, "expected_retries": 1},
    })


def save_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def append_jsonl(path, value):
    with path.open("a") as handle:
        handle.write(json.dumps(value, sort_keys=True) + "\n")


def design(mode):
    if mode == "preflight":
        warmup_rounds = 1
        measured_rounds = 1
    elif mode == "full":
        warmup_rounds = 5
        measured_rounds = 30
    else:
        raise ValueError(mode)

    return {
        "experiment": "mtc-retry-validation",
        "purpose": (
            "Validate direct authentication and one bounded external "
            "Trust Anchor ID retry using native measurements."
        ),
        "mode": mode,
        "scenarios": SCENARIOS,
        "warmup_rounds_per_scenario": warmup_rounds,
        "measured_rounds_per_scenario": measured_rounds,
        "warmup_transactions": warmup_rounds * len(SCENARIOS),
        "measured_transactions": measured_rounds * len(SCENARIOS),
        "measurement_source": "native",
        "primary_metrics": [
            "retry_total_tcp_connect_wall_ms_native",
            "retry_total_tls_attempt_wall_ms",
            "retry_total_attempt_wall_ms_native",
            "retry_total_tls_bytes_read",
            "retry_total_tls_bytes_written",
            "retry_total_tls_bytes",
        ],
        "validation_rules": {
            "happy": {
                "attempt_count": 1,
                "retry_count": 0,
                "attempt_results": ["PASS"],
            },
            "retry": {
                "attempt_count": 2,
                "retry_count": 1,
                "attempt_results": ["FAIL", "PASS"],
                "first_failure_reason": "trust_anchor_mismatch",
                "distinct_connection_ids": True,
            },
        },
    }


def validate_inputs(peer, trust, cert, key):
    for path, label in [
        (peer, "peer"),
        (trust, "trust"),
        (cert, "certificate"),
        (key, "key"),
    ]:
        if not path.is_file():
            raise SystemExit(f"{label} missing: {path}")

    if not REPO.joinpath("src/mtc/retry.py").is_file():
        raise SystemExit("src/mtc/retry.py missing")


def validate_report(report, scenario):
    expected = SCENARIOS[scenario]

    if report["final_result"] != "PASS":
        raise RuntimeError(
            f"{scenario}: final_result != PASS: "
            f"{report.get('final_result')}"
        )

    if report["attempt_count"] != expected["expected_attempts"]:
        raise RuntimeError(
            f"{scenario}: unexpected attempt_count "
            f"{report['attempt_count']}"
        )

    if report["retry_count"] != expected["expected_retries"]:
        raise RuntimeError(
            f"{scenario}: unexpected retry_count "
            f"{report['retry_count']}"
        )

    attempts = report.get("attempts", [])

    if len(attempts) != expected["expected_attempts"]:
        raise RuntimeError(
            f"{scenario}: unexpected attempts list length {len(attempts)}"
        )

    if scenario == "happy":
        if report["attempt_1_result"] != "PASS":
            raise RuntimeError("happy: attempt 1 did not PASS")

        if report["attempt_2_result"] is not None:
            raise RuntimeError("happy: unexpected second attempt")

        if attempts[0]["reason"] != "authenticated":
            raise RuntimeError(
                "happy: unexpected attempt reason "
                f"{attempts[0]['reason']}"
            )

        if attempts[0]["session_reused"] is not False:
            raise RuntimeError("happy: session reuse detected")

    elif scenario == "retry":
        if report["attempt_1_result"] != "FAIL":
            raise RuntimeError("retry: first attempt did not FAIL")

        if report["attempt_2_result"] != "PASS":
            raise RuntimeError("retry: second attempt did not PASS")

        if attempts[0]["reason"] != "trust_anchor_mismatch":
            raise RuntimeError(
                "retry: unexpected first failure reason "
                f"{attempts[0]['reason']}"
            )

        if attempts[1]["reason"] != "authenticated":
            raise RuntimeError(
                "retry: unexpected second result reason "
                f"{attempts[1]['reason']}"
            )

        if report["retry_selected_id"] != SCENARIOS["happy"]["initial_id"]:
            raise RuntimeError(
                "retry: unexpected retry_selected_id "
                f"{report['retry_selected_id']}"
            )

        first = report["attempt_1_connection_id"]
        second = report["attempt_2_connection_id"]

        if not first or not second or first == second:
            raise RuntimeError(
                "retry: connection IDs are missing or identical"
            )

        if any(a["session_reused"] is not False for a in attempts):
            raise RuntimeError("retry: session reuse detected")


def flatten_report(report, scenario, round_id, is_warmup):
    row = {
        "campaign_id": None,
        "round_id": round_id,
        "scenario": scenario,
        "is_warmup": is_warmup,
        "initial_trust_anchor_id": report["initial_trust_anchor_id"],
        "server_supported_ids": report["server_supported_ids"],
        "retry_selected_id": report["retry_selected_id"],
        "attempt_count": report["attempt_count"],
        "retry_count": report["retry_count"],
        "attempt_1_result": report["attempt_1_result"],
        "attempt_2_result": report["attempt_2_result"],
        "final_result": report["final_result"],
        "attempt_1_connection_id": report["attempt_1_connection_id"],
        "attempt_2_connection_id": report["attempt_2_connection_id"],
        "retry_total_tcp_connect_wall_ms_native": report[
            "retry_total_tcp_connect_wall_ms_native"
        ],
        "retry_total_tls_attempt_wall_ms": report[
            "retry_total_tls_attempt_wall_ms"
        ],
        "retry_total_attempt_wall_ms_native": report[
            "retry_total_attempt_wall_ms_native"
        ],
        "retry_total_tls_bytes_read": report["retry_total_tls_bytes_read"],
        "retry_total_tls_bytes_written": report["retry_total_tls_bytes_written"],
        "retry_total_tls_bytes": report["retry_total_tls_bytes"],
    }

    for index, attempt in enumerate(report["attempts"], 1):
        prefix = f"attempt_{index}"

        row[f"{prefix}_reason"] = attempt["reason"]
        row[f"{prefix}_requested_id"] = attempt["requested_id"]
        row[f"{prefix}_session_reused"] = attempt["session_reused"]
        row[f"{prefix}_tls_version"] = attempt["tls_version"]
        row[f"{prefix}_cipher"] = attempt["cipher"]
        row[f"{prefix}_negotiated_group"] = attempt["negotiated_group"]

        row[f"{prefix}_tcp_connect_wall_ms_native"] = attempt[
            "retry_tcp_connect_wall_ms_native"
        ]
        row[f"{prefix}_tls_attempt_wall_ms"] = attempt[
            "retry_tls_attempt_wall_ms"
        ]
        row[f"{prefix}_attempt_wall_ms_native"] = attempt[
            "retry_attempt_wall_ms_native"
        ]
        row[f"{prefix}_tls_bytes_read"] = attempt["tls_bytes_read"]
        row[f"{prefix}_tls_bytes_written"] = attempt["tls_bytes_written"]
        row[f"{prefix}_tls_bytes_total"] = attempt["tls_bytes_total"]

    return row


def run_transaction(
    peer,
    trust,
    cert,
    key,
    scenario,
    port,
):
    initial_id = SCENARIOS[scenario]["initial_id"]
    expected_connections = SCENARIOS[scenario]["expected_attempts"]

    server = subprocess.Popen(
        [
            str(peer),
            "server",
            "127.0.0.1",
            str(port),
            str(trust),
            "landmark",
            str(cert),
            str(key),
            str(expected_connections),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        ready = server.stdout.readline().strip()

        # retry-peer prints MTC_SETUP before MTC_RETRY_READY.
        if ready.startswith("MTC_SETUP "):
            ready = server.stdout.readline().strip()

        if ready != "MTC_RETRY_READY":
            stderr = server.stderr.read()
            raise RuntimeError(
                "server did not become ready: "
                f"stdout={ready!r} stderr={stderr!r}"
            )

        completed = subprocess.run(
            [
                sys.executable,
                str(REPO / "src/mtc/retry.py"),
                "--peer",
                str(peer),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--hostname",
                HOSTNAME,
                "--trust",
                str(trust),
                "--initial-id",
                initial_id,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        server_stdout, server_stderr = server.communicate(timeout=10)

        try:
            report = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "retry.py did not return valid JSON\n"
                f"stdout:\n{completed.stdout}\n"
                f"stderr:\n{completed.stderr}\n"
                f"server stdout:\n{server_stdout}\n"
                f"server stderr:\n{server_stderr}"
            ) from exc

        if completed.returncode != 0:
            raise RuntimeError(
                "retry.py failed\n"
                f"report:\n{json.dumps(report, indent=2)}\n"
                f"stderr:\n{completed.stderr}"
            )

        if server.returncode != 0:
            raise RuntimeError(
                "retry peer server failed\n"
                f"stdout:\n{server_stdout}\n"
                f"stderr:\n{server_stderr}"
            )

        validate_report(report, scenario)

        return report

    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=3)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


T95 = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571,
    6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228,
    11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
    16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060,
    26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042,
}


def metric_summary(values):
    n = len(values)
    mean = statistics.fmean(values)
    sample_stdev = statistics.stdev(values) if n > 1 else None
    if sample_stdev is None:
        ci_low = ci_high = None
    else:
        margin = T95.get(n - 1, 1.960) * sample_stdev / math.sqrt(n)
        ci_low, ci_high = mean - margin, mean + margin
    return {
        "n": n,
        "min": min(values),
        "median": statistics.median(values),
        "mean": mean,
        "sample_stdev": sample_stdev,
        "mean_95_ci_low": ci_low,
        "mean_95_ci_high": ci_high,
        "max": max(values),
    }


BOOTSTRAP_RESAMPLES = 10000
BOOTSTRAP_SEED = 42


def percentile(values, p):
    """Linear-interpolated percentile for an already sorted sample."""
    if not values:
        raise ValueError("empty percentile input")

    ordered = sorted(values)

    if len(ordered) == 1:
        return ordered[0]

    position = (len(ordered) - 1) * p
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower

    return (
        ordered[lower] * (1.0 - fraction)
        + ordered[upper] * fraction
    )


def bootstrap_median_ci(values, resamples=BOOTSTRAP_RESAMPLES, seed=BOOTSTRAP_SEED):
    """Percentile bootstrap CI for the median.

    The resampling unit is one paired happy/retry round.
    """
    if not values:
        raise ValueError("empty bootstrap input")

    rng = random.Random(seed)
    n = len(values)

    medians = []

    for _ in range(resamples):
        sample = [
            values[rng.randrange(n)]
            for _ in range(n)
        ]
        medians.append(statistics.median(sample))

    return [
        percentile(medians, 0.025),
        percentile(medians, 0.975),
    ]


def build_pairs(measured):
    """Build strict happy/retry pairs using round_id."""
    by_round = {}

    for row in measured:
        round_id = row["round_id"]
        scenario = row["scenario"]

        if scenario not in SCENARIOS:
            raise RuntimeError(
                f"unexpected scenario in measured observations: {scenario}"
            )

        slot = by_round.setdefault(round_id, {})

        if scenario in slot:
            raise RuntimeError(
                f"duplicate measured observation: "
                f"round={round_id} scenario={scenario}"
            )

        slot[scenario] = row

    pairs = []

    for round_id in sorted(by_round):
        slot = by_round[round_id]

        if set(slot) != {"happy", "retry"}:
            raise RuntimeError(
                f"incomplete measured pair at round {round_id}: "
                f"{sorted(slot)}"
            )

        pairs.append(
            {
                "round_id": round_id,
                "happy": slot["happy"],
                "retry": slot["retry"],
            }
        )

    return pairs


def paired_effect_summary(measured, metrics):
    pairs = build_pairs(measured)

    result = {
        "pairing_key": "round_id",
        "n_pairs": len(pairs),
        "difference_definition": "retry_minus_happy",
        "bootstrap": {
            "resamples": BOOTSTRAP_RESAMPLES,
            "seed": BOOTSTRAP_SEED,
            "unit": "paired measured round",
            "interval": "percentile 95% CI for median paired delta",
        },
        "metrics": {},
    }

    for metric in metrics:
        deltas = [
            pair["retry"][metric] - pair["happy"][metric]
            for pair in pairs
        ]

        result["metrics"][metric] = {
            "n_pairs": len(deltas),
            "median_delta_ms": statistics.median(deltas),
            "mean_delta_ms": statistics.fmean(deltas),
            "min_delta_ms": min(deltas),
            "max_delta_ms": max(deltas),
            "bootstrap_95_ci_median_ms": bootstrap_median_ci(deltas),
        }

    return result


def retry_attempt_breakdown(measured):
    retry_rows = [
        row
        for row in measured
        if row["scenario"] == "retry"
    ]

    fields = {
        "attempt_1_tcp_connect_wall_ms_native":
            "attempt_1_tcp_connect_wall_ms_native",
        "attempt_1_tls_attempt_wall_ms":
            "attempt_1_tls_attempt_wall_ms",
        "attempt_1_attempt_wall_ms_native":
            "attempt_1_attempt_wall_ms_native",
        "attempt_2_tcp_connect_wall_ms_native":
            "attempt_2_tcp_connect_wall_ms_native",
        "attempt_2_tls_attempt_wall_ms":
            "attempt_2_tls_attempt_wall_ms",
        "attempt_2_attempt_wall_ms_native":
            "attempt_2_attempt_wall_ms_native",
    }

    return {
        "n": len(retry_rows),
        "attempt_1": {
            "expected_result": "FAIL",
            "expected_reason": "trust_anchor_mismatch",
            "tcp_connect_wall_ms_native": metric_summary(
                [
                    row[fields["attempt_1_tcp_connect_wall_ms_native"]]
                    for row in retry_rows
                ]
            ),
            "tls_attempt_wall_ms": metric_summary(
                [
                    row[fields["attempt_1_tls_attempt_wall_ms"]]
                    for row in retry_rows
                ]
            ),
            "attempt_wall_ms_native": metric_summary(
                [
                    row[fields["attempt_1_attempt_wall_ms_native"]]
                    for row in retry_rows
                ]
            ),
        },
        "attempt_2": {
            "expected_result": "PASS",
            "expected_reason": "authenticated",
            "tcp_connect_wall_ms_native": metric_summary(
                [
                    row[fields["attempt_2_tcp_connect_wall_ms_native"]]
                    for row in retry_rows
                ]
            ),
            "tls_attempt_wall_ms": metric_summary(
                [
                    row[fields["attempt_2_tls_attempt_wall_ms"]]
                    for row in retry_rows
                ]
            ),
            "attempt_wall_ms_native": metric_summary(
                [
                    row[fields["attempt_2_attempt_wall_ms_native"]]
                    for row in retry_rows
                ]
            ),
        },
    }


def build_summary(rows):
    measured = [
        row
        for row in rows
        if not row["is_warmup"]
    ]

    metrics = [
        "retry_total_tcp_connect_wall_ms_native",
        "retry_total_tls_attempt_wall_ms",
        "retry_total_attempt_wall_ms_native",
        "retry_total_tls_bytes_read",
        "retry_total_tls_bytes_written",
        "retry_total_tls_bytes",
    ]

    result = {
        "measured_transactions": len(measured),
        "scenarios": {},
    }

    for scenario in SCENARIOS:
        selected = [
            row
            for row in measured
            if row["scenario"] == scenario
        ]

        result["scenarios"][scenario] = {
            "n": len(selected),
            "metrics": {
                metric: metric_summary(
                    [row[metric] for row in selected]
                )
                for metric in metrics
            },
        }

    # Keep the old unpaired descriptive comparison for compatibility.
    happy = result["scenarios"]["happy"]["metrics"]
    retry = result["scenarios"]["retry"]["metrics"]

    result["unpaired_descriptive"] = {
        "retry_minus_happy_median_ms": {
            metric: (
                retry[metric]["median"]
                - happy[metric]["median"]
            )
            for metric in metrics
        },
        "retry_over_happy_median_ratio": {
            metric: (
                retry[metric]["median"]
                / happy[metric]["median"]
                if happy[metric]["median"] > 0
                else None
            )
            for metric in metrics
        },
    }

    # Primary comparison: paired by measured round_id.
    result["paired_retry_effect"] = paired_effect_summary(
        measured,
        metrics,
    )

    # Explain where the retry cost comes from.
    result["retry_attempt_breakdown"] = retry_attempt_breakdown(
        measured
    )

    return result



def main():
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument(
        "mode",
        choices=["preflight", "full"],
        help="validation campaign size",
    )

    parser.add_argument(
        "--root",
        type=Path,
        required=True,
        help="output directory under artifacts/results",
    )

    parser.add_argument(
        "--peer",
        type=Path,
        default=DEFAULT_PEER,
    )

    parser.add_argument(
        "--trust",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--cert",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--key",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--base-port",
        type=int,
        default=19443,
    )
    parser.add_argument(
        "--profile",
        default="not-recorded",
        help="cryptographic profile label recorded in campaign metadata",
    )
    parser.add_argument("--leaf", type=int, default=0, help="configured MTC leaf recorded in campaign metadata")
    parser.add_argument("--progress-offset", type=int, default=0)
    parser.add_argument("--progress-total", type=int)

    args = parser.parse_args()

    root = args.root.resolve()

    results_root = (REPO / "artifacts/results").resolve()

    if not root.is_relative_to(results_root):
        raise SystemExit(
            "--root must be under artifacts/results"
        )

    if root.exists():
        raise SystemExit(
            f"Refusing to overwrite existing root: {root}"
        )

    validate_inputs(
        args.peer,
        args.trust,
        args.cert,
        args.key,
    )
    configure_scenarios(args.peer, args.trust)

    root.mkdir(parents=True)

    campaign_id = uuid.uuid4().hex
    campaign_design = design(args.mode)

    metadata = {
        **campaign_design,
        "campaign_id": campaign_id,
        "created_unix_ns": time.time_ns(),
        "peer": str(args.peer),
        "trust": str(args.trust),
        "cert": str(args.cert),
        "key": str(args.key),
        "hostname": HOSTNAME,
        "profile": args.profile,
        "leaf": args.leaf,
        "key_establishment": {
            "id": os.environ.get("MTC_KEM_ID", "x25519"),
            "label": os.environ.get("MTC_KEM_LABEL", "X25519"),
            "openssl_group": os.environ.get("MTC_TLS_GROUP", "X25519"),
        },
    }

    save_json(root / "design.json", metadata)

    observations_path = root / "observations.jsonl"
    raw_root = root / "raw"
    raw_root.mkdir()

    all_rows = []

    warmup_rounds = campaign_design[
        "warmup_rounds_per_scenario"
    ]
    measured_rounds = campaign_design[
        "measured_rounds_per_scenario"
    ]

    sequence = []

    for is_warmup, rounds in [
        (True, warmup_rounds),
        (False, measured_rounds),
    ]:
        for round_id in range(1, rounds + 1):
            # Keep the same deterministic scenario ordering.
            for scenario in ["happy", "retry"]:
                sequence.append(
                    (is_warmup, round_id, scenario)
                )

    for index, (is_warmup, round_id, scenario) in enumerate(
        sequence,
        1,
    ):
        port = args.base_port + (index % 1000)

        progress_total = args.progress_total or len(sequence)
        print(
            f"[{args.progress_offset + index}/{progress_total}] "
            f"profile={args.profile} "
            f"{'warmup' if is_warmup else 'measured'} "
            f"round={round_id} "
            f"scenario={scenario} "
            f"port={port}",
            flush=True,
        )

        report = run_transaction(
            args.peer,
            args.trust,
            args.cert,
            args.key,
            scenario,
            port,
        )

        raw_name = (
            f"{'warmup' if is_warmup else 'measured'}-"
            f"{round_id:03d}-{scenario}.json"
        )

        save_json(raw_root / raw_name, report)

        row = flatten_report(
            report,
            scenario,
            round_id,
            is_warmup,
        )

        row["campaign_id"] = campaign_id

        append_jsonl(observations_path, row)
        all_rows.append(row)

    summary = build_summary(all_rows)
    summary["campaign_id"] = campaign_id
    summary["mode"] = args.mode

    save_json(root / "summary.json", summary)

    status = {
        "status": "PASS",
        "campaign_id": campaign_id,
        "mode": args.mode,
        "observations": len(all_rows),
        "warmup_transactions": campaign_design[
            "warmup_transactions"
        ],
        "measured_transactions": campaign_design[
            "measured_transactions"
        ],
    }

    save_json(root / "status.json", status)

    print()
    print(json.dumps(status, indent=2))
    print()
    print(f"Results: {root}")


if __name__ == "__main__":
    main()
