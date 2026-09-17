"""Native/PCAP validation paired Native <-> PCAP instrumentation validation.

This is an instrumentation-validation experiment, not an authentication
performance experiment. Native timing remains the primary application-side
measurement; PCAP provides an independent on-wire observation.
"""
import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
import summary_outputs
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "campaigns/common"))
from pcap_capture import capture_session
# Native/PCAP validation helpers are importable both as a script and from offline tests.
sys.path.insert(0,str(Path(__file__).parent))
import results
import gate as full_gate

LATENCY_COMPOSE = [
    "docker", "compose",
    "-f", str(REPO / "docker/original_campaigns/compose.network-latency.yaml"),
    "-f", str(REPO / "campaigns/validation/native_pcap/compose.validation.yaml"),
]


def load(path):
    return json.loads(path.read_text())


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def hashes_ok(root):
    for name in ["baseline-source-sha256.json", "fixture-sha256.json"]:
        for relative, digest in load(root / name).items():
            path = REPO / relative
            if not path.is_file():
                raise RuntimeError("Preservation mismatch: " + relative)
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise RuntimeError("Preservation mismatch: " + relative)


def parse_latency_ping(text):
    values = [float(x) for x in re.findall(r"time=([0-9.]+) ms", text)]
    if len(values) != 20:
        raise RuntimeError(f"Expected 20 RTT probes, got {len(values)}")
    values.sort()
    return {
        "measured_rtt_min_ms": values[0],
        "measured_rtt_median_ms": (values[9] + values[10]) / 2,
        "measured_rtt_max_ms": values[-1],
        "probes_sent": 20,
        "probes_received": len(values),
        "packet_loss_percent": 0.0,
    }


def validate_probe_integrity(probe, probe_wall_ms):
    if probe_wall_ms <= 0:
        raise ValueError("Invalid probe wall time")
    if probe["measured_rtt_max_ms"] > probe_wall_ms:
        raise ValueError(
            "Reported ping RTT exceeds independently measured probe wall time: "
            f'max_rtt_ms={probe["measured_rtt_max_ms"]:.3f}, '
            f"probe_wall_ms={probe_wall_ms:.3f}"
        )

SCENARIO = "pq"

CONDITIONS = {
    "local": {
        "compose": "docker/original_campaigns/compose.network-latency.yaml",
        "network_family": "latency",
        "additional_rtt_ms": 0,
        "half_delay_ms": 0,
        "rate_mbit": None,
        "loss_percent": 0,
        "failure_aware": False,
    },
    "latency-100": {
        "compose": "docker/original_campaigns/compose.network-latency.yaml",
        "network_family": "latency",
        "additional_rtt_ms": 100,
        "half_delay_ms": 50,
        "rate_mbit": None,
        "loss_percent": 0,
        "failure_aware": False,
    },
    "constrained": {
        "compose": "docker/original_campaigns/compose.network-combined.yaml",
        "network_family": "combined",
        "profile": "constrained",
        "additional_rtt_ms": 100,
        "half_delay_ms": 50,
        "rate_mbit": 5,
        "loss_percent": 1,
        "failure_aware": True,
    },
}

TIMING_PAIRS = [
    {
        "native": "tcp_connect_wall_ms_native",
        "pcap": "tcp_connect_wall_ms",
        "difference": "native_minus_pcap_tcp_ms",
    },
    {
        "native": "handshake_wall_ms",
        "pcap": "tls_from_pcap_wall_ms",
        "difference": "native_minus_pcap_tls_ms",
    },
    {
        "native": "connection_establishment_wall_ms_native",
        "pcap": "connection_handshake_wall_ms",
        "difference": "native_minus_pcap_full_ms",
    },
]


def design(mode):
    if mode == "preflight":
        measured_rounds = 1
        warmup_rounds = 1
    elif mode == "full":
        measured_rounds = 30
        warmup_rounds = 5
    else:
        raise ValueError(mode)

    return {
        "experiment": "native-pcap-validation",
        "purpose": "paired instrumentation validation; not authentication performance",
        "mode": mode,
        "scenario": SCENARIO,
        "conditions": CONDITIONS,
        "conditions_count": len(CONDITIONS),
        "measured_rounds_per_condition": measured_rounds,
        "warmup_rounds_per_condition": warmup_rounds,
        "measured_attempts": len(CONDITIONS) * measured_rounds,
        "warmup_attempts": len(CONDITIONS) * warmup_rounds,
        "pcap": {
            "measured": True,
            "warmups": False,
            "population": "PCAP-enabled measured observations; separate from uncaptured scientific populations",
        },
        "pairing": {
            "required_identity": [
                "campaign_id",
                "round_id",
                "scenario",
                "is_warmup",
                "client_random",
            ],
            "successful_pair_requires_client_random": True,
            "difference_sign": "native_minus_pcap",
            "timing_pairs": TIMING_PAIRS,
        },
        "probe_integrity": {
            "clock": "host time.monotonic_ns",
            "rule": "reported measured_rtt_max_ms must not exceed independently measured probe_wall_ms",
            "scientific_rtt_gate_remains_separate": True,
        },
        "full_validation": {
            "bootstrap_resamples": results.BOOTSTRAP_RESAMPLES,
            "bootstrap_seed": results.BOOTSTRAP_SEED,
            "bootstrap_unit": "paired Native/PCAP validation measured observation within condition",
            "interpretation": "instrumentation validation only; no performance inference or correction factor",
        },
        "restrictions": [
            "do not reconstruct full timing as TCP + TLS",
            "do not force Native and PCAP equality",
            "do not derive correction factors",
            "do not merge captured and uncaptured populations",
            "do not rank authentication mechanisms",
        ],
    }



def compose_for(condition):
    return ["docker", "compose", "-f", str(REPO / CONDITIONS[condition]["compose"]),
            "-f", str(REPO / "campaigns/validation/native_pcap/compose.validation.yaml")]


def combined_helpers():
    # Import the existing authoritative hierarchy and gates, without executing a campaign.
    sys.path.insert(0, str(REPO / "campaigns/original_campaigns/combined_network_campaign"))
    from network import validate_qdisc, parse_ping, parse_iperf, validate_throughput, section
    from config import PROFILES
    return validate_qdisc, parse_ping, parse_iperf, validate_throughput, section, PROFILES


def apply_server_network(container, condition):
    if condition == "constrained":
        subprocess.run(["docker", "exec", container, "python3", "/opt/network-combined/apply_network.py"], check=True)
        subprocess.run(["docker", "exec", container, "iperf3", "-s", "-D"], check=True)
    elif CONDITIONS[condition]["half_delay_ms"]:
        subprocess.run(["docker", "exec", container, "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "delay", f'{CONDITIONS[condition]["half_delay_ms"]}ms'], check=True)


def validate_network(condition, server_qdisc, probe_text, probe_wall_ms):
    if condition == "constrained":
        validate_qdisc, parse_ping, parse_iperf, validate_throughput, section, profiles = combined_helpers()
        profile = profiles["constrained"]
        client_qdisc = section(probe_text, "QDISC_CLIENT_BEGIN", "QDISC_CLIENT_END")
        validate_qdisc(server_qdisc, profile)
        validate_qdisc(client_qdisc, profile)
        probe = parse_ping(probe_text, 200)
        throughput = parse_iperf(probe_text)
        validate_throughput(throughput, profile["rate_mbit"])
        tolerance = 10
        probe["measured_bandwidth_mbit"] = throughput
        probe["bandwidth_gate_direction"] = "reverse; preserved Combined gate"
    else:
        match = re.search(r"QDISC_CLIENT_BEGIN\n(.*?)QDISC_CLIENT_END", probe_text, re.S)
        if not match:
            raise RuntimeError("Missing client qdisc")
        client_qdisc = match.group(1)
        for text in [server_qdisc, client_qdisc]:
            lower = text.lower()
            if any(kind in lower for kind in ["tbf", "htb", "hfsc", "cake", "loss", "reorder", "duplicate", "corrupt"]):
                raise RuntimeError("Unexpected impairment in latency/local condition")
            if condition == "local":
                if "netem" in lower or "delay" in lower:
                    raise RuntimeError("Unexpected local impairment")
            elif "netem" not in lower or "delay 50ms" not in lower:
                raise RuntimeError("Expected 50ms delay on both endpoints")
        probe = parse_latency_ping(probe_text)
        tolerance = 3 if condition == "local" else 15
    validate_probe_integrity(probe, probe_wall_ms)
    target = CONDITIONS[condition]["additional_rtt_ms"]
    if abs(probe["measured_rtt_median_ms"] - target) > tolerance:
        raise RuntimeError("Measured RTT outside declared tolerance")
    return probe, client_qdisc, tolerance


def execute_local_preflight(root):
    return execute_condition_preflight(root, "local")


def execute_preflight(root):
    root = root.resolve()
    if not root.is_relative_to(REPO / "artifacts/results") or not root.is_dir():
        raise SystemExit("Existing root under artifacts/results is required")
    path = root / "preflight-status.json"
    if path.exists():
        raise SystemExit("Refusing to overwrite/retry preflight status")
    status = {"passed": False, "conditions": {}, "full_executed": False}
    save(path, status)
    try:
        for condition in CONDITIONS:
            print(f"preflight {condition}: 1 warmup + 1 measured pq handshake", flush=True)
            execute_condition_preflight(root, condition)
            status["conditions"][condition] = load(root / f"preflight-{condition}-status.json")
        status["passed"] = all(v["passed"] for v in status["conditions"].values())
        print("validation three-condition preflight PASS", flush=True)
    except BaseException as error:
        status["passed"] = False
        status["error"] = repr(error)
        for condition in CONDITIONS:
            result = root / f"preflight-{condition}-status.json"
            if result.exists(): status["conditions"][condition] = load(result)
        raise
    finally:
        save(path, status)


def execute_condition_preflight(root, condition):
    return execute_condition(root,condition,"preflight",1,1)


def execute_condition_full(root, condition, gate_root):
    return execute_condition(root,condition,"full",30,5,gate_root)


def execute_condition(root, condition, mode, measured_rounds, warmup_rounds, gate_root=None):
    """Shared validated lifecycle; only mode counts and constrained failure policy differ."""
    root = root.resolve()

    if not root.is_relative_to(REPO / "artifacts/results"):
        raise SystemExit("root must be under artifacts/results")

    gate_root = root if gate_root is None else gate_root.resolve()
    gate_path = gate_root / "tests-status.json"
    if not gate_path.is_file():
        raise SystemExit("ABORT: tests-status.json missing")

    gate = load(gate_path)
    if not gate.get("passed"):
        raise SystemExit("ABORT: tests did not pass")

    network = json.loads(
        subprocess.check_output(
            ["docker", "image", "inspect", "mt-tls-network:latency"],
            text=True,
        )
    )[0]

    capture = json.loads(
        subprocess.check_output(
            ["docker", "image", "inspect", "mt-tls-capture:local"],
            text=True,
        )
    )[0]

    if network["Id"] != gate.get("network_image_id"):
        raise SystemExit("ABORT: untested network image")

    if capture["Id"] != gate.get("capture_image_id"):
        raise SystemExit("ABORT: untested capture image")

    full_gate.check_hashes(REPO,gate_root,load(Path(__file__).parent/"source-transitions.json") if mode=="full" else None)
    if mode=="full":check_full_sources(root)

    compose = compose_for(condition)
    spec = CONDITIONS[condition]
    status_path = root / f"{mode}-{condition}-status.json"
    output = root / f"{mode}-{condition}"

    if status_path.exists():
        raise SystemExit("Refusing to overwrite/retry condition preflight status")
    if output.exists():
        raise SystemExit("Refusing existing condition preflight output")

    output.mkdir()

    campaign_id = f"native-pcap-{condition}-{mode}"
    seed = 900001
    directory = output / campaign_id
    directory.mkdir()

    status = {
        "experiment": "native-pcap-validation",
        "condition": condition,
        "scenario": SCENARIO,
        "passed": False,
        "network_image_id": network["Id"],
        "capture_image_id": capture["Id"],
        "mode": mode,
        "measured_rounds": measured_rounds,
        "warmup_rounds": warmup_rounds,
        "pcap_enabled": True,
        "performance_comparable_to_uncaptured": False,
        "measurement_population":
            "PCAP-enabled measured observation; separate from uncaptured populations",
    }
    save(status_path, status)

    env = os.environ.copy()
    env.update(
        MEASUREMENT_RUN_ROOT="/work/" + str(output.relative_to(REPO / "artifacts")),
        MEASUREMENT_CAMPAIGN_ID=campaign_id,
        MEASUREMENT_SEED=str(seed),
        NETWORK_HALF_DELAY_MS=str(spec["half_delay_ms"]),
        VALIDATION_NETWORK_FAMILY=spec["network_family"],
        VALIDATION_NETWORK_IMAGE=network["Id"],
        VALIDATION_CAPTURE_IMAGE=capture["Id"],
        MEASUREMENT_PCAP="1",
    )

    if condition == "constrained":
        profile = combined_helpers()[-1]["constrained"]
        env.update(NETWORK_PROFILE_JSON=json.dumps(profile), LOSS_TARGET_PERCENT="1", PROBE_PACKETS="200", HANDSHAKE_TIMEOUT_SECONDS="30")
    save(output / "source-sha256.json", {str(p.relative_to(REPO)): hashlib.sha256(p.read_bytes()).hexdigest()
         for p in Path(__file__).parent.iterdir() if p.is_file()})

    try:
        with (directory / "server-start.log").open("w") as log:
            subprocess.run(
                compose
                + ["up", "-d", "--force-recreate", "--wait", "server"],
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=True,
            )

        container = subprocess.check_output(
            compose + ["ps", "-q", "server"],
            env=env,
            text=True,
        ).strip()

        cfg = json.loads(
            subprocess.check_output(["docker", "inspect", container], text=True)
        )[0]

        if cfg["Image"] != network["Id"]:
            raise RuntimeError("Server identity/image mismatch")

        apply_server_network(container, condition)

        server_qdisc = subprocess.check_output(
            ["docker", "exec", container, "tc", "-s", "qdisc", "show", "dev", "eth0"],
            text=True,
        )
        (directory / "server-qdisc-before.txt").write_text(server_qdisc)

        probe_start = time.monotonic_ns()
        probe_result = subprocess.run(
            compose + ["run", "--rm", "client", "probe"],
            env=env,
            text=True,
            capture_output=True,
            check=True,
        )
        probe_wall_ms = (time.monotonic_ns() - probe_start) / 1_000_000

        probe_text = probe_result.stdout + probe_result.stderr
        (directory / "network-probe.txt").write_text(probe_text)

        probe, client_qdisc, tolerance = validate_network(condition, server_qdisc, probe_text, probe_wall_ms)
        (directory / "client-qdisc-before.txt").write_text(client_qdisc)
        status["network_validation"] = {"passed": True, "configured": spec, "rtt_tolerance_ms": tolerance, **probe}
        save(status_path, status)

        save(
            directory / "probe-integrity.json",
            {
                "passed": True,
                "clock": "host time.monotonic_ns",
                "probe_wall_ms": probe_wall_ms,
                **probe,
            },
        )

        with capture_session(
            compose,
            directory,
            env,
            True,
            measured_rounds,
            allow_failed=spec["failure_aware"],
        ):
            with (directory / "driver.log").open("w") as log:
                subprocess.run(
                    compose
                    + [
                        "run", "--rm", "client", "measure",
                        "--runs", str(measured_rounds),
                        "--warmup", str(warmup_rounds),
                        "--seed", str(seed),
                        "--image-id", network["Id"],
                        "--scenarios", SCENARIO,
                    ] + (["--failure-aware"] if mode=="full" and spec["failure_aware"] else []),
                    env=env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    check=True,
                )

        driver_text = (directory / "driver.log").read_text()
        client_before = re.search(r"QDISC_CLIENT_BEFORE_BEGIN\n(.*?)QDISC_CLIENT_BEFORE_END", driver_text, re.S)
        if not client_before:
            raise RuntimeError("Missing measured-client qdisc evidence")
        # Validate the fresh measured client, not just the earlier probe container.
        replacement = re.sub(r"QDISC_CLIENT_BEGIN\n.*?QDISC_CLIENT_END",
                             lambda _: "QDISC_CLIENT_BEGIN\n" + client_before.group(1) + "QDISC_CLIENT_END",
                             probe_text, count=1, flags=re.S)
        validate_network(condition, server_qdisc, replacement, probe_wall_ms)
        (directory / "client-qdisc-measurement.txt").write_text(client_before.group(1))

        paired,accounting = results.collect(directory,condition,campaign_id,measured_rounds,warmup_rounds,
                                             spec["failure_aware"],preflight=mode=="preflight")
        with (directory/"paired-observations.jsonl").open("x") as handle:
            for row in paired:handle.write(json.dumps(row)+"\n")
        status.update(passed=True,image_identity_valid=True,association_valid=True,integrity_valid=True,
                      campaign_id=campaign_id,seed=seed,probe_wall_ms=probe_wall_ms,**probe,**accounting,
                      source_integrity_status="PASS",
                      difference_sign="native_minus_pcap",measured_observations=accounting["successful_tls_observations"],
                      warmup_observations=accounting["warmup_successes"])
        if mode=="preflight":
            row=paired[0]
            status.update(tls_status="SUCCESS",capture_status="SUCCESS",analysis_status="SUCCESS",
                          paired_timings={key:row[key] for pair in TIMING_PAIRS for key in pair.values()},
                          measured_client_random=row["client_random"],pcap_sha256=row["pcap_sha256"],tcp_stream=row["tcp_stream"])
        else:
            status.update(tls_status="FAILURES_RECORDED" if accounting["failed_tls_observations"] else "SUCCESS",
                          pcap_integrity_status="PASS",paired_summary=results.summarize(paired,condition))
        save(status_path, status)

        full_gate.check_hashes(REPO,gate_root,load(Path(__file__).parent/"source-transitions.json") if mode=="full" else None)
        if mode=="full":check_full_sources(root)
        print(f"validation {condition} {mode} PASS", flush=True)

    except BaseException as error:
        status["passed"] = False
        status["error"] = repr(error)
        save(status_path, status)
        raise

    finally:
        with (root / f"{mode}-{condition}-shutdown.log").open("w") as log:
            subprocess.run(
                compose + ["down"],
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            )

def full_source_hashes():
    files={p for p in Path(__file__).parent.iterdir() if p.is_file()}
    files.update(REPO/relative for relative in ["campaigns/common/pcap_capture.py",
                 "campaigns/original_campaigns/handshake_capture/analyze.py",*{c["compose"] for c in CONDITIONS.values()}])
    return {str(p.relative_to(REPO)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def check_full_sources(root):
    if load(root/"full-source-sha256.json")!=full_source_hashes():raise RuntimeError("Full execution source mismatch")


def execute_full(root,preflight_root):
    root=root.resolve()
    if not root.is_relative_to(REPO/"artifacts/results") or root.exists():
        raise SystemExit("Full root must be new and nonexistent under artifacts/results")
    if preflight_root is None:raise SystemExit("--full requires --preflight-root")
    if root.is_relative_to(preflight_root.resolve()):raise SystemExit("Full output must be outside the approved preflight root")
    provenance=full_gate.validate(REPO,preflight_root,CONDITIONS,results.collect,
                                  load(Path(__file__).parent/"source-transitions.json"))
    root.mkdir(parents=True,exist_ok=False)
    save(root/"preflight-reference.json",provenance)
    save(root/"full-source-sha256.json",full_source_hashes())
    status={"passed":False,"full_executed":False,"experiment":"native-pcap-validation",
            "mode":"full","design":design("full"),"conditions":{},"preflight_root":str(preflight_root.resolve()),
            "capture_overhead":"NOT EVALUATED","interpretation":"instrumentation validation, no equality or correction factors"}
    path=root/"full-status.json";save(path,status)
    try:
        for condition in CONDITIONS:
            full_gate.unchanged(provenance);check_full_sources(root)
            print(f"full {condition}: 5 warmups + 30 measured attempts",flush=True)
            status["full_executed"]=True;save(path,status)
            execute_condition_full(root,condition,preflight_root)
            status["conditions"][condition]=load(root/f"full-{condition}-status.json")
            save(path,status)
        full_gate.unchanged(provenance);check_full_sources(root)
        pairs=[]
        for condition in CONDITIONS:
            directory=root/f"full-{condition}"/f"native-pcap-{condition}-full"
            pairs.extend(json.loads(line) for line in (directory/"paired-observations.jsonl").read_text().splitlines())

        with (root/"paired-observations.jsonl").open("x") as handle:
            for row in pairs:
                handle.write(json.dumps(row) + "\n")

        summary_csv, summary_json = summary_outputs.generate_validation_summary(root)

        status["summary_outputs"] = {
            "validation_summary_csv": str(summary_csv.relative_to(root)),
            "validation_summary_csv_sha256": summary_outputs.sha256(summary_csv),
            "validation_summary_json": str(summary_json.relative_to(root)),
            "validation_summary_json_sha256": summary_outputs.sha256(summary_json),
        }
        status["passed"] = True
    except BaseException as error:
        status["passed"] = False
        status["error"]=repr(error)
        for condition in CONDITIONS:
            result=root/f"full-{condition}-status.json"
            if result.exists():status["conditions"][condition]=load(result)
        raise
    finally:save(path,status)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=Path,
        help="Native/PCAP validation root under artifacts/results; required for execution modes",
    )
    parser.add_argument("--preflight-root",type=Path,help="Immutable approved gate root; full outputs go to a new --root")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dry-run", action="store_true")
    group.add_argument("--preflight", action="store_true")
    group.add_argument("--full", action="store_true")
    group.add_argument("--preflight-local", action="store_true")
    args = parser.parse_args()

    mode = "full" if args.full else "preflight"

    if args.dry_run:
        print(json.dumps(design(mode), indent=2))
        return

    if args.root is None:
        raise SystemExit("--root is required for execution")

    if args.preflight_local:
        execute_local_preflight(args.root)
        return

    if args.preflight:
        execute_preflight(args.root)
        return

    if args.full:
        execute_full(args.root,args.preflight_root)
        return


if __name__ == "__main__":
    main()
