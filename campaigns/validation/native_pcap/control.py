"""Initialize and regression-gate Native/PCAP validation Native <-> PCAP validation."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "campaigns"))

from common.image_chain import derived_from, ensure

VALIDATION_FIXTURE = Path(
    "artifacts/cert-chain-scaling/fixtures-20260914T113933Z/"
    "mldsa65/depth-2"
)

REQUIRED_FIXTURE_FILES = [
    "root.pem",
    "server.pem",
    "server.key",
    "manifest.json",
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def load(path):
    return json.loads(path.read_text())


def verify(root):
    for name in ["baseline-source-sha256.json", "fixture-sha256.json"]:
        for path, digest in load(root / name).items():
            target = REPO / path
            if not target.is_file() or sha(target) != digest:
                raise RuntimeError("preservation mismatch: " + path)


def init(root):
    if root.exists():
        raise SystemExit("refusing overwrite")

    root.mkdir(parents=True)

    tracked = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=REPO
    ).decode().split("\0")

    save(
        root / "baseline-source-sha256.json",
        {
            path: sha(REPO / path)
            for path in tracked
            if path and (REPO / path).is_file()
        },
    )

    fixture_root = REPO / VALIDATION_FIXTURE

    if not fixture_root.is_dir():
        raise RuntimeError(
            "Native/PCAP validation fixture directory missing: "
            + str(VALIDATION_FIXTURE)
        )

    missing = [
        name
        for name in REQUIRED_FIXTURE_FILES
        if not (fixture_root / name).is_file()
    ]
    if missing:
        raise RuntimeError(
            "Native/PCAP validation fixture incomplete; missing: "
            + ", ".join(missing)
        )

    fixtures = sorted(
        path
        for path in fixture_root.rglob("*")
        if path.is_file()
    )

    if not fixtures:
        raise RuntimeError("Native/PCAP validation fixture set is empty")

    save(
        root / "fixture-sha256.json",
        {
            str(path.relative_to(REPO)): sha(path)
            for path in fixtures
        },
    )

    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=REPO, text=True
    ).strip()

    status = subprocess.check_output(
        ["git", "status", "--short"], cwd=REPO, text=True
    )

    save(
        root / "metadata.json",
        {
            "experiment": "native-pcap-validation",
            "purpose": "instrumentation validation; not authentication performance",
            "preparation_commit": commit,
            "git_commit_before": commit,
            "git_status_before": status,
            "scenario": "pq",
            "tree_size": 16,
            "TLS": "1.3",
            "group": "X25519",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "server_authentication_only": True,
            "tickets": False,
            "resumption": False,
            "conditions": {
                "local": {
                    "additional_rtt_ms": 0,
                    "bandwidth_mbit": None,
                    "loss_percent": 0,
                },
                "latency-100": {
                    "additional_rtt_ms": 100,
                    "bandwidth_mbit": None,
                    "loss_percent": 0,
                },
                "constrained": {
                    "additional_rtt_ms": 100,
                    "bandwidth_mbit": 5,
                    "loss_percent": 1,
                },
            },
            "difference_sign": "native_minus_pcap",
            "pcap_population_separate_from_uncaptured": True,
            "status": "initialized",
        },
    )


def tests(root):
    verify(root)

    save(
        root / "tests-status.json",
        {
            "passed": False,
            "state": "resolving images",
        },
    )

    resolved = ensure("network")
    network = resolved["target"]
    measurement = resolved["images"]["measurement"]

    capture_result = subprocess.run(
        ["docker", "image", "inspect", "mt-tls-capture:local"],
        text=True,
        capture_output=True,
    )

    if capture_result.returncode != 0:
        raise RuntimeError(
            "mt-tls-capture:local is missing; "
            "Native/PCAP validation requires the validated capture image"
        )

    capture_info = json.loads(capture_result.stdout)[0]

    if not derived_from(capture_info, measurement):
        raise RuntimeError(
            "mt-tls-capture:local does not derive from the current "
            "mt-tls-measurement:local image; rebuild the capture image "
            "before Native/PCAP validation"
        )

    required = ["tc", "ping", "nstat", "iperf3"]

    for tool in required:
        subprocess.run(
            [
                "docker", "run", "--rm", "--network", "none",
                network["Id"],
                "sh", "-c", 'command -v "$1"', "sh", tool,
            ],
            check=True,
            capture_output=True,
        )

    regressions = [
        (
            "native_timing",
            [sys.executable, str(REPO / "src/profiling/test_native_timing.py")],
        ),
        (
            "shared_pcap_capture",
            [sys.executable, str(REPO / "campaigns/common/test_pcap_capture.py")],
        ),
        (
            "pcap_analyzer",
            [
                sys.executable,
                str(
                    REPO
                    / "campaigns/historical_campaigns/handshake_capture/test_analyze.py"
                ),
            ],
        ),
        (
            "latency_pcap_adapter",
            [
                sys.executable,
                str(
                    REPO
                    / "campaigns/historical_campaigns/network_latency/test_pcap_adapter.py"
                ),
            ],
        ),
        (
            "profile_timer_runtime",
            [
                "docker", "run", "--rm", "--network", "none",
                network["Id"],
                "sh", "/opt/profiling/test_timer.sh",
            ],
        ),
    ]

    regression_results = []

    with (root / "tests.log").open("w") as log:
        for name, command in regressions:
            log.write(f"=== {name} ===\\n")
            log.flush()

            result = subprocess.run(
                command,
                cwd=REPO,
                stdout=log,
                stderr=subprocess.STDOUT,
            )

            regression_results.append(
                {
                    "name": name,
                    "passed": result.returncode == 0,
                    "exit_code": result.returncode,
                }
            )

            if result.returncode:
                save(
                    root / "tests-status.json",
                    {
                        "passed": False,
                        "failed_regression": name,
                        "exit_code": result.returncode,
                        "network_image_id": network["Id"],
                        "measurement_image_id": measurement["Id"],
                        "capture_image_id": capture_info["Id"],
                        "regressions": regression_results,
                        "excluded_historical_tests": [
                            "/opt/measurement/tests.sh",
                            "/opt/profiling/test_tls.py",
                        ],
                        "exclusion_reason": (
                            "Historical multi-scenario tests require fixture "
                            "paths not used by the Native/PCAP validation pq-only validation."
                        ),
                    },
                )
                raise SystemExit(
                    f"Native/PCAP validation regression failure: {name}"
                )

    verify(root)

    save(
        root / "images.json",
        {
            "network_image": network,
            "measurement_image": measurement,
            "capture_image": {
                "Id": capture_info["Id"],
                "RepoTags": capture_info.get("RepoTags", []),
            },
            "automatic_rebuilds": resolved["rebuilt"],
        },
    )

    save(
        root / "tests-status.json",
        {
            "passed": True,
            "exit_code": 0,
            "network_image_id": network["Id"],
            "measurement_image_id": measurement["Id"],
            "capture_image_id": capture_info["Id"],
            "required_tools": required,
            "base_layers_verified": True,
            "capture_derives_from_measurement": True,
            "regressions": regression_results,
            "excluded_historical_tests": [
                "/opt/measurement/tests.sh",
                "/opt/profiling/test_tls.py",
            ],
            "exclusion_reason": (
                "Historical multi-scenario tests require fixture "
                "paths not used by the Native/PCAP validation pq-only validation."
            ),
        },
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=["init", "tests"])
    parser.add_argument("root", type=Path)
    args = parser.parse_args()

    root = args.root.resolve()

    if not root.is_relative_to(REPO / "artifacts/results"):
        raise SystemExit("root must be under artifacts/results")

    if args.stage == "init":
        init(root)
    else:
        if not root.is_dir():
            raise SystemExit("experiment root does not exist")
        tests(root)

    print(args.stage, "PASS", root)


if __name__ == "__main__":
    main()
