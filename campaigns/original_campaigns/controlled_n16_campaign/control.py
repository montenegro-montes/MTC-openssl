#!/usr/bin/env python3
"""Initialize and test a controlled N=16 campaign without historical templates."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import platform
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]
IMAGE = "mt-tls-measurement:local"
SCENARIOS = [
    "classic", "pq", "classic-mt", "pq-mt",
    "classic-compact-warm", "classic-compact-cold",
    "pq-compact-warm", "pq-compact-cold",
    "classic-mtc-experimental-standalone", "classic-mtc-experimental-landmark",
    "pq-mtc-experimental-standalone", "pq-mtc-experimental-landmark",
    "classic-rpk", "pq-rpk",
]
SOURCE_PREFIXES = (
    "campaigns/original_campaigns/controlled_n16_campaign/", "src/compact/", "src/integration/", "src/mtc/",
    "src/profiling/", "codigoOriginal/C/", "scripts/", "bin/",
)
SOURCE_FILES = {
    ".dockerignore", ".gitignore", "docker/original_campaigns/Dockerfile",
    "docker/original_campaigns/Dockerfile.compact", "docker/original_campaigns/Dockerfile.compact.dockerignore",
    "docker/original_campaigns/Dockerfile.profile", "docker/original_campaigns/Dockerfile.profile.dockerignore",
    "docker/original_campaigns/Dockerfile.mtc", "docker/original_campaigns/Dockerfile.mtc.dockerignore",
    "docker/original_campaigns/Dockerfile.measurement", "docker/original_campaigns/Dockerfile.measurement.dockerignore",
    "docker/original_campaigns/compose.measurement.yaml", "docker/original_campaigns/openssl.cnf",
}
FIXTURE_DIRS = (
    "artifacts/certs", "artifacts/merkle", "artifacts/compact/batch16",
    "artifacts/mtc/batch16-v2",
)


def save(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def relative_hashes(paths: list[Path]) -> dict[str, str]:
    return {str(path.relative_to(REPO)): sha256(path) for path in sorted(paths)}


def source_paths() -> list[Path]:
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=REPO, text=True,
    ).splitlines()
    selected = []
    for name in names:
        if name in SOURCE_FILES or name.startswith(SOURCE_PREFIXES):
            path = REPO / name
            if path.is_file():
                selected.append(path)
    if not selected:
        raise RuntimeError("No controlled N=16 source files found")
    return selected


def fixture_paths() -> list[Path]:
    missing = [name for name in FIXTURE_DIRS if not (REPO / name).is_dir()]
    if missing:
        raise RuntimeError("Missing N=16 fixture directories: " + ", ".join(missing))
    paths = []
    for name in FIXTURE_DIRS:
        paths.extend(path for path in (REPO / name).rglob("*") if path.is_file())
    if not paths:
        raise RuntimeError("No N=16 fixtures found")
    return paths


def image() -> dict:
    return json.loads(subprocess.check_output(
        ["docker", "image", "inspect", IMAGE], text=True
    ))[0]


def ensure_root(root: Path, allow_initialized: bool = False) -> Path:
    root = root.resolve()
    results = (REPO / "artifacts/results").resolve()
    if not root.is_relative_to(results):
        raise ValueError("root must be under artifacts/results")
    if allow_initialized:
        if not (root / "metadata.json").is_file():
            raise ValueError("campaign is not initialized")
    return root


def init(root: Path) -> None:
    root = ensure_root(root)
    if root.exists():
        contents = list(root.iterdir())
        initialized = all((root / name).is_file() for name in (
            "metadata.json", "baseline-source-sha256.json", "fixture-sha256.json",
            "measurement-image.json", "environment-before.json",
        ))
        if contents and initialized and not (root / "tests-status.json").exists():
            print("init ALREADY PASS", root)
            return
        if contents:
            raise FileExistsError("Output exists and is not empty; choose a new directory")
    else:
        root.mkdir(parents=True)
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    status = subprocess.check_output(["git", "status", "--short"], cwd=REPO, text=True).rstrip()
    current_image = image()
    sources = relative_hashes(source_paths())
    fixtures = relative_hashes(fixture_paths())
    baseline = {"root": str(root.relative_to(REPO)), "git_commit": commit,
                "git_status_before": status, "created_utc": now}
    metadata = {
        "experiment": "controlled-n16", "created_utc": now,
        "git_commit_before": commit, "git_status_before": status,
        "draft": "draft-ietf-plants-merkle-tree-certs-05",
        "status": "initialized", "campaigns": 10, "seeds": list(range(42, 52)),
        "tree_size": 16, "scenarios": SCENARIOS,
        "measured_handshakes_expected": 4200, "warmup_handshakes_expected": 700,
        "measurement_preflight": {"measured": 28, "warmup": 14,
                                  "excluded_from_campaign_analysis": True},
        "measurement_image_id": current_image["Id"],
        "source_files": len(sources), "fixture_files": len(fixtures),
    }
    environment = {
        "created_utc": now, "host_architecture": platform.machine(),
        "python": platform.python_version(),
        "docker": json.loads(subprocess.check_output(
            ["docker", "info", "--format", "{{json .}}"], text=True)),
    }
    save(root / "baseline.json", baseline)
    save(root / "metadata.json", metadata)
    save(root / "baseline-source-sha256.json", sources)
    save(root / "fixture-sha256.json", fixtures)
    save(root / "measurement-image.json", current_image)
    save(root / "environment-before.json", environment)
    print("init PASS", root)


def tests(root: Path) -> None:
    root = ensure_root(root, allow_initialized=True)
    status_path = root / "tests-status.json"
    if status_path.exists():
        raise FileExistsError("tests-status.json exists; choose a new campaign directory")
    current_image = image()
    log_path = root / "tests.log"
    with log_path.open("w") as log:
        result = subprocess.run([
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{REPO / 'artifacts'}:/work:ro", IMAGE,
            "sh", "/opt/measurement/tests.sh",
        ], stdout=log, stderr=subprocess.STDOUT)
    record = {"passed": result.returncode == 0, "exit_code": result.returncode,
              "image_id": current_image["Id"], "log": "tests.log"}
    save(status_path, record)
    metadata = json.loads((root / "metadata.json").read_text())
    metadata["tests"] = record
    metadata["status"] = "tests-passed" if record["passed"] else "tests-failed"
    save(root / "metadata.json", metadata)
    if not record["passed"]:
        raise RuntimeError(f"controlled N=16 tests failed; inspect {log_path}")
    print("tests PASS", root)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("init", "tests"))
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    if args.action == "init":
        init(args.root)
    else:
        tests(args.root)


if __name__ == "__main__":
    main()
