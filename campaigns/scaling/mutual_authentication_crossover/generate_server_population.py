#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from config import (
    ARTIFACT_ROOT,
    PROFILES,
    SERVER_ONLY_FIXTURES,
    MTC_SOURCE_CHAIN_PROFILE,
)

OPENSSL = "/opt/openssl-mtc/bin/openssl"
IMAGE = "mt-tls-mtc:local"
LD_LIBRARY_PATH = "/opt/openssl-mtc/lib:/opt/openssl/lib:/opt/oqs/lib"


def sha256(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def docker_openssl(root: Path, *args):
    cmd = [
        "docker", "run", "--rm",
        "-e", f"LD_LIBRARY_PATH={LD_LIBRARY_PATH}",
        "-v", f"{root.resolve()}:/work",
        "--entrypoint", OPENSSL,
        IMAGE,
        *map(str, args),
    ]
    print("+", " ".join(cmd))
    subprocess.run(cmd, check=True)


def write_server_ext(path: Path):
    path.write_text(
        """basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"""
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--profile",
        choices=PROFILES,
        required=True,
    )

    parser.add_argument("--count", type=int, default=1024)
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--output", type=Path)

    args = parser.parse_args()

    if args.count != 1024:
        raise SystemExit(
            "Controlled mutual-auth MTC population must contain exactly 1024 servers"
        )

    if args.days < 1:
        raise SystemExit("--days must be positive")

    profile = PROFILES[args.profile]

    fixture = (
        SERVER_ONLY_FIXTURES
        / args.profile
        / MTC_SOURCE_CHAIN_PROFILE
    )

    required = [
        fixture / "root.pem",
        fixture / "root.key",
        fixture / "server.pem",
        fixture / "server.key",
    ]

    missing = [p for p in required if not p.is_file()]
    if missing:
        raise SystemExit(f"Missing server-only fixture: {missing[0]}")

    out = (
        args.output.resolve()
        if args.output
        else ARTIFACT_ROOT / "server-mtc-source" / args.profile
    )

    if out.exists():
        raise SystemExit(
            f"Refusing to overwrite existing output: {out}"
        )

    os.umask(0o077)
    out.mkdir(parents=True)

    # Preserve the X.509 ca-server authority exactly.
    shutil.copyfile(fixture / "root.pem", out / "root.pem")
    shutil.copyfile(fixture / "root.key", out / "root.key")

    # Leaf 0 must be byte-for-byte identical to the server-only
    # ca-server baseline.
    shutil.copyfile(
        fixture / "server.pem",
        out / "server-0000.pem",
    )
    shutil.copyfile(
        fixture / "server.key",
        out / "server-0000.key",
    )

    for i in range(1, args.count):
        stem = f"server-{i:04d}"

        key_args = ["genpkey", "-algorithm", profile["algorithm"]]
        if profile.get("pkey_curve"):
            key_args += ["-pkeyopt", f"ec_paramgen_curve:{profile['pkey_curve']}"]
        docker_openssl(out, *key_args, "-out", f"/work/{stem}.key")

        docker_openssl(
            out,
            "req",
            "-new",
            "-key", f"/work/{stem}.key",
            "-out", f"/work/{stem}.csr",
            "-subj", "/CN=server",
            *([f"-{profile['digest']}"] if profile.get("digest") else []),
        )

        ext = out / f"{stem}.cnf"
        write_server_ext(ext)

        docker_openssl(
            out,
            "x509",
            "-req",
            "-in", f"/work/{stem}.csr",
            "-CA", "/work/root.pem",
            "-CAkey", "/work/root.key",
            "-set_serial", str(i + 2),
            "-out", f"/work/{stem}.pem",
            "-days", str(args.days),
            *([f"-{profile['digest']}"] if profile.get("digest") else []),
            "-extfile", f"/work/{stem}.cnf",
        )

    baseline_equal = (
        (out / "server-0000.pem").read_bytes()
        == (fixture / "server.pem").read_bytes()
        and
        (out / "server-0000.key").read_bytes()
        == (fixture / "server.key").read_bytes()
    )

    if not baseline_equal:
        raise SystemExit(
            "server-0000 is not byte-for-byte identical to server-only baseline"
        )

    manifest = {
        "experiment": "mutual-auth-crossover",
        "role": "server",
        "profile": args.profile,
        "source_chain_profile": MTC_SOURCE_CHAIN_PROFILE,
        "count": args.count,
        "days": args.days,
        "algorithm": profile["algorithm"],
        "curve": profile["pkey_curve"],
        "digest": profile["digest"],
        "source_fixture": str(fixture),
        "baseline_certificate": str(out / "server-0000.pem"),
        "baseline_private_key": str(out / "server-0000.key"),
        "root_certificate": str(out / "root.pem"),
        "baseline_certificate_sha256":
            sha256(out / "server-0000.pem"),
        "source_baseline_certificate_sha256":
            sha256(fixture / "server.pem"),
        "root_certificate_sha256":
            sha256(out / "root.pem"),
        "source_root_certificate_sha256":
            sha256(fixture / "root.pem"),
        "baseline_byte_identical": baseline_equal,
    }

    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n"
    )

    print()
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
