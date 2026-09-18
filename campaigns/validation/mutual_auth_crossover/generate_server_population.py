#!/usr/bin/env python3

import argparse
import shutil
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parents[3]

FIXTURE = (
    REPO
    / "artifacts"
    / "validation"
    / "chain-depth-server-only-fixtures-full-20260918T101613Z"
    / "ecdsa-p521"
    / "ca-server"
)

DEFAULT_OUTPUT = (
    REPO
    / "artifacts"
    / "validation"
    / "mutual-auth-crossover"
    / "server-source"
    / "ecdsa-p521-ca-server"
)

OPENSSL = "/opt/openssl-mtc/bin/openssl"


def run(*args):
    cmd = [OPENSSL, *map(str, args)]
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
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--count", type=int, default=128)
    args = parser.parse_args()

    if args.count != 128:
        raise SystemExit("Controlled population must contain exactly 128 servers")

    out = args.output.resolve()

    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"Refusing to overwrite non-empty directory: {out}")

    out.mkdir(parents=True, exist_ok=True)

    # Preserve the original CA exactly.
    shutil.copyfile(FIXTURE / "root.pem", out / "root.pem")
    shutil.copyfile(FIXTURE / "root.key", out / "root.key")

    # Leaf 0 must be byte-for-byte identical to the X.509 baseline.
    shutil.copyfile(FIXTURE / "server.pem", out / "server-0000.pem")
    shutil.copyfile(FIXTURE / "server.key", out / "server-0000.key")

    for i in range(1, args.count):
        prefix = f"server-{i:04d}"

        key = out / f"{prefix}.key"
        csr = out / f"{prefix}.csr"
        cert = out / f"{prefix}.pem"
        ext = out / f"{prefix}.cnf"

        write_server_ext(ext)

        run(
            "genpkey",
            "-algorithm", "EC",
            "-pkeyopt", "ec_paramgen_curve:P-521",
            "-out", key,
        )

        run(
            "req",
            "-new",
            "-sha512",
            "-key", key,
            "-out", csr,
            "-subj", "/CN=server",
        )

        run(
            "x509",
            "-req",
            "-sha512",
            "-days", "3650",
            "-in", csr,
            "-CA", out / "root.pem",
            "-CAkey", out / "root.key",
            "-CAcreateserial",
            "-out", cert,
            "-extfile", ext,
        )

    print()
    print("Generated server population:")
    print(out)
    print("count = 128")
    print("profile = ecdsa-p521")
    print("chain profile = ca-server")


if __name__ == "__main__":
    main()