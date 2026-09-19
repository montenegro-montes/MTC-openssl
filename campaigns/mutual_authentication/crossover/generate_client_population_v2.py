#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

from config import ARTIFACT_ROOT, PROFILES, CHAIN_PROFILES

OPENSSL = "/opt/openssl-mtc/bin/openssl"
IMAGE = "mt-tls-mtc:local"
LD_LIBRARY_PATH = "/opt/openssl-mtc/lib:/opt/openssl/lib:/opt/oqs/lib"


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


def sha256(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def keygen(out: Path, filename: str, curve: str):
    docker_openssl(
        out,
        "genpkey",
        "-algorithm", "EC",
        "-pkeyopt", f"ec_paramgen_curve:{curve}",
        "-out", f"/work/{filename}",
    )


def client_ext(stem: str):
    return f"""basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:mtc-{stem}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"""


def build_direct(out: Path, profile: dict, count: int, days: int):
    digest = f"-{profile['digest']}"

    for i in range(count):
        stem = f"client-{i:04d}"

        keygen(out, f"{stem}.key", profile["pkey_curve"])

        cnf = out / f"{stem}.cnf"
        cnf.write_text(
            f"""[req]
distinguished_name = dn
x509_extensions = v3_client
prompt = no

[dn]
CN = {stem}

[v3_client]
{client_ext(stem)}
"""
        )

        docker_openssl(
            out,
            "req",
            "-new",
            "-x509",
            "-key", f"/work/{stem}.key",
            "-out", f"/work/{stem}.pem",
            "-days", str(days),
            "-set_serial", str(i + 1),
            "-config", f"/work/{stem}.cnf",
            "-extensions", "v3_client",
            digest,
        )

    return out / "client-0000.pem"


def build_ca(out: Path, profile_name: str, profile: dict, count: int, days: int):
    digest = f"-{profile['digest']}"

    ca_cnf = out / "ca.cnf"
    ca_cnf.write_text(
        f"""[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = MTC Mutual Auth Crossover Client CA {profile_name}

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""
    )

    keygen(out, "ca.key", profile["pkey_curve"])

    docker_openssl(
        out,
        "req",
        "-new",
        "-x509",
        "-key", "/work/ca.key",
        "-out", "/work/ca.pem",
        "-days", str(days),
        "-set_serial", "1",
        "-config", "/work/ca.cnf",
        "-extensions", "v3_ca",
        digest,
    )

    for i in range(count):
        stem = f"client-{i:04d}"

        keygen(out, f"{stem}.key", profile["pkey_curve"])

        docker_openssl(
            out,
            "req",
            "-new",
            "-key", f"/work/{stem}.key",
            "-out", f"/work/{stem}.csr",
            "-subj", f"/CN={stem}",
            digest,
        )

        ext = out / f"{stem}.cnf"
        ext.write_text(client_ext(stem))

        docker_openssl(
            out,
            "x509",
            "-req",
            "-in", f"/work/{stem}.csr",
            "-CA", "/work/ca.pem",
            "-CAkey", "/work/ca.key",
            "-set_serial", str(i + 2),
            "-out", f"/work/{stem}.pem",
            "-days", str(days),
            digest,
            "-extfile", f"/work/{stem}.cnf",
        )

    return out / "ca.pem"


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--profile",
        choices=PROFILES,
        required=True,
    )

    parser.add_argument(
        "--chain-profile",
        choices=CHAIN_PROFILES,
        required=True,
    )

    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--output", type=Path)

    args = parser.parse_args()

    if not 1 <= args.count <= 1024:
        raise SystemExit("--count must be between 1 and 1024")

    if args.days < 1:
        raise SystemExit("--days must be positive")

    profile = PROFILES[args.profile]

    out = (
        args.output.resolve()
        if args.output
        else (
            ARTIFACT_ROOT
            / "client-x509"
            / args.profile
            / args.chain_profile
        )
    )

    if out.exists():
        raise SystemExit(
            f"Refusing to overwrite existing output: {out}"
        )

    os.umask(0o077)
    out.mkdir(parents=True)

    if args.chain_profile == "direct-server":
        trust_anchor = build_direct(
            out, profile, args.count, args.days
        )
    else:
        trust_anchor = build_ca(
            out,
            args.profile,
            profile,
            args.count,
            args.days,
        )

    baseline_cert = out / "client-0000.pem"
    baseline_key = out / "client-0000.key"

    manifest = {
        "experiment": "mutual-auth-crossover-v2",
        "role": "client",
        "profile": args.profile,
        "chain_profile": args.chain_profile,
        "count": args.count,
        "days": args.days,
        "curve": profile["pkey_curve"],
        "digest": profile["digest"],
        "baseline_certificate": str(baseline_cert),
        "baseline_private_key": str(baseline_key),
        "trust_anchor": str(trust_anchor),
        "baseline_certificate_sha256": sha256(baseline_cert),
        "trust_anchor_sha256": sha256(trust_anchor),
        "mtc_source_population": (
            args.chain_profile == "ca-server"
        ),
    }

    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n"
    )

    print()
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
