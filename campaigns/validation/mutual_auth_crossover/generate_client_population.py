#!/usr/bin/env python3

import argparse
import subprocess
from pathlib import Path


OPENSSL = "/opt/openssl-mtc/bin/openssl"
IMAGE = "mt-tls-mtc:local"
LD_LIBRARY_PATH = "/opt/openssl-mtc/lib:/opt/openssl/lib:/opt/oqs/lib"


def run(cmd):
    print("+", " ".join(str(x) for x in cmd))
    subprocess.run(cmd, check=True)


def docker_openssl(root: Path, *args):
    cmd = [
        "docker", "run", "--rm",
        "-e", f"LD_LIBRARY_PATH={LD_LIBRARY_PATH}",
        "-v", f"{root.resolve()}:/work",
        "--entrypoint", OPENSSL,
        IMAGE,
        *args,
    ]
    run(cmd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=128)
    args = parser.parse_args()

    out = args.output.resolve()

    if out.exists():
        raise SystemExit(f"Refusing to overwrite existing output: {out}")

    if args.count < 1 or args.count > 1024:
        raise SystemExit("--count must be between 1 and 1024")

    out.mkdir(parents=True)

    ca_cnf = """[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = MTC Mutual Auth Crossover Client CA P-521

[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""

    (out / "ca.cnf").write_text(ca_cnf)

    # P-521 CA
    docker_openssl(
        out,
        "ecparam",
        "-name", "secp521r1",
        "-genkey",
        "-noout",
        "-out", "/work/ca.key",
    )

    docker_openssl(
        out,
        "req",
        "-new",
        "-x509",
        "-key", "/work/ca.key",
        "-out", "/work/ca.pem",
        "-days", "3650",
        "-config", "/work/ca.cnf",
        "-extensions", "v3_ca",
        "-sha512",
    )

    for i in range(args.count):
        stem = f"client-{i:04d}"

        ext = f"""basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:mtc-{stem}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
"""

        (out / f"{stem}.cnf").write_text(ext)

        docker_openssl(
            out,
            "ecparam",
            "-name", "secp521r1",
            "-genkey",
            "-noout",
            "-out", f"/work/{stem}.key",
        )

        docker_openssl(
            out,
            "req",
            "-new",
            "-key", f"/work/{stem}.key",
            "-out", f"/work/{stem}.csr",
            "-subj", f"/CN={stem}",
            "-sha512",
        )

        docker_openssl(
            out,
            "x509",
            "-req",
            "-in", f"/work/{stem}.csr",
            "-CA", "/work/ca.pem",
            "-CAkey", "/work/ca.key",
            "-CAcreateserial",
            "-out", f"/work/{stem}.pem",
            "-days", "3650",
            "-sha512",
            "-extfile", f"/work/{stem}.cnf",
        )

    print()
    print("Generated client population:")
    print(out)
    print("count =", args.count)
    print("profile = ecdsa-p521")
    print("purpose = clientAuth")


if __name__ == "__main__":
    main()
