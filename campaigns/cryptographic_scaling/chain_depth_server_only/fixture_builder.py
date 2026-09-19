#!/usr/bin/env python3
"""Build one immutable server-only X.509 fixture for a semantic chain profile.

This builder is independent from mutual-auth and retry validation.
It supports:
- direct-server
- ca-server
- root-intermediate-server
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

from config import CHAIN_PROFILES, PROFILES

OPENSSL = "/opt/openssl/bin/openssl"


def run(*args):
    return subprocess.run(
        [OPENSSL, *map(str, args)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def run_bytes(*args, input=None):
    return subprocess.run(
        [OPENSSL, *map(str, args)],
        input=input,
        check=True,
        capture_output=True,
    ).stdout


def hash_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def key(profile, output):
    args = ["genpkey", "-algorithm", profile["algorithm"]]
    if profile.get("curve"):
        args += ["-pkeyopt", "ec_paramgen_curve:" + profile["curve"]]
    run(*args, "-out", output)


def sign_args(profile):
    return ["-" + profile["digest"]] if profile.get("digest") else []


def cert_checks(output, named_certs):
    checks = {}
    for name, path in named_certs:
        text = run("x509", "-in", path, "-noout", "-text")
        algorithms = re.findall(r"Signature Algorithm:\s*([^\n]+)", text)
        cert_spki = run_bytes(
            "pkey",
            "-pubin",
            "-outform",
            "DER",
            input=run_bytes("x509", "-in", path, "-pubkey", "-noout"),
        )
        checks[name] = {
            "signature_algorithms": algorithms,
            "spki_sha256": hashlib.sha256(cert_spki).hexdigest(),
            "key_matches_certificate": cert_spki
            == (output / f"{name}-spki.der").read_bytes(),
        }
    return checks


def build_direct_server(output, profile, days):
    server_key = output / "server.key"
    server = output / "server.pem"

    key(profile, server_key)
    run(
        "req",
        "-new",
        "-x509",
        "-key",
        server_key,
        "-out",
        server,
        "-days",
        days,
        "-set_serial",
        "1",
        "-subj",
        "/CN=server",
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-addext",
        "keyUsage=critical,digitalSignature",
        "-addext",
        "extendedKeyUsage=serverAuth",
        "-addext",
        "subjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1",
        *sign_args(profile),
    )

    root = output / "root.pem"
    root.write_bytes(server.read_bytes())

    (output / "intermediates.pem").write_bytes(b"")
    (output / "server-chain.pem").write_bytes(server.read_bytes())

    return [("server", server)], [("server", server_key)], root, server, []


def build_ca_server(output, profile, days):
    root_key = output / "root.key"
    root = output / "root.pem"
    server_key = output / "server.key"
    server_csr = output / "server.csr"
    server = output / "server.pem"
    server_ext = output / "server.cnf"

    key(profile, root_key)
    run(
        "req",
        "-new",
        "-x509",
        "-key",
        root_key,
        "-out",
        root,
        "-days",
        days,
        "-set_serial",
        "1",
        "-subj",
        "/CN=Chain Depth CA Root",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        *sign_args(profile),
    )

    key(profile, server_key)
    run("req", "-new", "-key", server_key, "-out", server_csr, "-subj", "/CN=server", *sign_args(profile))
    server_ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
    )
    run(
        "x509",
        "-req",
        "-in",
        server_csr,
        "-CA",
        root,
        "-CAkey",
        root_key,
        "-set_serial",
        "2",
        "-days",
        days,
        "-extfile",
        server_ext,
        "-out",
        server,
        *sign_args(profile),
    )

    (output / "intermediates.pem").write_bytes(b"")
    (output / "server-chain.pem").write_bytes(server.read_bytes())

    return [("root", root), ("server", server)], [("root", root_key), ("server", server_key)], root, server, []


def build_root_intermediate_server(output, profile, days):
    root_key = output / "root.key"
    root = output / "root.pem"
    inter_key = output / "intermediate-1.key"
    inter_csr = output / "intermediate-1.csr"
    inter = output / "intermediate-1.pem"
    inter_ext = output / "intermediate-1.cnf"
    server_key = output / "server.key"
    server_csr = output / "server.csr"
    server = output / "server.pem"
    server_ext = output / "server.cnf"

    key(profile, root_key)
    run(
        "req",
        "-new",
        "-x509",
        "-key",
        root_key,
        "-out",
        root,
        "-days",
        days,
        "-set_serial",
        "1",
        "-subj",
        "/CN=Chain Depth Root",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:1",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
        *sign_args(profile),
    )

    key(profile, inter_key)
    run("req", "-new", "-key", inter_key, "-out", inter_csr, "-subj", "/CN=Chain Depth Intermediate", *sign_args(profile))
    inter_ext.write_text(
        "basicConstraints=critical,CA:TRUE,pathlen:0\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
    )
    run(
        "x509",
        "-req",
        "-in",
        inter_csr,
        "-CA",
        root,
        "-CAkey",
        root_key,
        "-set_serial",
        "2",
        "-days",
        days,
        "-extfile",
        inter_ext,
        "-out",
        inter,
        *sign_args(profile),
    )

    key(profile, server_key)
    run("req", "-new", "-key", server_key, "-out", server_csr, "-subj", "/CN=server", *sign_args(profile))
    server_ext.write_text(
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectAltName=DNS:server,DNS:localhost,IP:127.0.0.1\n"
        "subjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n"
    )
    run(
        "x509",
        "-req",
        "-in",
        server_csr,
        "-CA",
        inter,
        "-CAkey",
        inter_key,
        "-set_serial",
        "3",
        "-days",
        days,
        "-extfile",
        server_ext,
        "-out",
        server,
        *sign_args(profile),
    )

    (output / "intermediates.pem").write_bytes(inter.read_bytes())
    (output / "server-chain.pem").write_bytes(server.read_bytes() + inter.read_bytes())

    return (
        [("root", root), ("intermediate-1", inter), ("server", server)],
        [("root", root_key), ("intermediate-1", inter_key), ("server", server_key)],
        root,
        server,
        [inter],
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile", choices=PROFILES, required=True)
    parser.add_argument("--chain-profile", choices=CHAIN_PROFILES, required=True)
    parser.add_argument("--days", type=int, default=30)
    args = parser.parse_args()

    if args.output.exists():
        parser.error("Output exists; fixture directories are immutable")
    if args.days < 1:
        parser.error("--days must be positive")

    os.umask(0o077)
    args.output.mkdir(parents=True)

    profile = PROFILES[args.profile]
    chain = CHAIN_PROFILES[args.chain_profile]

    if args.chain_profile == "direct-server":
        named_certs, named_keys, root, server, intermediates = build_direct_server(args.output, profile, args.days)
    elif args.chain_profile == "ca-server":
        named_certs, named_keys, root, server, intermediates = build_ca_server(args.output, profile, args.days)
    elif args.chain_profile == "root-intermediate-server":
        named_certs, named_keys, root, server, intermediates = build_root_intermediate_server(args.output, profile, args.days)
    else:
        raise AssertionError(args.chain_profile)

    for name, path in named_certs:
        run("x509", "-in", path, "-outform", "DER", "-out", args.output / f"{name}.der")

    for name, path in named_keys:
        run("pkey", "-in", path, "-outform", "DER", "-out", args.output / f"{name}-private.der")
        run("pkey", "-in", path, "-pubout", "-outform", "DER", "-out", args.output / f"{name}-spki.der")

    verify_args = ["verify", "-CAfile", root, "-verify_hostname", "server"]
    if intermediates:
        verify_args += ["-untrusted", args.output / "intermediates.pem"]
    run(*verify_args, server)

    for temporary in list(args.output.glob("*.csr")) + list(args.output.glob("*.cnf")):
        temporary.unlink()

    files = {x.name: hash_file(x) for x in sorted(args.output.iterdir()) if x.is_file()}

    meta = {
        "schema": 1,
        "experiment": "chain_depth_server_only",
        "image_id": os.environ.get("FIXTURE_IMAGE_ID"),
        "source_commit": os.environ.get("FIXTURE_SOURCE_COMMIT"),
        "generator_sha256": hash_file(Path(__file__)),
        "config_sha256": hash_file(Path(__file__).with_name("config.py")),
        "profile": args.profile,
        "security_level": profile["level"],
        "family": profile["family"],
        "requested_algorithm": profile["algorithm"],
        "curve": profile.get("curve"),
        "digest": profile.get("digest"),
        "chain_profile": args.chain_profile,
        "depth_including_root": chain["depth_including_root"],
        "chain_depth": chain["chain_depth"],
        "transmitted_certificates": chain["transmitted_certificates"],
        "root_transmitted": False,
        "validity_days": args.days,
        "openssl": run("version", "-a"),
        "certificate_checks": cert_checks(args.output, named_certs),
        "files_sha256": files,
    }

    (args.output / "manifest.json").write_text(json.dumps(meta, indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
