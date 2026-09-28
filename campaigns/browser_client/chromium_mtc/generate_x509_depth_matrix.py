#!/usr/bin/env python3
"""Generate controlled X.509 depth families for the Chromium MTC comparison."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import sys
import tempfile
import uuid

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import browser_validation as bv


DEPTHS = (2, 3, 4, 5)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def openssl_script(commands):
    return (
        "set -eu\n"
        "umask 077\n"
        + "\n".join(
            shlex.join(["/opt/mtc/openssl.sh", *command])
            for command in commands
        )
        + "\n"
    )


def run_generation(scratch, commands, image):
    bv.command(
        [
            "docker", "run", "--rm", "--pull", "never",
            "--network", "none",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "-e", "LC_ALL=C",
            "-v", str(scratch.resolve()) + ":/work",
            "-w", "/work",
            "--entrypoint", "/bin/sh",
            image,
            "-c", openssl_script(commands),
        ],
        timeout=1800,
    )


def ca_config(pathlen):
    return (
        "[req]\n"
        "distinguished_name=dn\n"
        "[dn]\n"
        "[cert]\n"
        "basicConstraints=critical,CA:TRUE,pathlen:" + str(pathlen) + "\n"
        "keyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=none\n"
        "authorityKeyIdentifier=none\n"
    )


def server_config():
    return (
        "[req]\n"
        "distinguished_name=dn\n"
        "[dn]\n"
        "[cert]\n"
        "basicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\n"
        f"subjectAltName=DNS:{bv.HOST}\n"
        "extendedKeyUsage=serverAuth\n"
        "subjectKeyIdentifier=none\n"
        "authorityKeyIdentifier=none\n"
    )


def serial():
    return str(uuid.uuid4().int)


def generate_family(output, fixture_set, profile, image):
    bv.require(profile in bv.PROFILES, "Unsupported profile")

    output.mkdir(parents=True, exist_ok=True)
    family = output / profile
    bv.require(not family.exists(), "Family output already exists: " + str(family))
    family.mkdir()

    key_options, digest = bv.profile_options(profile)

    with tempfile.TemporaryDirectory(prefix="x509-depth-family-") as temp:
        scratch = Path(temp)

        # One hierarchy shared by every depth:
        # root(pathlen=3) -> i1(2) -> i2(1) -> i3(0)
        cas = (
            ("root", 3),
            ("intermediate-1", 2),
            ("intermediate-2", 1),
            ("intermediate-3", 0),
        )

        for label, pathlen in cas:
            (scratch / f"{label}.cnf").write_text(ca_config(pathlen))

        (scratch / "server.cnf").write_text(server_config())

        commands = []

        # Shared root.
        commands.append([
            "genpkey", *key_options,
            "-out", "root.key",
        ])
        commands.append([
            "req", *digest,
            "-new", "-x509",
            "-key", "root.key",
            "-subj", f"/CN=Chromium MTC depth matrix {profile} root",
            "-config", "root.cnf",
            "-extensions", "cert",
            "-days", "30",
            "-set_serial", serial(),
            "-out", "root.pem",
        ])

        # Shared CA hierarchy.
        previous = "root"
        for index in range(1, 4):
            label = f"intermediate-{index}"

            commands.append([
                "genpkey", *key_options,
                "-out", f"{label}.key",
            ])
            commands.append([
                "req", *digest,
                "-new",
                "-key", f"{label}.key",
                "-subj", f"/CN=Browser intermediate {index} {profile}",
                "-config", f"{label}.cnf",
                "-out", f"{label}.csr",
            ])
            commands.append([
                "x509", *digest,
                "-req",
                "-in", f"{label}.csr",
                "-CA", f"{previous}.pem",
                "-CAkey", f"{previous}.key",
                "-set_serial", serial(),
                "-days", "30",
                "-extfile", f"{label}.cnf",
                "-extensions", "cert",
                "-out", f"{label}.pem",
            ])
            previous = label

        # Exactly one server key and CSR for D=2..5.
        commands.append([
            "genpkey", *key_options,
            "-out", "server.key",
        ])
        commands.append([
            "req", *digest,
            "-new",
            "-key", "server.key",
            "-subj", f"/CN={bv.HOST}",
            "-config", "server.cnf",
            "-out", "server.csr",
        ])

        # Four leaf certificates, each issued at the required level.
        issuers = {
            2: "root",
            3: "intermediate-1",
            4: "intermediate-2",
            5: "intermediate-3",
        }

        for depth in DEPTHS:
            issuer = issuers[depth]
            commands.append([
                "x509", *digest,
                "-req",
                "-in", "server.csr",
                "-CA", f"{issuer}.pem",
                "-CAkey", f"{issuer}.key",
                "-set_serial", serial(),
                "-days", "30",
                "-extfile", "server.cnf",
                "-extensions", "cert",
                "-out", f"server-d{depth}.pem",
            ])

        run_generation(scratch, commands, image)

        root_der_sha256 = bv.certificate_sha256(
            (scratch / "root.pem").read_bytes()
        )
        shared_server_key_sha256 = bv.sha(scratch / "server.key")

        public_pem = bv.docker_openssl(
            scratch,
            ["pkey", "-in", "server.key", "-pubout"],
            image,
        ).stdout
        public_body = "".join(
            line.strip()
            for line in public_pem.splitlines()
            if line and not line.startswith("-----")
        )
        server_spki_der = base64.b64decode(public_body, validate=True)
        server_spki_sha256 = hashlib.sha256(server_spki_der).hexdigest()

        cells = []

        for depth in DEPTHS:
            cell = family / f"d{depth}"
            cell.mkdir()

            shutil.copyfile(
                scratch / f"server-d{depth}.pem",
                cell / "server.pem",
            )
            shutil.copyfile(
                scratch / "server.key",
                cell / "server.key",
            )
            shutil.copyfile(
                scratch / "root.pem",
                cell / "root.pem",
            )

            (cell / "server.key").chmod(0o600)

            # Server sends nearest issuer first, root excluded.
            intermediate_labels = [
                f"intermediate-{index}"
                for index in range(depth - 2, 0, -1)
            ]
            if intermediate_labels:
                (cell / "intermediates.pem").write_bytes(
                    b"".join(
                        (scratch / f"{label}.pem").read_bytes()
                        for label in intermediate_labels
                    )
                )

            manifest = {
                "fixture_set": fixture_set,
                "family_id": profile,
                "profile": profile,
                "depth": depth,
                "hostname": bv.HOST,
                "shared_root": True,
                "shared_server_key": True,
                "root_der_sha256": root_der_sha256,
                "server_key_sha256": shared_server_key_sha256,
                "server_spki_sha256": server_spki_sha256,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "files_sha256": bv.hashes(cell),
            }
            write_json(cell / "manifest.json", manifest)

            validated = bv.validate_x509(
                cell,
                profile=profile,
                depth=depth,
                image=image,
                fixture_set=fixture_set,
            )

            bv.require(
                bv.certificate_sha256(
                    Path(validated["root"]).read_bytes()
                ) == root_der_sha256,
                f"D={depth}: shared root changed",
            )
            bv.require(
                validated["key_sha256"] == shared_server_key_sha256,
                f"D={depth}: shared server key changed",
            )

            cells.append({
                "depth": depth,
                "fixture": str(cell.relative_to(output)),
                "root_der_sha256": root_der_sha256,
                "server_key_sha256": shared_server_key_sha256,
                "server_spki_sha256": server_spki_sha256,
                "certificate_sha256": validated["certificate_sha256"],
                "intermediate_count": validated["intermediate_count"],
            })

    family_manifest = {
        "fixture_set": fixture_set,
        "family_id": profile,
        "profile": profile,
        "hostname": bv.HOST,
        "depths": list(DEPTHS),
        "shared_root": True,
        "shared_server_key": True,
        "root_der_sha256": root_der_sha256,
        "server_key_sha256": shared_server_key_sha256,
        "server_spki_sha256": server_spki_sha256,
        "cells": cells,
    }
    write_json(family / "family-manifest.json", family_manifest)

    print("Generated:", family)
    print("root DER SHA256:", root_der_sha256)
    print("server key SHA256:", shared_server_key_sha256)
    print("server SPKI SHA256:", server_spki_sha256)
    for cell in cells:
        print(
            f"D={cell['depth']}: "
            f"intermediates={cell['intermediate_count']} "
            f"fixture={cell['fixture']}"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "generate"))
    parser.add_argument("--profile", choices=bv.PROFILES)
    parser.add_argument("--fixture-set")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--image", default="mt-tls-mtc:local")
    args = parser.parse_args()

    if args.action == "plan":
        print("PRINT ONLY")
        print("Hostname:", bv.HOST)
        print("Depths:", ", ".join(map(str, DEPTHS)))
        print("Profiles:", ", ".join(bv.PROFILES))
        print("Per profile: one root, one server key, shared I1/I2/I3 hierarchy.")
        print("D2=root->server")
        print("D3=root->I1->server")
        print("D4=root->I1->I2->server")
        print("D5=root->I1->I2->I3->server")
        return 0

    bv.require(args.profile is not None, "generate requires --profile")
    bv.require(args.fixture_set, "generate requires --fixture-set")
    bv.require(args.output is not None, "generate requires --output")

    generate_family(
        args.output,
        args.fixture_set,
        args.profile,
        args.image,
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, bv.subprocess.SubprocessError) as error:
        print("ERROR:", error, file=sys.stderr)
        sys.exit(1)
