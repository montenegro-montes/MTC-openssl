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
FORMAL_FIXTURE_SET = "chromium-x509-depth-matrix-v1"


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


def build_matrix_manifest(output, fixture_set):
    bv.require(fixture_set == FORMAL_FIXTURE_SET, "Unexpected fixture_set")
    matrix_path = output / "matrix.json"
    bv.require(not matrix_path.exists(), "Matrix manifest already exists: " + str(matrix_path))
    families = {}
    root_hashes = set()
    spki_hashes = set()
    cell_count = 0
    for profile in bv.PROFILES:
        family_path = output / profile / "family-manifest.json"
        bv.require(family_path.is_file(), "Missing family manifest: " + str(family_path))
        family = json.loads(family_path.read_text())
        bv.require(family.get("fixture_set") == fixture_set, profile + ": fixture_set mismatch")
        bv.require(family.get("family_id") == profile and family.get("profile") == profile,
                   profile + ": family identity mismatch")
        bv.require(family.get("hostname") == bv.HOST, profile + ": hostname mismatch")
        bv.require(family.get("depths") == list(DEPTHS), profile + ": depth set mismatch")
        bv.require(family.get("shared_root") is True and family.get("shared_server_key") is True,
                   profile + ": family sharing invariant missing")
        cells = family.get("cells")
        bv.require(isinstance(cells, list) and len(cells) == len(DEPTHS),
                   profile + ": expected four cells")
        by_depth = {cell.get("depth"): cell for cell in cells if isinstance(cell, dict)}
        bv.require(set(by_depth) == set(DEPTHS), profile + ": invalid or duplicate cell depths")
        for depth in DEPTHS:
            cell = by_depth[depth]
            expected_fixture = f"{profile}/d{depth}"
            bv.require(cell.get("fixture") == expected_fixture,
                       f"{profile} D={depth}: fixture path mismatch")
            cell_path = output / expected_fixture / "manifest.json"
            bv.require(cell_path.is_file(), "Missing cell manifest: " + str(cell_path))
            cell_manifest = json.loads(cell_path.read_text())
            for key, expected in (
                    ("fixture_set", fixture_set), ("family_id", profile),
                    ("profile", profile), ("depth", depth), ("hostname", bv.HOST),
                    ("root_der_sha256", family.get("root_der_sha256")),
                    ("server_key_sha256", family.get("server_key_sha256")),
                    ("server_spki_sha256", family.get("server_spki_sha256"))):
                bv.require(cell_manifest.get(key) == expected,
                           f"{profile} D={depth}: {key} mismatch")
            for key in ("root_der_sha256", "server_key_sha256", "server_spki_sha256"):
                bv.require(cell.get(key) == family.get(key),
                           f"{profile} D={depth}: family {key} mismatch")
            bv.require(cell.get("certificate_sha256") ==
                       cell_manifest.get("files_sha256", {}).get("server.pem"),
                       f"{profile} D={depth}: certificate hash mismatch")
            bv.require(cell.get("intermediate_count") == depth - 2,
                       f"{profile} D={depth}: intermediate count mismatch")
        root_hashes.add(family["root_der_sha256"])
        spki_hashes.add(family["server_spki_sha256"])
        cell_count += len(cells)
        families[profile] = dict(family,
            family_manifest_sha256=bv.sha(family_path))
    bv.require(cell_count == 24, "Expected 24 X509 cells")
    bv.require(len(root_hashes) == 6, "Expected 6 unique roots")
    bv.require(len(spki_hashes) == 6, "Expected 6 unique server SPKIs")
    matrix = {
        "fixture_set": fixture_set,
        "hostname": bv.HOST,
        "profiles": list(bv.PROFILES),
        "depths": list(DEPTHS),
        "cell_count": cell_count,
        "unique_root_count": len(root_hashes),
        "unique_server_spki_count": len(spki_hashes),
        "families": families,
    }
    with matrix_path.open("x") as stream:
        stream.write(json.dumps(matrix, indent=2, sort_keys=True) + "\n")
    return matrix_path


def generate_matrix(output, fixture_set, image):
    bv.require(fixture_set == FORMAL_FIXTURE_SET, "Unexpected fixture_set")
    bv.require(not output.exists(), "Matrix output already exists: " + str(output))
    for profile in bv.PROFILES:
        generate_family(output, fixture_set, profile, image)
    matrix_path = build_matrix_manifest(output, fixture_set)
    print("Generated formal matrix:", matrix_path)


def ensure_matrix(repo, output, fixture_set, profiles, depth, image):
    """Reuse a valid formal matrix, or create it atomically when absent."""
    bv.require(fixture_set == FORMAL_FIXTURE_SET, "Unexpected fixture_set")
    bv.require(profiles and all(profile in bv.PROFILES for profile in profiles),
               "Unsupported requested profile")
    bv.require(depth in DEPTHS, "Unsupported requested depth")

    failures = []
    for profile in profiles:
        try:
            bv.precheck_formal_x509_fixture(
                repo, profile, depth, fixture_set)
        except (ValueError, OSError) as error:
            failures.append((profile, str(error) or type(error).__name__))
    if not failures:
        print("Reused validated formal X509 fixtures: profiles="+
              ",".join(profiles)+f" depth={depth}")
        return

    details = "; ".join(f"profile={profile} depth={depth}: {reason}"
                        for profile, reason in failures)
    if output.exists():
        bv.require(output.is_dir() and not output.is_symlink(),
                   "Formal X509 matrix path is not a safe directory: "+str(output))
        bv.require(not (output/'matrix.json').exists(),
                   "Formal X509 matrix manifest exists but requested cells are "
                   "invalid; preserved without overwrite. "+details)
        # A family is generated as one shared-root D=2..5 unit. Existing family
        # directories are never merged with newly generated certificate material.
        for profile, reason in failures:
            bv.require(not (output/profile).exists(),
                       "Formal X509 family exists but is incomplete, corrupt, or "
                       f"incompatible; preserved without overwrite. profile={profile} "
                       f"depth={depth}: {reason}")
        for profile in bv.PROFILES:
            family = output/profile
            if family.exists():
                for candidate_depth in DEPTHS:
                    bv.precheck_formal_x509_fixture(
                        repo, profile, candidate_depth, fixture_set)
                continue
            staging = Path(tempfile.mkdtemp(
                prefix=f".chromium-x509-{profile}-", dir=output.parent))
            try:
                generate_family(staging, fixture_set, profile, image)
                staging_repo = staging/'repo'
                staging_matrix = (staging_repo/'artifacts/x509'/fixture_set)
                staging_matrix.mkdir(parents=True)
                (staging/profile).replace(staging_matrix/profile)
                for candidate_depth in DEPTHS:
                    bv.precheck_formal_x509_fixture(
                        staging_repo, profile, candidate_depth, fixture_set)
                (staging_matrix/profile).replace(family)
            except Exception as error:
                raise ValueError(
                    f"Formal X509 family generation failed for profile={profile}; "
                    f"staging preserved at {staging}: {error}") from error
            for directory in (staging_matrix, staging_repo/'artifacts/x509',
                              staging_repo/'artifacts', staging_repo, staging):
                try:
                    directory.rmdir()
                except OSError:
                    pass
        build_matrix_manifest(output, fixture_set)
        for profile in profiles:
            bv.precheck_formal_x509_fixture(repo, profile, depth, fixture_set)
        print("Completed and validated formal X509 matrix:", output)
        return

    output.parent.mkdir(parents=True, exist_ok=True)
    staging_root = Path(tempfile.mkdtemp(
        prefix=".chromium-x509-depth-matrix-", dir=output.parent))
    staging_repo = staging_root / "repo"
    staging_output = (staging_repo / "artifacts" / "x509" / fixture_set)
    try:
        generate_matrix(staging_output, fixture_set, image)
        for profile in profiles:
            try:
                bv.precheck_formal_x509_fixture(
                    staging_repo, profile, depth, fixture_set)
            except (ValueError, OSError) as error:
                raise ValueError(
                    f"Generated formal X509 fixture validation failed for "
                    f"profile={profile} depth={depth}: {error}") from error
        inaccessible = [str(path) for path in staging_output.rglob("*")
                        if ((path.is_dir() and not os.access(path, os.R_OK | os.X_OK))
                            or (path.is_file() and not os.access(path, os.R_OK)))]
        bv.require(not inaccessible,
                   "Generated formal X509 artifacts are not accessible to "
                   "the invoking user: "+", ".join(inaccessible[:4]))
        # output was proved absent above; rename publishes the complete matrix.
        staging_output.replace(output)
    except Exception as error:
        raise ValueError(
            "Formal X509 generation failed for profiles="+
            ",".join(profiles)+f" depth={depth}; staging preserved at "
            f"{staging_root}: {error}") from error
    for directory in (staging_repo / "artifacts" / "x509",
                      staging_repo / "artifacts", staging_repo, staging_root):
        try:
            directory.rmdir()
        except OSError:
            pass
    print("Generated and validated formal X509 matrix:", output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "generate", "generate-matrix", "ensure"))
    parser.add_argument("--profile", choices=bv.PROFILES)
    parser.add_argument("--profiles", nargs="+", choices=bv.PROFILES)
    parser.add_argument("--depth", type=int, choices=DEPTHS)
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

    bv.require(args.fixture_set, "generate requires --fixture-set")
    bv.require(args.output is not None, "generate requires --output")

    if args.action == "ensure":
        bv.require(args.profile is None, "ensure uses --profiles")
        bv.require(args.profiles, "ensure requires --profiles")
        bv.require(args.depth is not None, "ensure requires --depth")
        ensure_matrix(HERE.parents[2], args.output, args.fixture_set,
                      args.profiles, args.depth, args.image)
        return 0

    if args.action == "generate-matrix":
        bv.require(args.profile is None and args.profiles is None and args.depth is None,
                   "generate-matrix does not accept profile/depth selectors")
        generate_matrix(args.output, args.fixture_set, args.image)
        return 0

    bv.require(args.profile is not None and args.profiles is None and args.depth is None,
               "generate requires --profile only")
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
