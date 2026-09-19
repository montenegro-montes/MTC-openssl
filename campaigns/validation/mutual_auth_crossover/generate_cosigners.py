#!/usr/bin/env python3

import argparse
import json
import os
import subprocess
from pathlib import Path

from config import ARTIFACT_ROOT, PROFILES

OPENSSL = "/opt/openssl-mtc/bin/openssl"
IMAGE = "mt-tls-mtc:local"
LD_LIBRARY_PATH = "/opt/openssl-mtc/lib:/opt/openssl/lib:/opt/oqs/lib"

ROLES = ("client", "server")


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=ARTIFACT_ROOT,
    )
    args = parser.parse_args()

    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=True)
    os.umask(0o077)

    manifest = {
        "experiment": "mutual-auth-crossover-v2",
        "purpose": (
            "Frozen MTC cosigner keys reused across chain profiles "
            "and all N values within each crypto profile and role"
        ),
        "profiles": {},
    }

    for profile_name, profile in PROFILES.items():
        manifest["profiles"][profile_name] = {}

        for role in ROLES:
            out = root / f"{role}-cosigners" / profile_name

            if out.exists() and any(out.iterdir()):
                raise SystemExit(
                    f"Refusing to overwrite existing cosigners: {out}"
                )

            out.mkdir(parents=True, exist_ok=True)

            rel = out.relative_to(root)

            for i in range(2):
                key = f"/work/{rel}/cosigner-{i}.key"
                spki = f"/work/{rel}/cosigner-{i}.spki"

                docker_openssl(
                    root,
                    "genpkey",
                    "-algorithm", "EC",
                    "-pkeyopt",
                    f"ec_paramgen_curve:{profile['pkey_curve']}",
                    "-out", key,
                )

                docker_openssl(
                    root,
                    "pkey",
                    "-in", key,
                    "-pubout",
                    "-outform", "DER",
                    "-out", spki,
                )

            fingerprints = []

            for i in range(2):
                result = subprocess.run(
                    [
                        "shasum", "-a", "256",
                        str(out / f"cosigner-{i}.spki"),
                    ],
                    text=True,
                    capture_output=True,
                    check=True,
                )
                fingerprints.append(result.stdout.split()[0])

            manifest["profiles"][profile_name][role] = {
                "directory": str(out),
                "cosigner_spki_sha256": fingerprints,
            }

    manifest_path = root / "cosigners-manifest.json"

    if manifest_path.exists():
        raise SystemExit(
            f"Refusing to overwrite manifest: {manifest_path}"
        )

    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n"
    )

    print()
    print("Generated frozen cosigners:")
    print(manifest_path)


if __name__ == "__main__":
    main()
