#!/usr/bin/env python3

import json
import subprocess
import sys
from pathlib import Path

from config import ARTIFACT_ROOT, MTC_N_VALUES


HERE = Path(__file__).resolve().parent

PREPARERS = {
    "client": HERE / "prepare_client_mtc_v2.py",
    "server": HERE / "prepare_server_mtc_v2.py",
}


def load_json(path):
    return json.loads(path.read_text())


def validate_manifest(role, profile, n, manifest, expected_spkis):
    errors = []

    if manifest.get("experiment") != "mutual-auth-crossover-v2":
        errors.append("wrong experiment")

    if manifest.get("role") != role:
        errors.append(
            f"wrong role: {manifest.get('role')!r}"
        )

    if manifest.get("profile") != profile:
        errors.append(
            f"wrong profile: {manifest.get('profile')!r}"
        )

    if manifest.get("tree_size") != n:
        errors.append(
            f"wrong tree_size: {manifest.get('tree_size')!r}"
        )

    if manifest.get("source_chain_profile") != "ca-server":
        errors.append(
            "source_chain_profile is not ca-server"
        )

    actual_ca = manifest.get("ca_spki_sha256")
    actual_cosigner = manifest.get("cosigner_spki_sha256")

    if actual_ca != expected_spkis[0]:
        errors.append(
            f"cosigner-0/CA SPKI changed: "
            f"{actual_ca} != {expected_spkis[0]}"
        )

    if actual_cosigner != expected_spkis[1]:
        errors.append(
            f"cosigner-1 SPKI changed: "
            f"{actual_cosigner} != {expected_spkis[1]}"
        )

    if errors:
        raise SystemExit(
            f"{role} {profile} N={n}: "
            + "; ".join(errors)
        )


def main():
    frozen_path = ARTIFACT_ROOT / "cosigners-manifest.json"

    if not frozen_path.is_file():
        raise SystemExit(
            f"Missing frozen cosigner manifest: {frozen_path}"
        )

    frozen = load_json(frozen_path)

    cells = []

    for profile, ns in MTC_N_VALUES.items():
        for role, preparer in PREPARERS.items():

            expected_spkis = (
                frozen["profiles"][profile][role]
                ["cosigner_spki_sha256"]
            )

            for n in ns:
                out = (
                    ARTIFACT_ROOT
                    / f"{role}-mtc"
                    / f"batch{n}"
                    / profile
                )

                manifest_path = out / "manifest.json"

                if out.exists() and not manifest_path.is_file():
                    raise SystemExit(
                        f"Partial output exists without manifest: {out}"
                    )

                if not manifest_path.is_file():
                    print()
                    print(
                        f"=== PREPARE {role} "
                        f"{profile} N={n} ==="
                    )

                    subprocess.run(
                        [
                            sys.executable,
                            str(preparer),
                            "--profile", profile,
                            "--n", str(n),
                        ],
                        check=True,
                    )
                else:
                    print(
                        f"REUSE {role} {profile} N={n}: "
                        f"{manifest_path}"
                    )

                manifest = load_json(manifest_path)

                validate_manifest(
                    role,
                    profile,
                    n,
                    manifest,
                    expected_spkis,
                )

                landmark = manifest["sizes"]["landmark"]

                cells.append({
                    "role": role,
                    "profile": profile,
                    "tree_size": n,
                    "ca_spki_sha256":
                        manifest["ca_spki_sha256"],
                    "cosigner_spki_sha256":
                        manifest["cosigner_spki_sha256"],
                    "mtc_certificate_bytes":
                        landmark["mtc_certificate_bytes"],
                    "mtc_inclusion_proof_bytes":
                        landmark["mtc_inclusion_proof_bytes"],
                    "trust_file_bytes":
                        manifest["trust_file_bytes"],
                    "path": str(out),
                })

    expected_cells = (
        2 * sum(len(ns) for ns in MTC_N_VALUES.values())
    )

    if len(cells) != expected_cells:
        raise SystemExit(
            f"Expected {expected_cells} cells, "
            f"got {len(cells)}"
        )

    summary = {
        "experiment": "mutual-auth-crossover-v2",
        "purpose":
            "Frozen client/server MTC preparation across N",
        "cell_count": len(cells),
        "expected_cell_count": expected_cells,
        "cosigner_invariance_validated": True,
        "cells": cells,
    }

    summary_path = (
        ARTIFACT_ROOT / "mtc-preparation-manifest.json"
    )

    if summary_path.exists():
        previous = load_json(summary_path)

        if previous != summary:
            raise SystemExit(
                "Existing mtc-preparation-manifest.json "
                "differs from current validation"
            )

        print()
        print(
            "Existing preparation manifest matches "
            "current validation."
        )
    else:
        summary_path.write_text(
            json.dumps(summary, indent=2) + "\n"
        )

    print()
    print("=== MTC PREPARATION PASS ===")
    print(f"cells = {len(cells)}")
    print("cosigner invariance = PASS")
    print(summary_path)


if __name__ == "__main__":
    main()
