#!/usr/bin/env python3
"""Generate deterministic Chromium CACertificates policy from a formal X.509 matrix."""

import argparse
import base64
import hashlib
import json
from pathlib import Path
import plistlib
import sys
import uuid

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import browser_validation as bv


POLICY_NAME = "CACertificates"
CHROMIUM_BUNDLE_ID = "org.chromium.Chromium"
DEPTHS = (2, 3, 4, 5)


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha_file(path):
    return sha_bytes(Path(path).read_bytes())


def write_new(path, data, *, binary=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "xb" if binary else "x"
    with path.open(mode) as f:
        f.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    matrix_path = args.matrix.resolve()
    matrix_root = matrix_path.parent
    output = args.output.resolve()

    bv.require(matrix_path.is_file(), "Matrix manifest does not exist")
    bv.require(not output.exists(), "Policy output already exists")

    matrix = json.loads(matrix_path.read_text())

    fixture_set = matrix.get("fixture_set")
    bv.require(
        fixture_set == "chromium-x509-depth-matrix-v1",
        "Unexpected fixture_set",
    )
    bv.require(matrix.get("cell_count") == 24, "Expected 24 X509 cells")
    bv.require(matrix.get("unique_root_count") == 6, "Expected 6 roots")
    bv.require(
        matrix.get("unique_server_spki_count") == 6,
        "Expected 6 server SPKIs",
    )

    roots = []
    der_values = []

    for profile in bv.PROFILES:
        family = matrix["families"][profile]
        expected_hash = family["root_der_sha256"]

        family_hashes = set()

        for depth in DEPTHS:
            pem = matrix_root / profile / f"d{depth}" / "root.pem"
            bv.require(pem.is_file(), f"Missing root: {pem}")

            der = bv.certificate_der(pem.read_bytes())
            digest = sha_bytes(der)

            bv.require(
                digest == expected_hash,
                f"{profile} D={depth}: root differs from matrix manifest",
            )
            family_hashes.add(digest)

        bv.require(
            len(family_hashes) == 1,
            f"{profile}: roots differ across depths",
        )

        # D=2 is sufficient after proving D=2..5 are identical.
        der = bv.certificate_der(
            (matrix_root / profile / "d2" / "root.pem").read_bytes()
        )

        encoded = base64.b64encode(der).decode("ascii")

        roots.append({
            "profile": profile,
            "root_der_sha256": expected_hash,
            "der_bytes": len(der),
        })
        der_values.append(der)

    root_hashes = [entry["root_der_sha256"] for entry in roots]

    bv.require(len(set(root_hashes)) == 6, "Roots are not unique")

    # Order is fixed by browser_validation.PROFILES.
    ordered_root_set_sha256 = sha_bytes(b"".join(der_values))

    ca_values = [
        base64.b64encode(der).decode("ascii")
        for der in der_values
    ]

    chromium_policy = {
        POLICY_NAME: ca_values,
    }

    policy_json = (
        json.dumps(chromium_policy, indent=2, sort_keys=True) + "\n"
    ).encode()

    profile_identifier = (
        "org.mtc.chromium.ca."
        + fixture_set.replace("_", "-")
    )

    payload_identifier = profile_identifier + ".managed"

    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": profile_identifier,
        "PayloadUUID": str(
            uuid.uuid5(uuid.NAMESPACE_URL, profile_identifier)
        ).upper(),
        "PayloadDisplayName": "Chromium MTC X509 Matrix CA Policy",
        "PayloadContent": [
            {
                "PayloadType": "com.apple.ManagedClient.preferences",
                "PayloadVersion": 1,
                "PayloadIdentifier": payload_identifier,
                "PayloadUUID": str(
                    uuid.uuid5(uuid.NAMESPACE_URL, payload_identifier)
                ).upper(),
                "PayloadDisplayName": "Chromium CACertificates",
                "PayloadContent": {
                    CHROMIUM_BUNDLE_ID: {
                        "Forced": [
                            {
                                "mcx_preference_settings": {
                                    POLICY_NAME: ca_values,
                                }
                            }
                        ]
                    }
                },
            }
        ],
    }

    mobileconfig = plistlib.dumps(
        profile,
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )

    output.mkdir(parents=True)

    canonical = output / "canonical-policy.json"
    linux = output / "linux" / "mtc-ca-policy.json"
    macos = output / "macos" / "chromium-mtc-ca.mobileconfig"

    write_new(canonical, policy_json, binary=True)
    write_new(linux, policy_json, binary=True)
    write_new(macos, mobileconfig, binary=True)

    manifest = {
        "fixture_set": fixture_set,
        "matrix_manifest_sha256": sha_file(matrix_path),
        "policy_name": POLICY_NAME,
        "chromium_bundle_id": CHROMIUM_BUNDLE_ID,
        "profile_order": list(bv.PROFILES),
        "root_count": len(roots),
        "roots": roots,
        "ordered_root_set_sha256": ordered_root_set_sha256,
        "outputs": {
            "canonical-policy.json": {
                "sha256": sha_file(canonical),
            },
            "linux/mtc-ca-policy.json": {
                "sha256": sha_file(linux),
            },
            "macos/chromium-mtc-ca.mobileconfig": {
                "sha256": sha_file(macos),
            },
        },
    }

    manifest_path = output / "policy-manifest.json"
    write_new(
        manifest_path,
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    )

    print("PASS: generated Chromium CACertificates policy")
    print("fixture set:", fixture_set)
    print("roots:", len(roots))
    print("ordered root set SHA256:", ordered_root_set_sha256)
    print("canonical:", canonical)
    print("macOS:", macos)
    print("Linux:", linux)

    for entry in roots:
        print(
            entry["profile"],
            entry["root_der_sha256"],
            f"({entry['der_bytes']} DER bytes)",
        )

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, KeyError) as error:
        print("ERROR:", error, file=sys.stderr)
        sys.exit(1)
