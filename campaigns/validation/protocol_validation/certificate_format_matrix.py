#!/usr/bin/env python3
"""Audit generated MTC certificates across profiles, modes, and leaf positions."""

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "src/mtc"))

import core
from crypto_profiles import SIGNATURE_PROFILES
from validate_mtc import validate


DEFAULT_LEAVES = (0, 7, 15)
DEFAULT_MODES = ("landmark", "standalone")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mtc-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--openssl", default="/opt/mtc/openssl.sh")
    parser.add_argument("--leaves", type=int, nargs="+", default=DEFAULT_LEAVES)
    args = parser.parse_args()

    if args.output.exists():
        parser.error("Output exists; choose a new report")

    fixture_root = args.mtc_root / "batch16" / "mtc"
    if not fixture_root.is_dir():
        parser.error(f"MTC fixture directory not found: {fixture_root}")

    cases = []
    passed = 0
    failed = 0

    for profile in SIGNATURE_PROFILES:
        profile_root = fixture_root / profile

        for leaf in args.leaves:
            leaf4 = f"{leaf:04d}"
            leaf6 = f"{leaf:06d}"
            entry = profile_root / "log" / f"{leaf6}.entry"

            for mode in DEFAULT_MODES:
                certificate = profile_root / f"{mode}-{leaf4}.der"

                trust = (
                    profile_root / "trust.bin"
                    if mode == "landmark"
                    else profile_root / "authority.bin"
                )

                case = {
                    "profile": profile,
                    "mode": mode,
                    "requested_leaf_index": leaf,
                    "certificate": str(certificate.relative_to(args.mtc_root)),
                    "entry": str(entry.relative_to(args.mtc_root)),
                    "trust": str(trust.relative_to(args.mtc_root)),
                }

                try:
                    if not certificate.is_file():
                        raise ValueError(f"missing certificate: {certificate}")
                    if not entry.is_file():
                        raise ValueError(f"missing log entry: {entry}")
                    if not trust.is_file():
                        raise ValueError(f"missing trust input: {trust}")

                    validation = validate(
                        SimpleNamespace(
                            object=certificate,
                            trust=trust,
                            mode=mode,
                            profile=profile,
                            openssl=args.openssl,
                            entry=entry,
                            sender=None,
                            revocation_checker=None,
                            revocation_trust=None,
                        )
                    )

                    if validation["overall"] != "PASS":
                        raise ValueError("validator did not return PASS")

                    if validation["tree_size"] != 16:
                        raise ValueError(
                            f"unexpected tree size: {validation['tree_size']}"
                        )

                    if validation["leaf_index"] != leaf:
                        raise ValueError(
                            "serial-derived leaf index does not match requested leaf"
                        )

                    if validation["log_number"] != 1:
                        raise ValueError(
                            f"unexpected log number: {validation['log_number']}"
                        )

                    serial = (validation["log_number"] << 48) | validation["leaf_index"]

                    case.update(
                        status="PASS",
                        tree_size=validation["tree_size"],
                        leaf_index=validation["leaf_index"],
                        log_number=validation["log_number"],
                        serial=serial,
                        subtree=validation["subtree"],
                        proof_hash_count=validation["proof_hash_count"],
                        expected_proof_hash_count=validation[
                            "expected_proof_hash_count"
                        ],
                        computed_root=validation["computed_root"],
                        expected_root=validation["expected_root"],
                        root_match=validation["root_match"],
                        mtc_wire_sha256=validation["mtc_wire_sha256"],
                        draft_checks=validation["draft_checks"]["checks"],
                    )
                    passed += 1

                except Exception as error:
                    case.update(status="FAIL", error=str(error))
                    failed += 1

                cases.append(case)

    report = {
        "draft": core.DRAFT,
        "claim": "generated-certificate audit for the implemented draft subset",
        "scope": {
            "tree_size": 16,
            "profiles": list(SIGNATURE_PROFILES),
            "modes": list(DEFAULT_MODES),
            "leaves": args.leaves,
        },
        "certificates_checked": len(cases),
        "passed": passed,
        "failed": failed,
        "overall": "PASS" if failed == 0 else "FAIL",
        "cases": cases,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")

    print(
        f"{report['overall']}: "
        f"{passed}/{len(cases)} generated certificates passed"
    )

    return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
