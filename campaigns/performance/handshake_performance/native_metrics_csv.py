#!/usr/bin/env python3
"""Parse native OpenSSL timing records for the handshake campaign CSV."""

import json
import re
import sys


HISTORICAL_FIELDS = (
    "tcp_connect_wall_ms_native",
    "handshake_wall_ms",
    "connection_establishment_wall_ms_native",
    "x509_verification_ms",
    "mtc_credential_auth_ms",
    "merkle_proof_ms",
    "landmark_validation_ms",
    "standalone_validation_ms",
    "certificate_verify_ms",
    "credential_verification_total_ms",
    "client_authentication_verification_total_ms",
    "credential_verification_other_ms",
)

V2_FIELDS = (
    "timing_schema_version",
    "mtc_total_ns",
    "merkle_leaf_hash_ns",
    "merkle_path_ns",
    "merkle_total_ns",
    "x509_signatures_ns",
    "x509_signature_count",
    "x509_signatures_scope",
    "x509_signature_cache_ns",
    "x509_signature_cache_hits",
    "x509_signature_cache_misses",
    "standalone_signatures_ns",
    "standalone_signature_count",
    "standalone_signature_cache_ns",
    "standalone_signature_cache_hits",
    "standalone_signature_cache_misses",
    "certificate_verify_crypto_ns",
    "credential_validation_total_ns",
    "handshake_total_ns",
    "verification_mode",
    "mtc_success",
)

UINT64_FIELDS = {
    "mtc_total_ns",
    "merkle_leaf_hash_ns",
    "merkle_path_ns",
    "merkle_total_ns",
    "x509_signatures_ns",
    "x509_signature_count",
    "x509_signature_cache_ns",
    "x509_signature_cache_hits",
    "x509_signature_cache_misses",
    "standalone_signatures_ns",
    "standalone_signature_count",
    "standalone_signature_cache_ns",
    "standalone_signature_cache_hits",
    "standalone_signature_cache_misses",
    "certificate_verify_crypto_ns",
    "credential_validation_total_ns",
    "handshake_total_ns",
}

NATIVE_V2_FIELDS = (
    "x509_signatures_ns",
    "x509_signature_count",
    "x509_signatures_scope",
    "x509_signature_cache_ns",
    "x509_signature_cache_hits",
    "x509_signature_cache_misses",
    "certificate_verify_crypto_ns",
    "credential_validation_total_ns",
    "handshake_total_ns",
)

MTC_V2_FIELDS = (
    "mtc_total_ns",
    "merkle_leaf_hash_ns",
    "merkle_path_ns",
    "merkle_total_ns",
    "standalone_signatures_ns",
    "standalone_signature_count",
    "standalone_signature_cache_ns",
    "standalone_signature_cache_hits",
    "standalone_signature_cache_misses",
    "verification_mode",
    "mtc_success",
)


def _records(text, marker):
    records = []
    for match in re.findall(rf"{re.escape(marker)}\s+(\{{[^\n]+\}})", text):
        try:
            records.append(json.loads(match))
        except json.JSONDecodeError:
            pass
    return records


def _historical_native_record(text):
    """Retain the pre-schema fallback for interleaved Docker output."""
    broken = re.search(
        r'NATIVE_METRICS\s+\{"tcp_connect_wall_ms_native":.*?'
        r'([0-9]+(?:\.[0-9]+)?),"handshake_wall_ms":([0-9]+(?:\.[0-9]+)?),'
        r'"connection_establishment_wall_ms_native":([0-9]+(?:\.[0-9]+)?),'
        r'"x509_verification_ms":([0-9]+(?:\.[0-9]+)?),'
        r'"credential_verification_total_ms":([0-9]+(?:\.[0-9]+)?),'
        r'"certificate_verify_ms":([0-9]+(?:\.[0-9]+)?),'
        r'"client_authentication_verification_total_ms":([0-9]+(?:\.[0-9]+)?)\}',
        text,
        re.S,
    )
    if not broken:
        raise ValueError("NATIVE_METRICS record missing")
    return dict(zip(
        ("tcp_connect_wall_ms_native", "handshake_wall_ms",
         "connection_establishment_wall_ms_native", "x509_verification_ms",
         "credential_verification_total_ms", "certificate_verify_ms",
         "client_authentication_verification_total_ms"),
        map(float, broken.groups()),
    ))


def _uint64(value, field):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f"{field} is not an unsigned integer")
    if isinstance(value, str):
        if not value or not value.isdecimal():
            raise ValueError(f"{field} is not an unsigned integer")
        value = int(value)
    if not 0 <= value < 1 << 64:
        raise ValueError(f"{field} is outside uint64")
    return value


def _schema(record, marker):
    if "timing_schema_version" not in record:
        return None
    version = _uint64(record["timing_schema_version"],
                      f"{marker}.timing_schema_version")
    if version == 0:
        raise ValueError(f"{marker}.timing_schema_version must be positive")
    return version


def validate_v2_intervals(values):
    """Reject impossible containment relations without deriving any metric."""
    containments = (
        ("handshake_total_ns", "credential_validation_total_ns"),
        ("credential_validation_total_ns", "mtc_total_ns"),
        ("credential_validation_total_ns", "x509_signatures_ns"),
        ("handshake_total_ns", "certificate_verify_crypto_ns"),
    )
    for outer, inner in containments:
        outer_value = values.get(outer)
        inner_value = values.get(inner)
        if (outer_value is not None and inner_value is not None
                and outer_value < inner_value):
            raise ValueError(
                f"incoherent timing intervals: {outer}={outer_value} "
                f"is smaller than {inner}={inner_value}")


def parse_native_metrics(text, case_name):
    native_records = _records(text, "NATIVE_METRICS")
    native = native_records[-1] if native_records else _historical_native_record(text)

    required = (
        "tcp_connect_wall_ms_native", "handshake_wall_ms",
        "connection_establishment_wall_ms_native", "x509_verification_ms",
        "credential_verification_total_ms", "certificate_verify_ms",
        "client_authentication_verification_total_ms",
    )
    if any(native.get(field) is None for field in required):
        raise ValueError("native TCP/TLS/verification metric is unavailable")
    if abs(native["x509_verification_ms"]
           - native["credential_verification_total_ms"]) > 1e-9:
        raise ValueError(
            "x509_verification_ms compatibility alias differs from "
            "credential_verification_total_ms")

    mtc = {
        "mtc_credential_auth_ms": None,
        "merkle_proof_ms": None,
        "landmark_validation_ms": None,
        "standalone_validation_ms": None,
    }
    mtc_record = None
    if case_name.startswith("mtc-"):
        mtc_records = _records(text, "MTC_VERIFY")
        if not mtc_records:
            raise ValueError("MTC verification metrics missing")
        mtc_record = mtc_records[-1]
        mtc.update(mtc_record)
        if mtc.get("mtc_credential_auth_ms") is None:
            raise ValueError("MTC credential authentication metric is unavailable")
        if mtc.get("merkle_proof_ms") is None:
            raise ValueError("Merkle proof metric is unavailable")
        expected = ("landmark_validation_ms" if "-landmark" in case_name
                    else "standalone_validation_ms")
        if mtc.get(expected) is None:
            raise ValueError(f"{expected} is unavailable")

    native_schema = _schema(native, "NATIVE_METRICS")
    mtc_schema = _schema(mtc_record, "MTC_VERIFY") if mtc_record else None
    if (native_schema is not None and mtc_schema is not None
            and native_schema != mtc_schema):
        raise ValueError(
            "incompatible timing_schema_version: "
            f"NATIVE_METRICS={native_schema}, MTC_VERIFY={mtc_schema}")
    schema = native_schema if native_schema is not None else mtc_schema

    suboperations = sum(mtc.get(field) or 0.0 for field in (
        "merkle_proof_ms", "landmark_validation_ms",
        "standalone_validation_ms"))
    other = native["credential_verification_total_ms"] - suboperations
    if other < -1e-6:
        print(
            f"WARNING: negative credential_verification_other_ms={other:.9f} "
            f"for {case_name}",
            file=sys.stderr,
        )

    values = {
        "tcp_connect_wall_ms_native": native["tcp_connect_wall_ms_native"],
        "handshake_wall_ms": native["handshake_wall_ms"],
        "connection_establishment_wall_ms_native":
            native["connection_establishment_wall_ms_native"],
        "x509_verification_ms": native["x509_verification_ms"],
        "mtc_credential_auth_ms": mtc.get("mtc_credential_auth_ms"),
        "merkle_proof_ms": mtc.get("merkle_proof_ms"),
        "landmark_validation_ms": mtc.get("landmark_validation_ms"),
        "standalone_validation_ms": mtc.get("standalone_validation_ms"),
        "certificate_verify_ms": native["certificate_verify_ms"],
        "credential_verification_total_ms":
            native["credential_verification_total_ms"],
        "client_authentication_verification_total_ms":
            native["client_authentication_verification_total_ms"],
        "credential_verification_other_ms": other,
        "timing_schema_version": schema,
    }
    for field in NATIVE_V2_FIELDS:
        values[field] = native.get(field)
    if mtc_record:
        for field in MTC_V2_FIELDS:
            values[field] = mtc_record.get(field)

    for field in UINT64_FIELDS:
        values[field] = _uint64(values.get(field), field)
    if values.get("mtc_success") is not None and not isinstance(
            values["mtc_success"], bool):
        raise ValueError("mtc_success is not boolean")
    validate_v2_intervals(values)
    return values


def csv_values(values):
    result = []
    for field in (*HISTORICAL_FIELDS, *V2_FIELDS):
        value = values.get(field)
        if value is None:
            result.append("")
        elif isinstance(value, bool):
            result.append("true" if value else "false")
        else:
            result.append(str(value))
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        raise SystemExit("usage: native_metrics_csv.py LOG CASE")
    try:
        with open(argv[0], errors="replace") as stream:
            values = parse_native_metrics(stream.read(), argv[1])
    except ValueError as error:
        raise SystemExit(f"ERROR: {error}") from error
    # The sentinel preserves a final empty field when Bash splits the output.
    print("|".join((*csv_values(values), "__END__")))


if __name__ == "__main__":
    main()
