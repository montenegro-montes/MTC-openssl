#!/usr/bin/env python3
"""Check the archived article datasets and write their plotted/table values."""

import csv
import json
import statistics
from decimal import Decimal
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
PROFILES = ("ecdsa-p384", "mldsa65", "slhdsa192s")
CASES = (("x509-simple-d3", "x509"),
         ("mtc-simple-landmark", "landmark"),
         ("mtc-simple-standalone", "standalone"))
ARMS = ("full-ordinary", "full-zlib", "elided-ordinary", "elided-zlib")
EXPECTED_TABLE = {
    "ecdsa-p384": (4157, 3917, 3643, 3614, 3839, 3620),
    "mldsa65": (17482, 17271, 11911, 11908, 15312, 8680),
    "slhdsa192s": (52464, 52318, 35858, 35865, 52193, 19687),
}
EXPECTED_FIGURES = {
    ("s_client", "ecdsa-p384"): (3.364, 1.256, 3.248),
    ("s_client", "mldsa65"): (0.533, 0.214, 0.358),
    ("s_client", "slhdsa192s"): (7.212, 3.076, 7.072),
    ("chromium", "ecdsa-p384"): (6.041, 2.896, 5.670),
    ("chromium", "mldsa65"): (3.644, 2.011, 2.985),
}


def rows(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def write_csv(path, fields, records):
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fields)
        writer.writeheader()
        writer.writerows(records)


def byte_values(records):
    assert len(records) == 100
    for row in records:
        assert int(row["tls_bytes_read"]) + int(row["tls_bytes_written"]) == int(row["tls_bytes_total"])
    return tuple(int(statistics.median(int(row[key]) for row in records))
                 for key in ("tls_bytes_read", "tls_bytes_written", "tls_bytes_total"))


def table_values():
    native = rows(DATA / "table_i/native/native.csv")
    native_summary = json.loads((DATA / "table_i/native/summary.json").read_text())
    assert native_summary["server_hostname"] == "server.mtc.example.com"
    assert native_summary["key_establishment"]["openssl_group"] == "X25519MLKEM768"
    image_id = native_summary["image_id"]
    output = []
    for profile in PROFILES:
        study_dir = DATA / "table_i" / profile
        study = rows(study_dir / "samples.csv")
        summary = json.loads((study_dir / "summary.json").read_text())
        config = json.loads((study_dir / "config.json").read_text())
        assert summary["reference_match"] and summary["image_id"] == config["image_id"] == image_id
        assert config["profile"] == profile and config["hostname"] == "server.mtc.example.com"
        assert config["openssl_group"] == "X25519MLKEM768" and config["x509_depth"] == 3
        arm_data = {}
        for arm in ARMS:
            sample = [row for row in study if row["condition"] == arm and row["phase"] == "measured"]
            arm_data[arm] = byte_values(sample)
            reported = summary["arms"][arm]
            assert arm_data[arm][2] == int(reported["tls_bytes_total_median"])
        native_data = {}
        for case, name in CASES:
            sample = [row for row in native if row["profile"] == profile
                      and row["case"] == case and row["phase"] == "measured"]
            native_data[name] = byte_values(sample)
        ordinary = arm_data["full-ordinary"]
        reference = native_data["x509"]
        assert ordinary[1] == reference[1]
        assert abs(ordinary[0] - reference[0]) <= (1 if profile == "ecdsa-p384" else 0)
        baseline = reference[2]
        sequence = [native_data["x509"], arm_data["full-zlib"],
                    arm_data["elided-ordinary"], arm_data["elided-zlib"],
                    native_data["standalone"], native_data["landmark"]]
        assert tuple(value[2] for value in sequence) == EXPECTED_TABLE[profile]
        for name, values in zip(("X.509 D=3", "D=3 + zlib", "Intermediate omitted",
                                 "Omitted + zlib offered", "MTC Standalone", "MTC Landmark"), sequence):
            sent = (",".join(summary["arms"]["elided-zlib"]["sent_messages"])
                    if name == "Omitted + zlib offered" else
                    "CompressedCertificate" if name == "D=3 + zlib" else
                    "Certificate" if name.startswith(("X.509", "Intermediate")) else "MTC")
            output.append(dict(profile=profile, arm=name, read_median_B=values[0],
                               written_median_B=values[1], total_median_B=values[2],
                               reduction_pct=f"{100 * (baseline - values[2]) / baseline:.2f}",
                               sent_message=sent,
                               measurement_block="native" if name in
                               ("X.509 D=3", "MTC Standalone", "MTC Landmark") else "elision"))
    return output


def figure_values():
    stats = rows(DATA / "figures/authentication_statistics.csv")
    samples = rows(DATA / "figures/authentication_samples.csv")
    output = []
    for (client, profile), expected in EXPECTED_FIGURES.items():
        for index, case in enumerate(("x509", "landmark", "standalone")):
            selected = [row for row in stats if row["client"] == client
                        and row["profile"] == profile and row["phase"] == "measured"
                        and row["credential_type"] == ("x509" if case == "x509" else "mtc")
                        and row["mtc_verification_mode"] == ("" if case == "x509" else case)]
            metric = {row["metric"]: row for row in selected}
            components = ("credential_validation_total_ns", "certificate_verify_crypto_ns", "auth_total_ns")
            assert all(name in metric for name in components)
            assert all(int(metric[name]["n_valid"]) == int(metric[name]["n_observations"]) == 100
                       for name in components)
            selected_samples = [row for row in samples if row["client"] == client
                                and row["profile"] == profile and row["phase"] == "measured"
                                and row["credential_type"] == ("x509" if case == "x509" else "mtc")
                                and row["mtc_verification_mode"] == ("" if case == "x509" else case)]
            assert len(selected_samples) == 100
            for name in components:
                source_mean = sum(Decimal(row[name]) for row in selected_samples) / Decimal(100)
                assert abs(source_mean - Decimal(metric[name]["mean"])) <= Decimal("0.01")
            values = [Decimal(metric[name]["mean"]) / Decimal(1_000_000) for name in components]
            assert abs(values[0] + values[1] - values[2]) < Decimal("0.000001")
            assert round(float(values[2]), 3) == expected[index]
            output.append(dict(client=client, profile=profile, case=case, n=100,
                               credential_validation_mean_ms=f"{values[0]:.6f}",
                               certificate_verify_mean_ms=f"{values[1]:.6f}",
                               authentication_total_mean_ms=f"{values[2]:.6f}",
                               figure_label_ms=f"{values[2]:.3f}"))
    return output


def main():
    table = table_values()
    figures = figure_values()
    write_csv(DATA / "table_i_values.csv", tuple(table[0]), table)
    write_csv(DATA / "figure_4_5_values.csv", tuple(figures[0]), figures)
    print("PASS: Table I has 18 checked rows; Figures 4 and 5 have 15 checked bars.")


if __name__ == "__main__":
    main()
