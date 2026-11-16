#!/usr/bin/env python3
"""Check and summarize a new Table I run without mixing image IDs or fixtures."""

import argparse
import csv
import json
import statistics
from pathlib import Path


PROFILES = ("ecdsa-p384", "mldsa65", "slhdsa192s")
ARMS = ("full-ordinary", "full-zlib", "elided-ordinary", "elided-zlib")
NATIVE = (("x509-simple-d3", "X.509 D=3"),
          ("mtc-simple-standalone", "MTC Standalone"),
          ("mtc-simple-landmark", "MTC Landmark"))
LABELS = {"full-ordinary": "X.509 D=3", "full-zlib": "D=3 + zlib",
          "elided-ordinary": "Intermediate omitted",
          "elided-zlib": "Omitted + zlib offered"}
FIELDS = ("profile", "arm", "read_median_B", "written_median_B",
          "total_median_B", "reduction_pct", "sent_message", "measurement_block")


def pair(value):
    profile, sep, path = value.partition("=")
    if not sep or profile not in PROFILES:
        raise argparse.ArgumentTypeError("Expected PROFILE=RESULT_DIRECTORY")
    return profile, Path(path)


def rows(path):
    with path.open(newline="") as stream:
        return list(csv.DictReader(stream))


def byte_values(records):
    if len(records) != 100:
        raise ValueError(f"Expected 100 measured rows, found {len(records)}")
    for row in records:
        if int(row["tls_bytes_read"]) + int(row["tls_bytes_written"]) != int(row["tls_bytes_total"]):
            raise ValueError("Directional byte counters do not sum to the total")
    medians = tuple(statistics.median(int(row[key]) for row in records)
                    for key in ("tls_bytes_read", "tls_bytes_written", "tls_bytes_total"))
    if any(int(value) != value for value in medians):
        raise ValueError("A byte median is not an integer; inspect the samples")
    return tuple(map(int, medians))


def output_row(profile, name, values, baseline, sent, block):
    return dict(profile=profile, arm=name, read_median_B=values[0],
                written_median_B=values[1], total_median_B=values[2],
                reduction_pct=f"{100 * (baseline - values[2]) / baseline:.2f}",
                sent_message=sent, measurement_block=block)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", action="append", type=pair, required=True)
    parser.add_argument("--native", type=Path,
                        help="D=3 native result directory; required for the complete six-arm table")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    studies = dict(args.study)
    if set(studies) != set(PROFILES) or len(args.study) != len(PROFILES):
        parser.error("Supply exactly one study for each of the three profiles")

    native_rows = None
    native_summary = None
    if args.native:
        native_rows = rows(args.native / "native.csv")
        native_summary = json.loads((args.native / "summary.json").read_text())
        if native_summary.get("server_hostname") != "server.mtc.example.com" \
                or native_summary["key_establishment"]["openssl_group"] != "X25519MLKEM768" \
                or native_summary["x509_trust_path"]["depth_including_root"] != 3:
            raise ValueError("Native hostname, group, or depth differs")

    result = []
    image_ids = set()
    for profile in PROFILES:
        study = studies[profile]
        config = json.loads((study / "config.json").read_text())
        summary = json.loads((study / "summary.json").read_text())
        samples = rows(study / "samples.csv")
        image_ids.add(config["image_id"])
        if config["profile"] != profile or config["hostname"] != "server.mtc.example.com" \
                or config["openssl_group"] != "X25519MLKEM768" \
                or config["tls_version"] != "TLS1.3" or config["x509_depth"] != 3 \
                or summary["image_id"] != config["image_id"] \
                or summary["reference_match"] is not True:
            raise ValueError(f"Invalid study binding or pilot reference: {profile}")
        study_values = {}
        for arm in ARMS:
            measured = [row for row in samples if row["phase"] == "measured"
                        and row["condition"] == arm]
            values = byte_values(measured)
            if values[2] != summary["arms"][arm]["tls_bytes_total_median"]:
                raise ValueError(f"Summary differs from samples: {profile} {arm}")
            study_values[arm] = values

        native_values = {}
        if native_rows is not None:
            if native_summary.get("image_id") != config["image_id"]:
                raise ValueError(f"Native and compression images differ: {profile}")
            bindings = native_summary["x509_trust_path"]["fixtures"]["bindings"]
            if not any(item["profile"] == profile and item["role"] == "server"
                       and item["path"] == config["fixture"] for item in bindings):
                raise ValueError(f"Native and compression X.509 fixtures differ: {profile}")
            for case, name in NATIVE:
                measured = [row for row in native_rows if row["phase"] == "measured"
                            and row["profile"] == profile and row["case"] == case]
                native_values[name] = byte_values(measured)
            ordinary = study_values["full-ordinary"]
            reference = native_values["X.509 D=3"]
            if reference != ordinary:
                raise ValueError(f"Directional X.509 references differ: {profile}")
            baseline = reference[2]
        else:
            baseline = study_values["full-ordinary"][2]

        for arm in ARMS:
            values = native_values["X.509 D=3"] if arm == "full-ordinary" and native_values \
                else study_values[arm]
            result.append(output_row(profile, LABELS[arm], values, baseline,
                                     ",".join(summary["arms"][arm]["sent_messages"]),
                                     "native" if arm == "full-ordinary" and native_values else "elision"))
        for name in ("MTC Standalone", "MTC Landmark"):
            if native_values:
                result.append(output_row(profile, name, native_values[name], baseline,
                                         "MTC", "native"))
    if len(image_ids) != 1:
        raise ValueError("Profiles used different compression images")
    if args.output.exists():
        raise ValueError(f"Output exists; use a new path: {args.output}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", newline="") as stream:
        writer = csv.DictWriter(stream, FIELDS)
        writer.writeheader()
        writer.writerows(result)
    print(f"PASS: {len(result)} Table I rows; image {next(iter(image_ids))}; "
          + ("native reference checked" if native_rows is not None else "X.509 only; native block pending"))


if __name__ == "__main__":
    main()
