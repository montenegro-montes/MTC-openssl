"""Report byte and TLS timing results; check archived Landmark compatibility."""

import argparse
import csv
import json
from pathlib import Path
import statistics

from intermediate_elision import ARMS, percentile95


def pair(argument):
    try:
        profile, directory = argument.split("=", 1)
    except ValueError as error:
        raise argparse.ArgumentTypeError("Expected PROFILE=DIRECTORY") from error
    return profile, Path(directory)


def measured(directory, profile, case):
    rows = [r for r in csv.DictReader((directory / "native.csv").open())
            if r["profile"] == profile and r["case"] == case
            and r["phase"] == "measured"]
    if len(rows) != 100:
        raise ValueError(f"Expected 100 measured rows for {profile} {case}: {directory}")
    for row in rows:
        if int(row["tls_bytes_read"]) + int(row["tls_bytes_written"]) != int(row["tls_bytes_total"]):
            raise ValueError("Archived native byte counter mismatch")
    return rows


def byte_pair(rows):
    return (statistics.median(int(r["tls_bytes_read"]) for r in rows),
            statistics.median(int(r["tls_bytes_written"]) for r in rows))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--study", action="append", type=pair, required=True,
                        help="PROFILE=full four-arm result directory")
    parser.add_argument("--archive", action="append", type=pair, required=True,
                        help="PROFILE=archived native d3 directory")
    args = parser.parse_args()
    studies, archives = dict(args.study), dict(args.archive)
    if studies.keys() != archives.keys():
        parser.error("Every study profile needs one archived native directory")
    image_ids = {json.loads((directory / "config.json").read_text())["image_id"]
                 for directory in studies.values()}
    if len(image_ids) != 1:
        raise ValueError("Study profiles used different image IDs")
    for profile in studies:
        study, archive = studies[profile], archives[profile]
        config = json.loads((study / "config.json").read_text())
        result = json.loads((study / "summary.json").read_text())
        native_summary = json.loads((archive / "summary.json").read_text())
        if config["profile"] != profile or config["hostname"] != "server" \
                or config["openssl_group"] != "X25519MLKEM768" \
                or config["tls_version"] != "TLS1.3" or config["x509_depth"] != 3:
            raise ValueError(f"Study configuration mismatch: {profile}")
        if not result["reference_match"] or result["image_id"] != config["image_id"]:
            raise ValueError(f"Study reference or image mismatch: {profile}")
        if native_summary["key_establishment"]["openssl_group"] != "X25519MLKEM768" \
                or native_summary["x509_trust_path"]["depth_including_root"] != 3:
            raise ValueError(f"Archived native configuration mismatch: {profile}")
        bindings = native_summary["x509_trust_path"]["fixtures"]["bindings"]
        if not any(item["profile"] == profile and item["role"] == "server"
                   and item["path"] == config["fixture"] for item in bindings):
            raise ValueError(f"Archived X.509 chain differs: {profile}")
        x509 = measured(archive, profile, "x509-simple-d3")
        landmark = measured(archive, profile, "mtc-simple-landmark")
        standalone = measured(archive, profile, "mtc-simple-standalone")
        baseline_pair = (result["arms"]["full-ordinary"]["tls_bytes_read_median"],
                         result["arms"]["full-ordinary"]["tls_bytes_written_median"])
        archived_pair = byte_pair(x509)
        if archived_pair != baseline_pair:
            if profile != "ecdsa-p384" or archived_pair[1] != baseline_pair[1] \
                    or abs(archived_pair[0] - baseline_pair[0]) > 1:
                raise ValueError(f"Archived and study X.509 counters differ by direction: {profile}")
            print("P-384 read-byte median differs by one byte; ECDSA DER signature length varies.")
        print(f"\n{profile}: study image {config['image_id']}")
        print(f"Reference check: {result['reference_status']}")
        print(f"Study CSV: {study / 'samples.csv'}")
        print(f"Landmark archive CSV (separate measurement block): {archive / 'native.csv'}")
        print("arm | read B | written B | total B | handshake median ms | p95 ms | sent message")
        for arm in ARMS:
            data = result["arms"][arm]
            print(f"{arm} | {data['tls_bytes_read_median']:g} | "
                  f"{data['tls_bytes_written_median']:g} | "
                  f"{data['tls_bytes_total_median']:g} | "
                  f"{data['handshake_wall_ms_median']:.3f} | "
                  f"{data['handshake_wall_ms_p95']:.3f} | "
                  f"{','.join(data['sent_messages'])}")
        for name, rows in (("MTC Standalone", standalone), ("MTC Landmark", landmark)):
            read, written = byte_pair(rows)
            times = [float(r["handshake_wall_ms"]) for r in rows]
            print(f"{name} [archive] | {read:g} | {written:g} | "
                  f"{read + written:g} | {statistics.median(times):.3f} | "
                  f"{percentile95(times):.3f} | separate block")
        landmark_read, landmark_written = byte_pair(landmark)
        landmark_total = landmark_read + landmark_written
        standalone_read, standalone_written = byte_pair(standalone)
        standalone_total = standalone_read + standalone_written
        full_total = result["arms"]["full-ordinary"]["tls_bytes_total_median"]
        elided_total = result["arms"]["elided-ordinary"]["tls_bytes_total_median"]
        print(f"Standalone saving vs full X.509: "
              f"{100 * (full_total - standalone_total) / full_total:.2f}%")
        print(f"Intermediate omission vs full X.509: {result['intermediate_elision_savings_pct']:.2f}%")
        print(f"Additional Landmark saving vs elided X.509: "
              f"{100 * (elided_total - landmark_total) / elided_total:.2f}%")
        print("Timing blocks are independent; archived MTC image ID was not recorded in the native CSV.")


if __name__ == "__main__":
    main()
