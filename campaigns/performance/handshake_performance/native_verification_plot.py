#!/usr/bin/env python3
"""Plot non-overlapping client authentication verification timings."""
import argparse
import csv
import statistics
import warnings
from pathlib import Path

PROFILES = (
    "ecdsa-p256", "ecdsa-p384", "ecdsa-p521",
    "mldsa44", "mldsa65", "mldsa87",
    "slhdsa128s", "slhdsa192s", "slhdsa256s",
)
PROFILE_LABELS = (
    "ECDSA P-256", "ECDSA P-384", "ECDSA P-521",
    "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
    "SLH-DSA-128s", "SLH-DSA-192s", "SLH-DSA-256s",
)
CASES = ("x509", "landmark", "standalone")
CASE_LABELS = {"x509": "X.509 D3", "landmark": "MTC Landmark",
               "standalone": "MTC Standalone"}
COMPONENTS = (
    ("credential_other", "Other credential verification", "#1f77b4"),
    ("merkle", "Merkle proof", "#2ca02c"),
    ("landmark", "Landmark trust", "#ff7f0e"),
    ("standalone", "Standalone validation", "#9467bd"),
    ("certificate_verify", "CertificateVerify", "#d62728"),
)
ROUNDING_TOLERANCE_MS = 1e-6


def _number(row, field):
    value = row.get(field, "")
    return None if value in (None, "") else float(value)


def _case(value):
    if value.startswith("x509-simple"):
        return "x509"
    if value == "mtc-simple-landmark":
        return "landmark"
    if value == "mtc-simple-standalone":
        return "standalone"
    return None


def row_components(row):
    """Return exclusive components, accepting both historical and new CSVs."""
    credential = _number(row, "credential_verification_total_ms")
    legacy = _number(row, "x509_verification_ms")
    if credential is None:
        credential = legacy
    elif legacy is not None and abs(credential - legacy) > ROUNDING_TOLERANCE_MS:
        raise ValueError("credential_verification_total_ms differs from its "
                         "x509_verification_ms compatibility alias")
    if credential is None:
        raise ValueError("credential verification timing is unavailable")
    merkle = _number(row, "merkle_proof_ms") or 0.0
    landmark = _number(row, "landmark_validation_ms") or 0.0
    standalone = _number(row, "standalone_validation_ms") or 0.0
    other = credential - merkle - landmark - standalone
    if other < -ROUNDING_TOLERANCE_MS:
        warnings.warn(f"negative credential verification residual: {other:.9f} ms",
                      RuntimeWarning)
    certificate_verify = _number(row, "certificate_verify_ms")
    if certificate_verify is None:
        raise ValueError("CertificateVerify timing is unavailable")
    return {
        "credential_other": other,
        "merkle": merkle,
        "landmark": landmark,
        "standalone": standalone,
        "certificate_verify": certificate_verify,
        "credential_total": credential,
        "authentication_total": _number(
            row, "client_authentication_verification_total_ms"),
    }


def _outliers(values):
    """Return Tukey 1.5-IQR outliers for a directly measured interval."""
    if len(values) < 4:
        return []
    first, _, third = statistics.quantiles(values, n=4, method="inclusive")
    width = third - first
    low, high = first - 1.5 * width, third + 1.5 * width
    return [value for value in values if value < low or value > high]


def load_medians(path):
    with Path(path).open(newline="") as stream:
        rows = [row for row in csv.DictReader(stream)
                if row.get("phase") == "measured" and _case(row.get("case", ""))]
    grouped = {}
    for row in rows:
        key = (row.get("profile"), _case(row["case"]))
        grouped.setdefault(key, []).append(row_components(row))
    missing = [(profile, case) for profile in PROFILES for case in CASES
               if (profile, case) not in grouped]
    if missing:
        raise ValueError("missing measured profile/case cells: "
                         + ", ".join(f"{p}/{c}" for p, c in missing))
    result = {}
    for key, samples in grouped.items():
        result[key] = {
            name: statistics.median(sample[name] for sample in samples)
            for name, _, _ in COMPONENTS
        }
        totals = [sample["authentication_total"] for sample in samples
                  if sample["authentication_total"] is not None]
        result[key]["authentication_total"] = (
            statistics.median(totals) if totals else None)
        result[key]["authentication_outliers"] = _outliers(totals)
    return result


def render(input_csv, output_dir):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    data = load_medians(input_csv)
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    positions = []
    labels = []
    for profile_index, profile in enumerate(PROFILES):
        for case_index, case in enumerate(CASES):
            positions.append(profile_index * 4 + case_index)
            labels.append(CASE_LABELS[case])

    figure, (main, zoom) = plt.subplots(2, 1, figsize=(18, 10), sharex=True,
                                        gridspec_kw={"height_ratios": [3, 2]})
    bottoms = [0.0] * len(positions)
    for name, label, color in COMPONENTS:
        values = [data[(profile, case)][name]
                  for profile in PROFILES for case in CASES]
        main.bar(positions, values, bottom=bottoms, width=0.8,
                 color=color, label=label)
        bottoms = [bottom + value for bottom, value in zip(bottoms, values)]
    outlier_label = True
    for position, (profile, case) in zip(
            positions, ((profile, case) for profile in PROFILES for case in CASES)):
        values = data[(profile, case)]["authentication_outliers"]
        if values:
            main.scatter([position] * len(values), values, marker="x", color="black",
                         zorder=3, label="Total authentication outlier"
                         if outlier_label else None)
            outlier_label = False
    zoom_bottoms = [0.0] * len(positions)
    for name, label, color in COMPONENTS[1:4]:
        values = [data[(profile, case)][name]
                  for profile in PROFILES for case in CASES]
        zoom.bar(positions, values, bottom=zoom_bottoms, width=0.8,
                 color=color, label=label)
        zoom_bottoms = [bottom + value for bottom, value in zip(zoom_bottoms, values)]
    for axis in (main, zoom):
        axis.set_ylabel("Median time (ms)")
        axis.grid(axis="y", alpha=0.25)
    zoom.set_title("Expanded view: Merkle and Landmark/Standalone suboperations")
    main.set_title("Client authentication verification — component medians")
    main.legend(ncol=5, loc="upper center", bbox_to_anchor=(0.5, 1.18))
    zoom.set_xticks(positions)
    zoom.set_xticklabels(labels, rotation=55, ha="right", fontsize=8)
    for profile_index, label in enumerate(PROFILE_LABELS):
        zoom.text(profile_index * 4 + 1, -0.34, label,
                  transform=zoom.get_xaxis_transform(), ha="center", va="top",
                  fontsize=9, fontweight="bold")
    figure.text(0.5, 0.005,
                "Component medians are computed independently; their sum need not "
                "equal the median of the directly measured total interval.",
                ha="center", fontsize=9)
    figure.tight_layout(rect=(0, 0.07, 1, 0.97))
    png = output / "native-verification-components.png"
    pdf = output / "native-verification-components.pdf"
    figure.savefig(png, dpi=200, bbox_inches="tight")
    figure.savefig(pdf, bbox_inches="tight")
    plt.close(figure)
    return png, pdf


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path,
                        help="native.csv from mt-handshake-performance")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    png, pdf = render(args.input, args.output_dir)
    print(png)
    print(pdf)


if __name__ == "__main__":
    main()
