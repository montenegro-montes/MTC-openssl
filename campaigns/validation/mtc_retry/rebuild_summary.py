"""Rebuild an MTC retry summary from an existing observations.jsonl."""

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run


def load_jsonl(path):
    rows = []

    with path.open() as handle:
        for line_number, line in enumerate(handle, 1):
            line = line.strip()

            if not line:
                continue

            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    f"Invalid JSON at {path}:{line_number}: {exc}"
                )

    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        type=Path,
        help="existing mtc-retry campaign root",
    )
    parser.add_argument(
        "--output",
        default="summary-paired.json",
        help="output filename inside campaign root",
    )

    args = parser.parse_args()

    root = args.root.resolve()
    observations = root / "observations.jsonl"

    if not observations.is_file():
        raise SystemExit(
            f"Missing observations: {observations}"
        )

    rows = load_jsonl(observations)

    summary = run.build_summary(rows)

    campaign_ids = {
        row["campaign_id"]
        for row in rows
    }

    if len(campaign_ids) != 1:
        raise SystemExit(
            f"Expected one campaign_id, found {campaign_ids}"
        )

    summary["campaign_id"] = next(iter(campaign_ids))

    design_path = root / "design.json"

    if design_path.is_file():
        design = json.loads(design_path.read_text())
        summary["mode"] = design.get("mode")

    output = root / args.output
    output.write_text(
        json.dumps(summary, indent=2) + "\n"
    )

    print(f"PASS: rebuilt summary from {len(rows)} observations")
    print(f"Output: {output}")


if __name__ == "__main__":
    main()
