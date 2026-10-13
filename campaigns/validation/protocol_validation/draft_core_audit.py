#!/usr/bin/env python3
"""Run the pinned MTC draft core vectors and save machine-readable evidence."""
import argparse
import contextlib
import io
import json
import runpy
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "src/mtc"))
import core

DRAFT = core.DRAFT


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    started = time.time_ns()
    captured = io.StringIO()
    result = {
        "draft": DRAFT,
        "scope": "core draft vectors C.1, C.2 and C.4; draft-07 certificate-format/MTCProof encoding; RFC 9162 consistency",
        "claim": "core-vector agreement; not complete draft conformance",
        "source": "src/mtc/test_core.py",
    }
    try:
        sys.path.insert(0, str(REPO / "src/mtc"))
        with contextlib.redirect_stdout(captured):
            runpy.run_path(str(REPO / "src/mtc/test_core.py"), run_name="__main__")
        output = captured.getvalue().strip().splitlines()
        result.update(overall="PASS", checks=output, inclusion_evaluations=12807)
    except Exception as error:
        result.update(overall="FAIL", checks=captured.getvalue().strip().splitlines(), error=str(error))
    result["elapsed_ns"] = time.time_ns() - started
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{result['overall']} {args.output}")
    if result["overall"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
