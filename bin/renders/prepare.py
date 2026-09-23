#!/usr/bin/env python3
"""Create a plain-language, action-specific report for mt-prepare."""
import argparse
import datetime as dt
import html
import json
import platform
import shlex
from pathlib import Path


IMAGES = (
    (1, "mt-tls-lab:local", "Base TLS/X.509 environment and cryptographic tools"),
    (2, "mt-tls-mtc:local", "Experimental MTC TLS implementation"),
    (3, "mt-tls-capture:local", "Packet capture and protocol inspection tools"),
)


def esc(value):
    return html.escape(str(value))


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def read_env(path):
    values = {}
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return values
    for line in lines:
        if not line or line.lstrip().startswith("#") or "=" not in line:
            continue
        key, raw = line.split("=", 1)
        try:
            parsed = shlex.split(raw)
        except ValueError:
            continue
        if len(parsed) == 1:
            values[key] = parsed[0]
    return values


def table(headers, rows):
    head = "".join(f"<th>{esc(item)}</th>" for item in headers)
    body = "".join("<tr>" + "".join(f"<td>{esc(item)}</td>" for item in row) + "</tr>" for row in rows)
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--action", choices=("init", "run", "rebuild"), required=True)
    parser.add_argument("--selection", required=True)
    parser.add_argument("--started-epoch", type=int, required=True)
    parser.add_argument("--ended-epoch", type=int, required=True)
    parser.add_argument("--exit-code", type=int, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    repo = args.repo.resolve()
    events = []
    try:
        for line in args.events.read_text().splitlines():
            stage, image, outcome, dockerfile = line.split("\t", 3)
            events.append({"stage": int(stage), "image": image, "outcome": outcome, "dockerfile": dockerfile})
    except (OSError, ValueError):
        pass

    cert_config = repo / ".mt-state/cert-scaling/paths.env"
    protocol_config = repo / ".mt-state/protocol-validation/paths.env"
    paths = read_env(cert_config)
    fixture_root = Path(paths["MTC16"]) if paths.get("MTC16") else None
    validation_file = Path(paths["MTC_VALID"]) / "validation.json" if paths.get("MTC_VALID") else None
    validation = read_json(validation_file) if validation_file else None
    validation_pass = bool(validation and validation.get("passed") is True)
    configs_ready = cert_config.is_file() and protocol_config.is_file()

    expected = {
        "init": "Initialize or preserve launcher configuration; do not build images or generate fixtures.",
        "run": "Prepare the image chain through the requested stage, reusing existing images.",
        "rebuild": "Rebuild the requested stage; with ALL, rebuild all three images.",
    }[args.action]
    if args.selection == "ALL":
        expected += " Then prepare the N=16 MTC fixtures and check their functional TLS validation."

    passed = args.exit_code == 0 and configs_ready
    if args.selection == "ALL":
        passed = passed and bool(fixture_root and (fixture_root / "manifest.json").is_file()) and validation_pass
    outcome = "PASS" if passed else "NO PASS"
    started = dt.datetime.fromtimestamp(args.started_epoch, dt.timezone.utc)
    ended = dt.datetime.fromtimestamp(args.ended_epoch, dt.timezone.utc)
    host = {"system": platform.system(), "release": platform.release(), "machine": platform.machine(), "python": platform.python_version()}
    summary = {
        "campaign": "mt-prepare",
        "action": args.action,
        "selection": args.selection,
        "status": outcome,
        "exit_code": args.exit_code,
        "expected": expected,
        "stages": events,
        "configuration": {"cert_scaling": cert_config.is_file(), "protocol_validation": protocol_config.is_file()},
        "fixtures": {
            "required": args.selection == "ALL",
            "root": str(fixture_root) if fixture_root else None,
            "manifest": bool(fixture_root and (fixture_root / "manifest.json").is_file()),
            "functional_validation": validation_pass,
        },
        "execution": {"started_utc": started.isoformat(), "ended_utc": ended.isoformat(), "elapsed_seconds": max(0, args.ended_epoch - args.started_epoch), "host": host},
    }
    args.result.parent.mkdir(parents=True, exist_ok=True)
    args.result.write_text(json.dumps(summary, indent=2) + "\n")

    action_text = {
        "init": "The persistent configuration was checked and only missing files were created.",
        "run": "The required image chain was prepared, reusing each image that was already available.",
        "rebuild": "An explicit rebuild was requested; the recorded stages show what was rebuilt or reused.",
    }[args.action]
    rows = []
    observed = {event["stage"]: event["outcome"] for event in events}
    limit = 3 if args.selection == "ALL" else (int(args.selection) if args.selection.isdigit() else 0)
    for stage, image, purpose in IMAGES:
        if stage <= limit:
            rows.append((stage, image, purpose, observed.get(stage, "sin completar")))
    if not rows:
        rows = [("—", "None", "init neither builds nor inspects Docker images", "not applicable")]

    config_rows = [
        ("mt-cert-scaling configuration", "ready" if cert_config.is_file() else "missing"),
        ("mt-protocol-validation configuration", "ready" if protocol_config.is_file() else "missing"),
    ]
    fixture_rows = [
        ("N=16 fixtures required", "yes" if args.selection == "ALL" else "no"),
        ("Fixture manifest", "present" if summary["fixtures"]["manifest"] else "missing/not required"),
        ("Functional TLS validation", "PASS" if validation_pass else "missing/not required"),
    ]
    execution_rows = [("Start UTC", summary["execution"]["started_utc"]), ("End UTC", summary["execution"]["ended_utc"]), ("Duration", f'{summary["execution"]["elapsed_seconds"]} s'), ("Computer", f'{host["system"]} {host["release"]} {host["machine"]}'), ("Exit code", args.exit_code)]
    color = "pass" if outcome == "PASS" else "fail"
    report = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>MTC/TLS preparation</title><style>body{{font:16px system-ui;background:#f3f6fa;color:#172033;margin:0}}main{{max-width:1050px;margin:auto;padding:28px}}header,section{{background:#fff;border:1px solid #dbe3ed;border-radius:12px;padding:22px;margin:16px 0}}h1{{margin:.2em 0}}h2{{font-size:20px}}.result{{font-size:26px;font-weight:800}}.pass{{color:#087443}}.fail{{color:#b42318}}.note{{background:#eef5ff;padding:14px;border-left:5px solid #3974c6}}table{{border-collapse:collapse;width:100%}}th,td{{padding:10px;border-bottom:1px solid #ddd;text-align:left}}th{{background:#edf2f7}}.scroll{{overflow:auto}}</style></head><body><main><header><p>Explained preparation report</p><h1>mt-prepare: {esc(args.action)} {esc(args.selection)}</h1><p class="result {color}">{outcome}</p><p>{esc(expected)}</p></header><section><h2>What was executed</h2><p>{esc(action_text)}</p>{table(("Stage", "Image", "Purpose", "Result"), rows)}</section><section><h2>Configuration</h2>{table(("Component", "Status"), config_rows)}</section><section><h2>Fixtures and validation</h2>{table(("Check", "Result"), fixture_rows)}<p class="note">Numbered stages prepare images only. Fixture generation and functional TLS validation are performed only with ALL.</p></section><section><h2>What the result means</h2><p><strong>{outcome}</strong>: the command {'finished and produced the outputs required for this case' if passed else 'did not finish successfully or a required output is missing'}.</p><p class="note">Duration measures preparation and may include compilation, cache use, configuration, generation, and validation. It cannot compare X.509 and MTC handshake performance.</p></section><section><h2>Time and computer</h2>{table(("Field", "Value"), execution_rows)}</section></main></body></html>'''
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(report)
    print(f"JSON: {args.result}")
    print(f"HTML: {args.output}")


if __name__ == "__main__":
    main()
