#!/usr/bin/env python3
"""Reject tracked private, raw, transient, or duplicated experiment artifacts."""
import subprocess
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
tracked = subprocess.check_output(["git", "ls-files", "artifacts"], cwd=repo, text=True).splitlines()
if tracked:
    raise SystemExit("Generated artifacts must not be tracked:\n" + "\n".join(tracked))
tracked = subprocess.check_output(["git", "ls-files", "results"], cwd=repo, text=True).splitlines()
bad = []
for name in tracked:
    path = Path(name); parts = set(path.parts); base = path.name
    if (parts & {"logs", "server-metrics", "source"} or
        base in {"samples.csv", "components.csv"} or
        path.suffix.lower() in {".log", ".key", ".pem", ".der", ".bin"}):
        bad.append(name)
if bad:
    raise SystemExit("Non-public artifacts are tracked:\n" + "\n".join(bad))
print(f"PASS: {len(tracked)} publication snapshot files tracked outside artifacts")
