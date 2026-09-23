#!/usr/bin/env python3
"""Preparation and preservation gate for the combined network campaign."""
import subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve();REPO=HERE.parents[3]
if len(sys.argv)!=3:raise SystemExit("usage: control.py init|tests|audit ROOT")
raise SystemExit(subprocess.run([sys.executable,REPO/"campaigns/network/common/control.py",sys.argv[1],sys.argv[2],"--experiment","network-combined"]).returncode)
