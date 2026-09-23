#!/usr/bin/env python3
import subprocess,sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[3]
raise SystemExit(subprocess.run([sys.executable,REPO/"campaigns/network/common/plots.py",*sys.argv[1:]]).returncode)
