#!/usr/bin/env python3
"""Manual MTC validation runner for the current experimental draft."""
import subprocess,sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[3]
def main():
 workflow=REPO/"campaigns/scaling/mtc_profile_scaling/workflow.py"
 subprocess.run([sys.executable,str(workflow),"validate",*sys.argv[1:]],check=True)
if __name__=="__main__":main()
