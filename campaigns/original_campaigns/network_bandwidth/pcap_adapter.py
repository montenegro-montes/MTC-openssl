"""Bandwidth lifecycle uses the shared core; defaults retain success-only analysis."""
from pathlib import Path
import sys
import subprocess
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'common'))
from pcap_capture import (capture_session, save_status, FINALIZATION_SECONDS,
                          ANALYSIS_SECONDS_PER_OBSERVATION, STARTUP_MARGIN_SECONDS)
