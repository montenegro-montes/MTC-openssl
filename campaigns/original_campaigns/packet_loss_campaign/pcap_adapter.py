"""Thin failure-aware loss adapter; all capture/extraction belongs to the shared core."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'common'))
from pcap_capture import capture_session as shared_session


def capture_session(compose, directory, env, enabled, observation_count):
    return shared_session(compose,directory,env,enabled,observation_count,allow_failed=True)
