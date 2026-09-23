"""Controlled-N16 compatibility entry point for the shared PCAP core."""
from pathlib import Path
import sys

COMMON = Path(__file__).resolve().parents[2]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
from common import pcap_capture as _core

# Preserve the historical ``import capture`` module identity so callers that
# patch lifecycle helpers continue to patch the shared implementation itself.
sys.modules['pcap_capture'] = _core
sys.modules[__name__] = _core
