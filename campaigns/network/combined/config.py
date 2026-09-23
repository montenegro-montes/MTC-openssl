"""Frozen design for the representative combined-network campaign."""
import os
PROFILES = {
    "baseline": {"code": 0, "rtt_ms": 10, "half_delay_ms": 5, "rate_mbit": None, "loss_percent": "0"},
    "wan": {"code": 1, "rtt_ms": 50, "half_delay_ms": 25, "rate_mbit": 20, "loss_percent": "0.5"},
    "constrained": {"code": 2, "rtt_ms": 100, "half_delay_ms": 50, "rate_mbit": 5, "loss_percent": "1"},
    "adverse": {"code": 3, "rtt_ms": 100, "half_delay_ms": 50, "rate_mbit": 1, "loss_percent": "2"},
}
AUTH_MODE = os.environ.get('NETWORK_AUTH_MODE', 'single')
PROFILE = os.environ.get('NETWORK_PROFILE', 'mldsa65')
SCENARIOS = ['x509-simple','mtc-single-landmark','mtc-single-standalone'] if AUTH_MODE == 'single' else ['x509-mutual','mtc-mutual-landmark','mtc-mutual-standalone']
PAIRS = [(SCENARIOS[1],SCENARIOS[0]),(SCENARIOS[2],SCENARIOS[0]),(SCENARIOS[2],SCENARIOS[1])]
IMAGE = "mt-tls-network:local"
BASE_IMAGE = "mt-tls-mtc:local"
TIMEOUT_SECONDS = 30
TBF_QUEUE_LATENCY_MS = 1000
def burst_bytes(rate_mbit): return max(1600, int(rate_mbit * 1_000_000 / 8 / 1000))
def seed(profile, campaign): return 400000 + PROFILES[profile]["code"] * 1000 + campaign
