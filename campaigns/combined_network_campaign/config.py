"""Frozen design for the representative combined-network campaign."""
PROFILES = {
    "baseline": {"code": 0, "rtt_ms": 10, "half_delay_ms": 5, "rate_mbit": None, "loss_percent": "0"},
    "wan": {"code": 1, "rtt_ms": 50, "half_delay_ms": 25, "rate_mbit": 20, "loss_percent": "0.5"},
    "constrained": {"code": 2, "rtt_ms": 100, "half_delay_ms": 50, "rate_mbit": 5, "loss_percent": "1"},
    "adverse": {"code": 3, "rtt_ms": 100, "half_delay_ms": 50, "rate_mbit": 1, "loss_percent": "2"},
}
SCENARIOS = ["pq", "pq-rpk", "pq-compact-warm", "pq-compact-cold",
             "pq-mtc-experimental-landmark", "pq-mtc-experimental-standalone"]
PAIRS = [("pq-compact-warm", "pq"), ("pq-mtc-experimental-landmark", "pq"),
         ("pq-compact-warm", "pq-mtc-experimental-landmark"),
         ("pq-compact-cold", "pq"), ("pq-mtc-experimental-standalone", "pq"),
         ("pq-rpk", "pq")]
IMAGE = "mt-tls-network:latency"
BASE_IMAGE_ID = "sha256:4b04891fc50251a422c3357f35f355151ea50150d0e678dadde8c8f97b968b43"
TIMEOUT_SECONDS = 30
TBF_QUEUE_LATENCY_MS = 1000
def burst_bytes(rate_mbit): return max(1600, int(rate_mbit * 1_000_000 / 8 / 1000))
def seed(profile, campaign): return 400000 + PROFILES[profile]["code"] * 1000 + campaign
