"""Frozen experiment constants and deterministic identifiers."""
LOSSES=['0','0.1','0.5','1','2','5']
LOSS_CODES={'0':0,'0.1':1,'0.5':5,'1':10,'2':20,'5':50}
SCENARIOS=['pq','pq-rpk','pq-compact-warm','pq-compact-cold','pq-mtc-experimental-landmark','pq-mtc-experimental-standalone']
PAIRS=[('pq-compact-warm','pq'),('pq-mtc-experimental-landmark','pq'),('pq-compact-warm','pq-mtc-experimental-landmark'),('pq-compact-cold','pq'),('pq-mtc-experimental-standalone','pq'),('pq-compact-cold','pq-mtc-experimental-standalone'),('pq-rpk','pq')]
RTT_MS=50
HANDSHAKE_TIMEOUT_SECONDS=30
IMAGE='mt-tls-network:latency'
BASE_IMAGE_ID='sha256:4b04891fc50251a422c3357f35f355151ea50150d0e678dadde8c8f97b968b43'
def seed(loss,campaign):return 300000+LOSS_CODES[loss]*100+campaign
