"""Frozen experiment constants and deterministic identifiers."""
import os
LOSSES=['0','0.1','0.5','1','2','5']
LOSS_CODES={'0':0,'0.1':1,'0.5':5,'1':10,'2':20,'5':50}
AUTH_MODE = os.environ.get('NETWORK_AUTH_MODE', 'single')
PROFILE = os.environ.get('NETWORK_PROFILE', 'mldsa65')
SCENARIOS = ['x509-simple','mtc-single-landmark','mtc-single-standalone'] if AUTH_MODE == 'single' else ['x509-mutual','mtc-mutual-landmark','mtc-mutual-standalone']
PAIRS=[(SCENARIOS[1],SCENARIOS[0]),(SCENARIOS[2],SCENARIOS[0]),(SCENARIOS[2],SCENARIOS[1])]
RTT_MS=50
HANDSHAKE_TIMEOUT_SECONDS=30
IMAGE='mt-tls-network:local'
BASE_IMAGE='mt-tls-mtc:local'
def seed(loss,campaign):return 300000+LOSS_CODES[loss]*100+campaign
