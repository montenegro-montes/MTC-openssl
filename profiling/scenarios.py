"""Use previous scenario definitions without modifying their files."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
spec=importlib.util.spec_from_file_location('phase2_scenarios','/opt/compact/scenarios.py')
previous=importlib.util.module_from_spec(spec);spec.loader.exec_module(previous)
OPENSSL='/opt/profiling/openssl.sh'
previous.OPENSSL=OPENSSL
BATCH=previous.BATCH
SCENARIOS=previous.SCENARIOS+['classic-rpk','pq-rpk']
base=previous.base
pin_cache={}

def is_rpk(scenario):return '-compact-' in scenario or scenario.endswith('-rpk')

def pin(scenario):
    family=base(scenario)
    if family not in pin_cache:
        cert=Path('/work/certs')/family/'server.pem'
        public=subprocess.check_output(['/opt/openssl/bin/openssl','x509','-in',str(cert),'-pubkey','-noout'])
        spki=subprocess.check_output(['/opt/openssl/bin/openssl','pkey','-pubin','-outform','DER'],input=public)
        pin_cache[family]=hashlib.sha256(spki).hexdigest()
    return pin_cache[family]

def server_args(scenario,port):
    args=previous.server_args(base(scenario) if scenario.endswith('-rpk') else scenario,port)
    if scenario.endswith('-rpk'):args+=['-profile_rpk_only']
    return args+['-lab_metrics']

def client_args(scenario,host,port):
    args=previous.client_args(base(scenario) if scenario.endswith('-rpk') else scenario,host,port)
    if scenario.endswith('-rpk'):
        i=args.index('-CAfile');del args[i:i+2]
        args+=['-profile_rpk_only','-dane_tlsa_domain','server','-dane_tlsa_rrdata','3 1 1 '+pin(scenario)]
    return args
