"""Use the saved protocol scenario definitions with one measurement executable."""
import importlib.util
spec=importlib.util.spec_from_file_location('mtc_scenarios','/opt/mtc/scenarios.py')
previous=importlib.util.module_from_spec(spec);spec.loader.exec_module(previous)
OPENSSL='/opt/paper/openssl.sh'
previous.OPENSSL=OPENSSL
previous.previous.OPENSSL=OPENSSL
previous.previous.previous.OPENSSL=OPENSSL
ALL_SCENARIOS=previous.ALL_SCENARIOS
SCENARIOS=ALL_SCENARIOS
BATCH=previous.BATCH
MTC_BATCH=previous.MTC_BATCH
base=previous.base
is_rpk=previous.is_rpk
client_args=previous.client_args
server_args=previous.server_args
