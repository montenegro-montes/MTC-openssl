import importlib.util,os
from pathlib import Path
spec=importlib.util.spec_from_file_location('profile_scenarios','/opt/profiling/scenarios.py');previous=importlib.util.module_from_spec(spec);spec.loader.exec_module(previous)
OPENSSL='/opt/mtc/openssl.sh';previous.OPENSSL=OPENSSL;previous.previous.OPENSSL=OPENSSL
BATCH=previous.BATCH;MTC_BATCH=Path(os.environ.get('MTC_BATCH','/work/mtc/batch16-v2'))
SCENARIOS=previous.previous.SCENARIOS+[f'{family}-mtc-experimental-{mode}' for family in ['classic','pq'] for mode in ['standalone','landmark']]
OPTIONAL=['classic-rpk','pq-rpk'];base=previous.base;is_rpk=previous.is_rpk

def server_args(scenario,port):
    if '-mtc-experimental-' not in scenario:return previous.server_args(scenario,port)
    family=base(scenario);mode=scenario.rsplit('-',1)[1];directory=MTC_BATCH/family
    args=previous.server_args(family,port);i=args.index('-cert');args[i+1]=str(directory/f'{mode}-0000.pem')
    ident='32473.'+('1' if family=='classic' else '2')+('.1.1.1' if mode=='landmark' else '')
    return args+['-mtc_id',ident]
def client_args(scenario,host,port):
    if '-mtc-experimental-' not in scenario:return previous.client_args(scenario,host,port)
    args=previous.client_args(base(scenario),host,port);i=args.index('-CAfile');del args[i:i+2]
    return args+['-mtc_trust',str(MTC_BATCH/base(scenario)/('trust.bin' if scenario.endswith('-landmark') else 'authority.bin'))]+(['-mtc_landmark'] if scenario.endswith('-landmark') else [])
ALL_SCENARIOS=SCENARIOS+OPTIONAL
