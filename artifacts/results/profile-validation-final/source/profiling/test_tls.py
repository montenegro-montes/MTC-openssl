"""Run the previous security suite against the instrumented implementation."""
import sys
from pathlib import Path
sys.path.append('/opt/compact')
source = Path('/opt/compact/test_tls.py').read_text()
source = source.replace('LAB_METRICS ', 'PROFILE_METRICS ')
source = source.replace("2 if '-compact-' in scenario else 0", "2 if ('-compact-' in scenario or scenario.endswith('-rpk')) else 0")
exec(compile(source, '/opt/compact/test_tls.py', 'exec'))
# A pinned key must reject mismatches and X509 fallback in both families.
original_client_args = client_args
for family in ['classic', 'pq']:
    scenario = family + '-rpk'
    with server(scenario) as port:
        def client_args(*args):
            values = original_client_args(*args)
            index = values.index('-dane_tlsa_rrdata') + 1
            values[index] = '3 1 1 ' + '00' * 32
            return values
        test(family + ' rejects wrong pin', scenario, port, False)
        def client_args(*args):
            values = original_client_args(*args)
            for flag in ['-dane_tlsa_rrdata', '-dane_tlsa_domain']:
                index = values.index(flag)
                del values[index:index+2]
            return values
        test(family + ' rejects missing pin', scenario, port, False)
        client_args = original_client_args
    with server(family) as port:
        test(family + ' pinned RPK rejects X509 fallback', scenario, port, False)
print('Profile TLS:', count, 'PASS')
