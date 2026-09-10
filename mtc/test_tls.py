import sys,subprocess,tempfile,json
from pathlib import Path
sys.path.append('/opt/compact')
from scenarios import *
# Reuse the existing connection harness, not its credential implementation.
source=Path('/opt/compact/test_tls.py').read_text().split('with tempfile.TemporaryDirectory() as temp:')[0]
source=source.replace('from prepare import command, tree, bundle, dates', '')
source=source.replace('LAB_METRICS ','PROFILE_METRICS ')
source=source.replace("marker = 'Compact verification: OK'", "marker = 'MTC verification: OK' if '-mtc-experimental-' in scenario else 'Compact verification: OK'")
exec(compile(source,'compact-harness','exec'))
for family in ['classic','pq']:
    for mode in ['standalone','landmark']:
        scenario=family+'-mtc-experimental-'+mode
        with server(scenario) as port:
            test(scenario,scenario,port,True)
            test('wrong DNS',scenario,port,False,['-verify_hostname','wrong.invalid'])
            test('wrong trust',scenario,port,False,['-mtc_trust',MTC_BATCH/('pq' if family=='classic' else 'classic')/'trust.bin'])
            for flag in [['-reconnect'],['-psk','aa'],['-enable_server_rpk']]:test('incompatible '+flag[0],scenario,port,False,flag)
        with server(family) as port:test('no X509 fallback',scenario,port,False)
        with server(scenario,['-groups','P-256']) as port:test('HRR',scenario,port,True,['-groups','X25519:P-256'])
print('MTC TLS:',count,'PASS')
from mutations import signed_bad_constraints,malformed_proofs
from core import pem
with tempfile.TemporaryDirectory() as tmp:
    tmp=Path(tmp)
    for family in ['classic','pq']:
        directory=MTC_BATCH/family
        for mode in ['standalone','landmark']:
            scenario=family+'-mtc-experimental-'+mode
            variants=malformed_proofs((directory/f'{mode}-0000.der').read_bytes())
            if mode=='standalone':variants.update(signed_bad_constraints(directory,family,tmp))
            for label,value in variants.items():
                target=tmp/'case.pem';target.write_bytes(pem(value))
                with server(scenario,['-cert',target]) as port:test(family+' '+mode+' '+label,scenario,port,False)
        n=json.loads((directory/'manifest.json').read_text())['tree_size']
        if n>1:
            for mode in ['standalone','landmark']:
                scenario=family+'-mtc-experimental-'+mode
                with server(scenario,['-cert',directory/f'{mode}-{n-1:04d}.pem','-key',BATCH/family/'issued'/f'{n-1}.key']) as port:
                    test('last leaf, other subtree',scenario,port,True,['-verify_hostname',f'member-{n-1}.lab'])
print('MTC TLS including malformed and signed invalid credentials:',count,'PASS')
