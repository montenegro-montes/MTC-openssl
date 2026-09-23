"""Run one isolated TLS 1.3 handshake per scenario and export key material."""
import argparse,datetime,json,subprocess,sys
from pathlib import Path

sys.path.insert(0,'/opt/measurement')
import scenarios as tls_scenarios
from config import SCENARIOS

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--scenarios',nargs='+',choices=SCENARIOS,default=SCENARIOS)
    args=parser.parse_args();keylog=args.output/'tls.keys';records=[]
    for scenario in args.scenarios:
        directory=args.output/'connections'/scenario;directory.mkdir(parents=True)
        port=4433+tls_scenarios.ALL_SCENARIOS.index(scenario)
        command=tls_scenarios.client_args(scenario,'server',port)+['-keylogfile',str(keylog)]
        started=datetime.datetime.now(datetime.timezone.utc).isoformat()
        result=subprocess.run(command,input='GET / HTTP/1.0\r\n\r\n',text=True,capture_output=True,timeout=30)
        log=result.stdout+result.stderr;(directory/'client.log').write_text(log)
        marker='MTC verification: OK' if '-mtc-experimental-' in scenario else ('Compact verification: OK' if '-compact-' in scenario else 'Verify return code: 0 (ok)')
        success=result.returncode==0 and 'New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384' in log and marker in log
        record={'scenario':scenario,'server_port':port,'started_utc':started,'finished_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'returncode':result.returncode,'verification_marker':marker,'passed':success}
        (directory/'connection.json').write_text(json.dumps(record,indent=2)+'\n');records.append(record)
        if not success:raise RuntimeError(f'Handshake validation failed: {scenario}')
    (args.output/'connections.json').write_text(json.dumps(records,indent=2)+'\n')
    print('PASS',len(records),'captured handshakes')
if __name__=='__main__':main()
