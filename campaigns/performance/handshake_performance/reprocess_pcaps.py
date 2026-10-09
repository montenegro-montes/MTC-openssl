#!/usr/bin/env python3
"""Reanalyze retained handshake PCAPs into a new derived result directory."""
import argparse
import csv
import json
import math
from pathlib import Path
import statistics
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
sys.path.insert(0,str(HERE))
import pcap_handshake as pcap

IDENTITY=('profile','case','key_establishment','openssl_group','phase','repetition')

def require(condition,message):
    if not condition:raise ValueError(message)

def capture_directory(source,row):
    values=[source/'pcap'/f"{row['profile']}-{row['case']}-{row.get('phase','measured')}-{row['repetition']}",
            source/'pcap'/f"{row['profile']}-{row['case']}-{row['repetition']}"]
    found=[path for path in values if (path/'handshake.pcap').is_file() and (path/'keylog.txt').is_file()]
    require(len(found)==1,'missing or ambiguous retained capture for '+row['profile']+'/'+row['case']+'/'+row['repetition'])
    return found[0]

TSHARK_PREFERENCES=('tcp.desegment_tcp_streams','tls.desegment_ssl_records','tls.desegment_ssl_application_data')

def check_tshark(image):
    command=['docker','run','--rm','--network','none','--entrypoint','tshark',image,'-G','currentprefs']
    result=subprocess.run(command,capture_output=True,text=True)
    require(result.returncode==0,'unable to inspect tshark preferences')
    missing=[name for name in TSHARK_PREFERENCES if name not in result.stdout]
    require(not missing,'tshark lacks required preferences: '+', '.join(missing))

def tshark(capture,output,image,server_port='4433'):
    require(str(server_port).isdigit() and 1<=int(server_port)<=65535,'invalid recorded server port')
    command=['docker','run','--rm','--network','none','-v',f'{capture}:/capture:ro','--entrypoint','tshark',image,
             '-d',f'tcp.port=={server_port},tls','-o','tcp.desegment_tcp_streams:TRUE',
             '-o','tls.desegment_ssl_records:TRUE','-o','tls.desegment_ssl_application_data:TRUE',
             '-o','tls.keylog_file:/capture/keylog.txt','-r','/capture/handshake.pcap','-Y',f'tcp.port == {server_port}',
             '-T','fields','-E','separator=/t','-E','occurrence=a','-E','aggregator=,']
    for field in pcap.FIELDS:command.extend(('-e',field))
    result=subprocess.run(command,capture_output=True)
    output.write_bytes(result.stdout);(output.with_suffix('.stderr')).write_bytes(result.stderr)
    require(result.returncode==0,'tshark failed for '+str(capture))

def describe(values):
    n=len(values);mean=statistics.fmean(values);stdev=statistics.stdev(values) if n>1 else None
    return dict(n=n,mean=mean,sample_stdev=stdev,median=statistics.median(values),
                mean_95_ci_low=None if stdev is None else mean-1.96*stdev/math.sqrt(n),
                mean_95_ci_high=None if stdev is None else mean+1.96*stdev/math.sqrt(n))

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('source',type=Path);parser.add_argument('output',type=Path);parser.add_argument('--capture-image',default='mt-tls-capture:local');args=parser.parse_args()
    source=args.source.resolve();output=args.output.resolve()
    require(source.is_dir() and (source/'pcap.csv').is_file(),'SOURCE must contain pcap.csv')
    require(not output.exists(),'OUTPUT must not exist')
    require(output.is_relative_to((REPO/'artifacts/results').resolve()),'OUTPUT must be below artifacts/results')
    output.mkdir(parents=True);(output/'tshark').mkdir()
    rows=[]
    try:
        with (source/'pcap.csv').open(newline='') as stream:original=list(csv.DictReader(stream))
        source_summary=json.loads((source/'summary.json').read_text()) if (source/'summary.json').is_file() else {}
        check_tshark(args.capture_image)
        for index,row in enumerate(original,1):
            port=row.get('server_port') or row.get('port') or (source_summary.get('tls') or {}).get('port') or '4433'
            capture=capture_directory(source,row);tsv=output/'tshark'/f'{index:06d}.tsv';tshark(capture,tsv,args.capture_image,str(port))
            case=row['case'];kind='x509' if case.startswith('x509-') else ('mtc-landmark' if 'landmark' in case else 'mtc-standalone')
            result=pcap.analyze_safe(pcap.load_tsv(tsv),server_port=str(port),expect_client_certificate='-mutual' in case,credential_kind=kind)
            rows.append({**{key:row.get(key,'') for key in IDENTITY},**result,
                         'source_capture':str(capture.relative_to(source))})
        fields=(*IDENTITY,*pcap.METRIC_FIELDS,'source_capture')
        with (output/'pcap.csv').open('x',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader();writer.writerows(rows)
        measured=[row for row in rows if row.get('phase','measured')=='measured' and row['analysis_status']=='OK']
        key_establishment=source_summary.get('key_establishment') or {
            'id':original[0].get('key_establishment','unknown'),
            'label':original[0].get('key_establishment','unknown'),
            'openssl_group':original[0].get('openssl_group','unknown')}
        summary={'source_campaign':str(source),'derivation':'offline PCAP reprocessing; no TLS connections executed',
                 'key_establishment':key_establishment,
                 'x509_trust_path':source_summary.get('x509_trust_path'),
                 'definitions':source_summary.get('definitions',{}),'pcap':{}}
        for profile in sorted({row['profile'] for row in measured}):
            summary['pcap'][profile]={}
            for case in sorted({row['case'] for row in measured if row['profile']==profile}):
                group=[row for row in measured if row['profile']==profile and row['case']==case]
                summary['pcap'][profile][case]={'key_establishment':key_establishment,**{
                    metric:(describe(values) if (values:=[float(row[metric]) for row in group
                                                   if row.get(metric) not in (None,'')]) else None)
                    for metric in pcap.METRIC_FIELDS
                    if metric not in ('tcp_stream','client_random','analysis_status','analysis_error','authentication_components_status','authentication_components_error')}}
        (output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
        now=int(time.time())
        subprocess.run([sys.executable,str(REPO/'bin/renders/handshake-performance.py'),str(output/'summary.json'),
                        '--output',str(output/'report.html'),'--mode','run-pcap','--started-epoch',str(now),
                        '--ended-epoch',str(now),'--kem-id',str(key_establishment.get('id','unknown')),
                        '--kem-label',str(key_establishment.get('label','unknown')),
                        '--kem-group',str(key_establishment.get('openssl_group','unknown'))],check=True)
    except BaseException:
        (output/'FAILED').write_text('Derived output is incomplete; inspect retained stderr and rerun to a new directory.\n')
        raise
    print(output)

if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError,subprocess.SubprocessError) as error:
        print('ERROR: '+str(error),file=sys.stderr);raise SystemExit(1)
