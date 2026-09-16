"""Read-only adapters. Source values are never repaired or statistically aggregated."""
import csv
import hashlib
import json
from pathlib import Path

VERSION = '1.0.0'
RAW_NAMES = {'samples.csv','observations.csv','all-samples.csv'}
SUMMARY_NAMES = {'summary.csv','scenario-summary.csv','campaign-summary.csv','bootstrap-comparisons.csv','paired-comparisons.csv','paired-table.csv','main-table.csv','network-validation.csv','network-telemetry.csv','byte-decomposition.csv','retransmissions.csv'}

def leaves(value, prefix=''):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from leaves(item, f'{prefix}.{key}' if prefix else key)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from leaves(item, f'{prefix}[{index}]')
    else:
        yield prefix, value

def metric_records(value):
    if isinstance(value, dict):
        if any(k in value for k in ('handshake_wall_ms','tcp_connect_wall_ms_native','tcp_connect_wall_ms','connection_handshake_packets','transport_total_bytes')):
            yield value
        if isinstance(value.get('metrics'), dict):
            yield {**{k:v for k,v in value.items() if k != 'metrics'}, **value['metrics']}
        for key,item in value.items():
            if key != 'metrics': yield from metric_records(item)
    elif isinstance(value, list):
        for item in value:
            yield from metric_records(item)

def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()

def load(source):
    source=Path(source).resolve()
    if not source.is_dir(): raise ValueError('Results directory does not exist')
    model={'source':source,'documents':{},'tables':{},'inventory':[],'warnings':[],'metrics':[],'integrity':[]}
    for path in sorted(source.rglob('*')):
        if not path.is_file() or path.is_symlink(): continue
        name=str(path.relative_to(source))
        if path.suffix not in ('.json','.jsonl','.csv','.pcap','.md','.png','.pdf'): continue
        # All supported evidence artifacts are inventoried and hashed. Binary/document
        # presentation artifacts are preserved as provenance but are never parsed.
        model['inventory'].append({'artifact':name,'bytes':path.stat().st_size,'sha256':digest(path)})
        if path.name=='packets.csv' or path.suffix in ('.pcap','.md','.png','.pdf'): continue
        try:
            if path.suffix=='.csv':
                with path.open(newline='') as stream: data=list(csv.DictReader(stream))
                model['tables'][name]=data
                if path.name in RAW_NAMES: model['metrics'] += [(name,row) for row in data]
            else:
                data=json.loads(path.read_text()) if path.suffix=='.json' else [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
                model['documents'][name]=data
                if 'server-metrics/' not in name:
                    model['metrics'] += [(name,row) for row in metric_records(data)]
                for key,value in leaves(data):
                    terminal=key.rsplit('.',1)[-1]
                    if (terminal in ('passed','hash_match','association_valid','source_and_fixture_hashes_unchanged') and value is False) or (terminal.endswith('status') and terminal!='tls_status' and path.name!='tls-status.json'
                            and isinstance(value,str) and any(x in value.upper() for x in ('FAIL','ERROR'))):
                        model['warnings'].append(f'{name}: {key} = {value}')
                if path.name in ('capture-status.json','summary.json') and isinstance(data,dict) and data.get('pcap_sha256'):
                    pcap=path.parent/'handshakes.pcap'
                    actual=digest(pcap) if pcap.is_file() else None
                    check={'artifact':name,'expected_sha256':data['pcap_sha256'],'actual_sha256':actual,'hash_match':actual==data['pcap_sha256'] if actual else None}
                    model['integrity'].append(check)
                    if check['hash_match'] is False: model['warnings'].append(f'INTEGRITY FAILURE: {name} PCAP hash mismatch')
        except (ValueError,OSError) as error: model['warnings'].append(f'{name}: unreadable artifact: {error}')
    top={k:v for name,data in model['documents'].items() if '/' not in name and isinstance(data,dict) for k,v in data.items()}
    model['smoke']=top.get('integration_smoke_only') is True or 'integration-smoke' in source.parts
    model['flags']={k:top.get(k) for k in ('integration_smoke_only','scientific_measurement','performance_comparable','pcap_enabled')}
    if model['smoke'] and model['flags']['integration_smoke_only'] is None: model['flags']['integration_smoke_only']=True
    # Presence is labelled separately; never infer the experiment's pcap_enabled flag.
    model['keylog_available']=any(p.is_file() for pattern in ('*.keys','*.keylog') for p in source.rglob(pattern))
    model['pcap_present']=any('tcp_connect_wall_ms' in r or 'connection_handshake_packets' in r for _,r in model['metrics'])
    analysis=model['documents'].get('analysis_extended.json', {})
    crossover=(
        isinstance(analysis,dict)
        and analysis.get('result_domain')=='CERTIFICATE_SIZE_CROSSOVER'
    )
    model['adapter']=(
        'certificate-size-crossover' if crossover
        else 'integration-smoke' if model['smoke']
        else 'campaign-csv' if model['tables']
        else 'json-records'
    )
    execution=model['documents'].get('result.json', {})
    status=execution.get('status') if isinstance(execution,dict) else None
    if status in ('FAIL','FAILURE'): model['status']='FAILURE'
    elif model['warnings']: model['status']='PARTIAL / VALIDATION FAILURE'
    elif status in ('PASS','SUCCESS','COMPLETED'): model['status']='SUCCESS'
    elif status in ('FAIL','FAILURE'): model['status']='FAILURE'
    elif status in ('NOT_EXECUTED','NOT EXECUTED'): model['status']='NOT EXECUTED'
    elif isinstance(model['documents'].get('campaign-status.json'),dict):
        c=model['documents']['campaign-status.json'];model['status']='SUCCESS' if c.get('passed') is True else ('FAILURE' if c.get('passed') is False else 'PARTIAL')
    else: model['status']='PARTIAL — overall execution status not recorded'
    return model
