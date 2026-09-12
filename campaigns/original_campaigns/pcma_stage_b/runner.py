"""Manual-only Docker bridge TLS runner. Imports never start containers."""
import csv
import datetime
import json
import os
from pathlib import Path
import platform
import random
import re
import subprocess
import sys
import time
import uuid

from design import ROOT,PROFILES,VERSION,digest,fixture_records,save

BIN='/opt/pcma-bin/pcma_tls'

def parse_metrics(log):
    found=re.findall(r'^PCMA_METRICS (\{.*\})$',log,re.M)
    if len(found)!=1:raise ValueError('exactly one native metrics record required')
    return json.loads(found[0])

def source_hashes():
    files=list((ROOT/'campaigns/original_campaigns/pcma_stage_b').rglob('*'))
    files += [ROOT/x for x in ('compact/compact.c','compact/compact.h','integration/mt_wire.c','integration/mt_wire.h','codigoOriginal/C/crypto/merkle.c','codigoOriginal/C/crypto/merkle.h','campaigns/original_campaigns/pcma/core.py','campaigns/original_campaigns/pcma/cache.py','campaigns/original_campaigns/pcma/workloads.py','campaigns/original_campaigns/pcma_stage_a2/formats.py','campaigns/original_campaigns/combined_network_campaign/network.py','campaigns/original_campaigns/combined_network_campaign/config.py')]
    return {str(p.relative_to(ROOT)):digest(p) for p in files if p.is_file() and '__pycache__' not in p.parts}

def command(args,**kw):
    return subprocess.run(args,text=True,capture_output=True,check=True,timeout=60,**kw).stdout

def execute(config,plan,output,capture=False):
    output=output.resolve()
    # Writable mount is limited to a new Stage-B directory under artifacts/results.
    relative=output.relative_to((ROOT/'artifacts/results').resolve())
    if output.exists():raise FileExistsError('choose a new output directory')
    fixtures=fixture_records(config,plan['cells'])
    output.mkdir(parents=True,exist_ok=False)
    project='pcmab'+uuid.uuid4().hex[:12]
    compose=['docker','compose','-p',project,'-f',str(ROOT/'campaigns/original_campaigns/pcma_stage_b/compose.yaml')]
    env=dict(os.environ,PCMA_IMAGE=config['image'])
    def docker(args):return command(compose+args,env=env)
    def inside(role,args):return docker(['exec','-T',role]+args)
    def remote(p):return '/work/results/'+str(p.resolve().relative_to((ROOT/'artifacts/results').resolve()))
    image=json.loads(command(['docker','image','inspect',config['image']]))[0]
    manifest=dict(version=VERSION,created_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  git_commit=command(['git','rev-parse','HEAD'],cwd=ROOT).strip(),source_sha256=source_hashes(),
                  config=config,plan=plan,fixtures=fixtures,image_id=image['Id'],image_created=image['Created'],
                  host=dict(system=platform.platform(),machine=platform.machine()),capture=capture,
                  wire=dict(extension='0xffa7',advertisement='PCA2/v1/ranges',proof='MTP2',bundle='PCB1'),
                  network_definitions={k:PROFILES[k] for k in {x['profile'] for x in plan['cells']}},
                  cache_commit='only after successful SSL_connect and authentication/control checks',
                  inference='campaign-level; independent cache reset per campaign/budget; warmups retained in progressive history')
    save(output/'manifest.json',manifest)
    # Exact leaf lists and arm order are frozen on disk before any handshake.
    orders={}
    for cell in plan['cells']:
        rng=random.Random(cell['seed']);order=[]
        for _ in cell['sequence']:
            indices=list(range(len(cell['arms'])));rng.shuffle(indices);order.append(indices)
        orders[cell['campaign_id']]=order
    save(output/'sequences.json',dict(cells=plan['cells'],arm_orders=orders))
    writer=None;raw=(output/'observations.csv').open('x',newline='');started=False
    try:
        docker(['up','-d']);started=True
        provenance={role:dict(version=inside(role,[BIN,'--version']).strip(),
                     build_inputs=json.loads(inside(role,['cat','/opt/pcma-bin/build-inputs.json'])),
                     binary_sha256=inside(role,['sha256sum',BIN]).split()[0],
                     openssl_commit=inside(role,['cat','/opt/openssl/SOURCE_COMMIT']).strip(),
                     openssl_build=inside(role,['/opt/openssl/bin/openssl','version','-a']),
                     library_sha256=inside(role,['sh','-c','sha256sum /opt/openssl/lib/libssl.so.3 /opt/openssl/lib/libcrypto.so.3']),
                     system=inside(role,['uname','-a'])) for role in ('client','server')}
        for endpoint in provenance.values():
            for name,value in endpoint['build_inputs'].items():
                if manifest['source_sha256'].get(name)!=value:raise ValueError('image/source freeze mismatch: '+name)
        save(output/'environment.json',dict(endpoints=provenance,containers=docker(['ps','--format','json'])))
        sys.path.insert(0,str(ROOT/'campaigns/original_campaigns/combined_network_campaign'))
        from network import commands,validate_qdisc
        for cell in plan['cells']:
            directory=output/cell['campaign_id'];directory.mkdir();logs=directory/'logs';logs.mkdir()
            profile=PROFILES[cell['profile']];qdisc={}
            for role in ('server','client'):
                if cell['profile']=='baseline':
                    subprocess.run(compose+['exec','-T',role,'tc','qdisc','del','dev','eth0','root'],env=env,capture_output=True,timeout=60)
                else:
                    for cmd in commands(profile):inside(role,cmd)
                actual=inside(role,['tc','-s','qdisc','show','dev','eth0'])
                if cell['profile']=='baseline':
                    if any(k in actual for k in ('netem','tbf')):raise ValueError('baseline has artificial impairment')
                else:validate_qdisc(actual,profile)
                qdisc[role]=actual
            save(directory/'network.json',qdisc)
            cap=None
            if capture:
                inside('client',['sh','-c','command -v tcpdump >/dev/null'])
                cap=subprocess.Popen(compose+['exec','-T','client','tcpdump','-U','-i','eth0','-s','0','-w',remote(directory/'capture.pcap'),'tcp','port','4433'],env=env,stdout=subprocess.DEVNULL,stderr=(directory/'capture.log').open('x'))
                time.sleep(.5)
                if cap.poll() is not None:raise RuntimeError('capture failed; no TLS attempted')
            try:
                for position,leaf in enumerate(cell['sequence'],1):
                    fixture=fixtures['trees'][str(cell['N'])]['leaves'][str(leaf)]
                    paths={k:'/work/'+v for k,v in fixture['paths'].items()}
                    for order,arm_index in enumerate(orders[cell['campaign_id']][position-1]):
                        arm=cell['arms'][arm_index];scenario=arm['scenario'];pcma=scenario=='pq-compact-pcma'
                        key=f'{position:04d}-{arm_index}';ready=directory/(key+'.ready');cache=directory/f"cache-{arm['budget_kb']}-{arm['policy']}.bin"
                        # Warm/PQ never call persistence; one file per PCMA budget in a campaign.
                        common=[fixture['hostname'],paths['cert'],paths['key'],paths['authority'],paths['bundle'],paths['root'],remote(cache),str(arm['budget_kb']*1024),arm['policy'],remote(ready)]
                        before=digest(cache) if cache.exists() else None
                        slog=logs/(key+'-server.log');clog=logs/(key+'-client.log')
                        server_stream=slog.open('x')
                        server=subprocess.Popen(compose+['exec','-T','server',BIN,'server',scenario,'0.0.0.0','4433']+common,env=env,stdout=server_stream,stderr=subprocess.STDOUT)
                        failure=None;client_result=None
                        try:
                            deadline=time.monotonic()+40
                            while not ready.exists():
                                if server.poll() is not None or time.monotonic()>deadline:raise RuntimeError('server readiness failed')
                                time.sleep(.02)
                            client_result=subprocess.run(compose+['exec','-T','client',BIN,'client',scenario,'server','4433']+common,env=env,text=True,capture_output=True,timeout=60)
                            clog.write_text(client_result.stdout+client_result.stderr)
                            server.wait(timeout=60)
                        except Exception as exc:
                            failure=type(exc).__name__+': '+str(exc)
                        finally:
                            if server.poll() is None:server.terminate();server.wait(timeout=10)
                            server_stream.close()
                        cm=sm={}
                        try:
                            cm=parse_metrics(clog.read_text());sm=parse_metrics(slog.read_text())
                        except Exception as exc:failure=failure or str(exc)
                        success=bool(not failure and cm.get('success') and sm.get('success') and client_result and client_result.returncode==0 and server.returncode==0)
                        row=dict(campaign_id=cell['campaign_id'],round=position-cell['warmup_rounds'],is_warmup=int(position<=cell['warmup_rounds']),sequence_position=position,leaf=leaf,hostname=fixture['hostname'],scenario=scenario,N=cell['N'],workload=cell['workload'],base_seed=config['base_seed'],seed=cell['seed'],cache_policy=arm['policy'],cache_budget=arm['budget_kb']*1024,network_profile=cell['profile'],order=order,root=fixtures['trees'][str(cell['N'])]['root'],success=success,failure=failure or '',client_metrics=json.dumps(cm,sort_keys=True),server_metrics=json.dumps(sm,sort_keys=True),cache_before_sha256=before or '',cache_after_sha256=digest(cache) if cache.exists() else '',client_log=str(clog.relative_to(output)),server_log=str(slog.relative_to(output)))
                        for field in ('wall_ms','cpu_ms','tls_read_bytes','tls_written_bytes','handshake_read_bytes','handshake_written_bytes','clienthello_bytes','certificate_bytes','certificate_verify_bytes','encrypted_extensions_bytes','advertisement_bytes','pcma_extension_bytes','credential_bytes','proof_bytes','normal_hashes','reused_hashes','transmitted_hashes','cache_nodes','cache_bytes','cache_hits','cache_misses','nodes_added','nodes_evicted','fallback_events','encode_ms','advertisement_parse_ms','range_lookup_ms','partial_construction_ms','cache_lookup_ms','reconstruction_ms','verification_ms','credential_verify_ms','tls_version','resumed','cipher','group','signature_nid'):
                            row[field]=cm.get(field)
                        row.update(server_cpu_ms=sm.get('cpu_ms'),server_advertisement_parse_ms=sm.get('advertisement_parse_ms') if pcma else None,
                                   server_range_lookup_ms=sm.get('range_lookup_ms') if pcma else None,server_partial_construction_ms=sm.get('partial_construction_ms') if pcma else None)
                        if success:
                            row['tls_total_bytes']=cm['tls_read_bytes']+cm['tls_written_bytes']
                            row['handshake_total_bytes']=cm['handshake_read_bytes']+cm['handshake_written_bytes']
                            row['server_authentication_bytes']=cm['encrypted_extensions_bytes']+cm['certificate_bytes']+cm['certificate_verify_bytes']
                            row['net_authentication_bytes']=cm['advertisement_bytes']+cm['proof_bytes'] if pcma else (cm['proof_bytes'] if scenario.endswith('warm') else None)
                            row['net_authentication_saving']=fixture['normal_proof_bytes']-row['net_authentication_bytes'] if pcma else None
                        else:
                            for f in ('tls_total_bytes','handshake_total_bytes','server_authentication_bytes','net_authentication_bytes','net_authentication_saving'):row[f]=None
                        if writer is None:writer=csv.DictWriter(raw,fieldnames=list(row));writer.writeheader()
                        writer.writerow(row);raw.flush()
                        if not success:raise RuntimeError('TLS attempt failed; preserved raw logs and row; campaign aborted')
            finally:
                if cap:
                    subprocess.run(compose+['exec','-T','client','pkill','-INT','tcpdump'],env=env,capture_output=True,timeout=60)
                    cap.wait(timeout=10)
            save(directory/'complete.json',dict(campaign_id=cell['campaign_id'],handshakes=len(cell['sequence'])*len(cell['arms'])))
            print(cell['campaign_id'],'complete',flush=True)
    finally:
        raw.close()
        if started:docker(['down','--remove-orphans'])
    # No completion marker exists for interrupted/failed campaigns.
    save(output/'complete.json',dict(version=VERSION,hashes={str(p.relative_to(output)):digest(p) for p in output.rglob('*') if p.is_file()},expected_handshakes=plan['expected_handshakes']))
