"""Offline identity/integrity accounting and paired statistics for Native/PCAP validation."""
import csv
import hashlib
import json
import math
import random
import re
import statistics
from pathlib import Path

BOOTSTRAP_SEED = 900009
BOOTSTRAP_RESAMPLES = 10000
PAIRS = [('tcp_connect_wall_ms_native','tcp_connect_wall_ms','native_minus_pcap_tcp_ms'),
         ('handshake_wall_ms','tls_from_pcap_wall_ms','native_minus_pcap_tls_ms'),
         ('connection_establishment_wall_ms_native','connection_handshake_wall_ms','native_minus_pcap_full_ms')]


def read_csv(path):
    if not path.is_file():return []
    with path.open() as handle:return list(csv.DictReader(handle))


def identity(row):
    try:
        result=(row['campaign_id'],int(row['round_id']),row['scenario'],int(row['is_warmup']))
        if int(row['round'])+1 != result[1] or int(row.get('order_in_round',1)) != 1:raise ValueError()
    except (KeyError,TypeError,ValueError) as error:raise RuntimeError('Invalid observation identity') from error
    if result[2]!='pq' or result[1]<1 or result[3] not in (0,1):raise RuntimeError('Invalid observation identity')
    return result


def unique(rows):
    result={}
    for row in rows:
        key=identity(row)
        if key in result:raise RuntimeError('Duplicate observation identity')
        result[key]=row
    return result


def numeric(value):
    try:result=float(value)
    except (ValueError,TypeError) as error:raise RuntimeError('Missing/non-numeric timing') from error
    if isinstance(value,bool) or not math.isfinite(result) or result<0:raise RuntimeError('Invalid timing')
    return result


def verify_capture(directory,row):
    folder=directory/row['artifact_directory']
    if not folder.resolve().is_relative_to((directory/'pcap').resolve()):raise RuntimeError('Invalid PCAP artifact path')
    observation=json.loads((folder/'observation.json').read_text())
    if identity(observation)!=identity(row):raise RuntimeError('PCAP observation identity mismatch')
    status=json.loads((folder/'capture-status.json').read_text())
    if status.get('status')!='SUCCESS':raise RuntimeError('Capture infrastructure failure')
    digest=hashlib.sha256((folder/'handshakes.pcap').read_bytes()).hexdigest()
    if digest!=status.get('pcap_sha256') or digest!=row.get('pcap_sha256'):raise RuntimeError('PCAP SHA mismatch')
    summary_path=folder/'summary.json'
    if row.get('analysis_status') in ('SUCCESS','PARTIAL'):
        summary=json.loads(summary_path.read_text())
        if summary.get('pcap_sha256')!=digest:raise RuntimeError('Extractor SHA mismatch')
        if len(summary.get('scenarios',[]))!=1 or summary['scenarios'][0]!=row.get('metrics'):raise RuntimeError('Extractor observation mismatch')
    return folder,digest


def collect(directory,condition,campaign_id,measured_rounds,warmup_rounds,failure_aware,preflight=False):
    good=read_csv(directory/'samples.csv');warm=read_csv(directory/'warmups.csv');failed=read_csv(directory/'failures.csv')
    all_rows=good+warm+failed;attempts=unique(all_rows)
    expected={(campaign_id,i+1,'pq',w) for w,n in [(0,measured_rounds),(1,warmup_rounds)] for i in range(n)}
    if set(attempts)!=expected:raise RuntimeError('Attempt accounting mismatch')
    if any(identity(r)[3] for r in good) or any(not identity(r)[3] for r in warm):raise RuntimeError('Warmup population mismatch')
    if failed and not failure_aware:raise RuntimeError('TLS failure outside failure-aware condition')
    if preflight and failed:raise RuntimeError('Preflight requires successful TLS warmup and measurement')
    pcaps=[json.loads(line) for line in (directory/'pcap-metrics.jsonl').read_text().splitlines() if line.strip()]
    pcap_by_id=unique(pcaps)
    measured_keys={key for key in expected if key[3]==0}
    if set(pcap_by_id)!=measured_keys:raise RuntimeError('PCAP attempt accounting mismatch')
    folders=list((directory/'pcap').glob('sample-*'))
    if len(folders)!=measured_rounds:raise RuntimeError('PCAP directory accounting mismatch')
    randoms=set();paired=[];partial=0;unavailable=0;unpairable=0
    for success in good+warm:
        value=success.get('client_random','')
        if not re.fullmatch('[0-9a-f]{64}',value) or value in randoms:raise RuntimeError('Missing/malformed/duplicate client_random')
        randoms.add(value)
    for failure in failed:
        value=failure.get('client_random')
        if value:
            if not re.fullmatch('[0-9a-f]{64}',value) or value in randoms:raise RuntimeError('Ambiguous failed client_random')
            randoms.add(value)
    for native in good:
        row=pcap_by_id[identity(native)]
        if row.get('tls_status') != 'SUCCESS':
            raise RuntimeError('Missing successful observation evidence: tls_status')

        if row.get('capture_status') != 'SUCCESS':
            raise RuntimeError('Missing successful observation evidence: capture_status')

        if row.get('analysis_status') != 'SUCCESS':
            if not failure_aware:
                raise RuntimeError('Missing successful observation evidence: analysis_status')

            # Under the failure-aware condition, a successful TLS handshake may
            # occasionally have an intact PCAP that cannot independently expose
            # the TLS Finished boundary (for example because tshark cannot
            # reconstruct/decrypt the complete handshake). Preserve the
            # observation as unpairable; never manufacture PCAP timing metrics.
            if row.get('analysis_status') != 'ANALYSIS_FAILURE':
                raise RuntimeError('Unexpected successful-TLS analysis status')

            verify_capture(directory, row)
            unpairable += 1
            continue
        if row.get('association_confidence')!='client_random' or row.get('client_random')!=native['client_random']:raise RuntimeError('Native/PCAP client_random mismatch')
        folder,digest=verify_capture(directory,row);metrics=row.get('metrics')
        if not isinstance(metrics,dict) or metrics.get('client_random')!=native['client_random']:raise RuntimeError('Extractor client_random mismatch')
        if type(metrics.get('tcp_stream')) is not int or metrics['tcp_stream']<0:raise RuntimeError('Invalid tcp_stream')
        entries=[line.split() for line in (folder/'tls.keys').read_text().splitlines() if line and not line.startswith('#')]
        if not entries or any(len(e)!=3 or e[1].lower()!=native['client_random'] for e in entries):raise RuntimeError('Keylog/client_random mismatch')
        result={k:native[k] for k in ['campaign_id','round_id','round','scenario','is_warmup','client_random']}
        result.update(condition=condition,tcp_stream=metrics['tcp_stream'],pcap_sha256=digest,association_valid=True,integrity_valid=True,tls_status='SUCCESS',capture_status='SUCCESS',analysis_status='SUCCESS')
        for n,p,d in PAIRS:
            result[n]=numeric(native.get(n));result[p]=numeric(metrics.get(p));result[d]=result[n]-result[p]
        for field in ['connection_handshake_packets','connection_handshake_tcp_payload_bytes','connection_handshake_ip_bytes','connection_handshake_frame_bytes','connection_handshake_retransmission_frames']:
            result[field]=metrics.get(field)
        paired.append(result)
    measured_failures=[r for r in failed if identity(r)[3]==0]
    for failure in measured_failures:
        row=pcap_by_id[identity(failure)]
        if row.get('tls_status')!='TLS_MEASUREMENT_FAILURE':raise RuntimeError('Failed TLS outcome mismatch')
        if row.get('capture_status')!='SUCCESS' or row.get('analysis_status') not in ('SUCCESS','PARTIAL'):
            # A connection that sends no packets cannot supply a PCAP; retain this
            # diagnostic, but never waive integrity/ambiguity errors on real captures.
            folder=directory/row['artifact_directory']
            status=json.loads((folder/'capture-status.json').read_text())
            error=status.get('error','')
            log=(folder/'tcpdump.log').read_text() if (folder/'tcpdump.log').is_file() else ''
            if (row.get('capture_status')=='CAPTURE_FAILURE' and error=='tcpdump did not record captured packets'
                and '0 packets captured' in log and '0 packets received by filter' in log
                and '0 packets dropped by kernel' in log and 'listening on eth0' in log
                and failure.get('tcp_connect_wall_ms_native') in (None,'')
                and failure.get('client_random') in (None,'')
                and (not (folder/'handshakes.pcap').exists() or (folder/'handshakes.pcap').stat().st_size<=24)):
                unavailable+=1
                continue
            raise RuntimeError('Failed-attempt infrastructure/analysis error: '+row.get('error','unavailable'))
        folder,digest=verify_capture(directory,row)
        random_value=failure.get('client_random')
        if random_value:
            if row.get('association_confidence')!='client_random' or row.get('client_random')!=random_value or row['metrics'].get('client_random')!=random_value:
                raise RuntimeError('Failed client_random association mismatch')
            entries=[line.split() for line in (folder/'tls.keys').read_text().splitlines() if line and not line.startswith('#')]
            if not entries or any(len(e)!=3 or e[1].lower()!=random_value for e in entries):raise RuntimeError('Failed keylog/client_random mismatch')
        elif row.get('association_confidence')!='observation_tuple_only':
            raise RuntimeError('Failed tuple association mismatch')
        if row.get('analysis_status')=='PARTIAL':
            partial+=1
            if any(row['metrics'].get(k) is not None for k in ['tls_from_pcap_wall_ms','connection_handshake_wall_ms','connection_handshake_tcp_payload_bytes','connection_handshake_ip_bytes','connection_handshake_frame_bytes']):raise RuntimeError('Fabricated incomplete TLS/full metrics')
    accounting=dict(measured_attempts=measured_rounds,warmup_attempts=warmup_rounds,successful_tls_observations=len(good),failed_tls_observations=len(measured_failures),successful_native_pcap_pairs=len(paired),incomplete_or_unpairable_observations=len(measured_failures)+unpairable,partial_analyses=partial,unavailable_captures=unavailable,warmup_successes=len(warm),warmup_failures=len(failed)-len(measured_failures))
    if len(good)+len(measured_failures)!=measured_rounds:raise RuntimeError('Measured accounting mismatch')
    return paired,accounting


def summarize(paired,condition,resamples=BOOTSTRAP_RESAMPLES,seed=BOOTSTRAP_SEED):
    if resamples!=10000:raise ValueError('Native/PCAP validation requires 10000 paired resamples')
    rows=[r for r in paired if r.get('condition')==condition and r.get('tls_status')=='SUCCESS'
          and r.get('association_valid') is True and r.get('integrity_valid') is True and int(r.get('is_warmup',0))==0]
    if len(rows)<2:raise RuntimeError('Too few successful pairs for bootstrap: '+condition)
    rng=random.Random(seed);boot={d:[] for _,_,d in PAIRS}
    # Resample one shared vector of observation indices for all three deltas.
    for _ in range(resamples):
        sample=[rows[rng.randrange(len(rows))] for _ in rows]
        for _,_,d in PAIRS:boot[d].append(statistics.median(r[d] for r in sample))
    result={}
    for _,_,d in PAIRS:
        values=[r[d] for r in rows]
        if any(not math.isfinite(v) for v in values):raise RuntimeError('Invalid bootstrap input')
        ordered=sorted(boot[d]);median=statistics.median(values)
        result[d]=dict(n_successful_pairs=len(rows),median_delta_ms=median,ci95_lower_ms=ordered[249],ci95_upper_ms=ordered[9749],bootstrap_seed=seed,bootstrap_resamples=resamples,bootstrap_unit='paired observation within condition')
    return result
