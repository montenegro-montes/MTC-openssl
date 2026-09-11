"""Add campaign IDs and setup/byte accounting to the saved measurement driver.
The TLS protocol implementations and native handshake metric definitions stay fixed.
"""
import os,json,re
from pathlib import Path
import scenarios
warmup_rows=[]

def enrich(row,log,scenario):
    family=scenarios.base(scenario)
    compact='-compact-' in scenario
    mtc='-mtc-experimental-' in scenario
    warm=scenario.endswith('-warm')
    landmark=scenario.endswith('-landmark')
    cf=compact_metadata[family]
    root_file=scenarios.BATCH/family/'root.signed'
    ca_file=Path('/work/certs')/family/'ca.pem'
    directory=scenarios.MTC_BATCH/family
    row.update(campaign_id=os.environ['MEASUREMENT_CAMPAIGN_ID'],round_id=row['round']+1,seed=int(os.environ['MEASUREMENT_SEED']),
               order_in_round=row['order']+1,scenario_order=row['order']+1,
               rpk_spki_bytes=cf['leaf0_spki_bytes'] if compact or scenario.endswith('-rpk') else 0,
               compact_credential_bytes=cf['credential0_bytes'] if compact else 0,
               merkle_proof_bytes=cf['proof0_bytes'] if compact else 0,
               signed_root_bytes=root_file.stat().st_size if compact else 0,
               signed_root_tls_bytes=root_file.stat().st_size if compact and not warm else 0,
               root_setup_ms=None,root_validation_ms=None,setup_wall_ms=None,setup_cpu_ms=None,trust_validation_ms=None,
               mtc_proof_bytes=row['mtc_proof_encoded_bytes'],mtc_subtree_signature_bytes=row['mtc_signature_bytes'],
               mtc_landmark_bytes=(directory/'trust.bin').stat().st_size if landmark else 0,
               mtc_checkpoint_oob_bytes=0,trust_base_bytes=None,predistributed_bytes=None,predistributed_incremental_bytes=0,
               trust_cache='none; new process',trust_validation_scope='not measured')
    if compact or mtc:
        matches=re.findall(r'^MEASUREMENT_SETUP (\{.*\})$',log,re.M)
        if len(matches)!=1:raise RuntimeError('Missing setup CPU/wall instrumentation')
        setup=json.loads(matches[0])
        if setup['scheme']!=('compact' if compact else 'MTC-experimental'):raise RuntimeError('Setup scheme mismatch')
        if setup['setup_wall_ms']<0 or setup['setup_cpu_ms']<0:raise RuntimeError('Invalid setup clock')
        row.update(setup_wall_ms=setup['setup_wall_ms'],setup_cpu_ms=setup['setup_cpu_ms'])
    if compact:
        root_validation=re.findall(r'^ROOT_SIGNATURE_SETUP (\{.*\})$',log,re.M)
        row['root_setup_ms']=row['setup_wall_ms']
        row['trust_base_bytes']=ca_file.stat().st_size
        row['predistributed_incremental_bytes']=root_file.stat().st_size if warm else 0
        row['predistributed_bytes']=row['trust_base_bytes']+row['predistributed_incremental_bytes']
        if warm:
            if len(root_validation)!=1:raise RuntimeError('Missing warm root signature measurement')
            row['root_validation_ms']=json.loads(root_validation[0])['wall_ms']
            row['trust_validation_ms']=row['root_validation_ms']
            row['trust_validation_scope']='root signature operation only, before handshake, every process'
        else:row['trust_validation_scope']='root signature during handshake; not separately timed'
    elif mtc:
        row['trust_base_bytes']=(directory/'authority.bin').stat().st_size
        row['predistributed_bytes']=(directory/('trust.bin' if landmark else 'authority.bin')).stat().st_size
        row['predistributed_incremental_bytes']=row['predistributed_bytes']-row['trust_base_bytes']
        row['trust_validation_ms']=row['mtc_trust_validation_ms']
        row['trust_validation_scope']='checkpoint signatures before handshake, every process' if landmark else 'trust keys configured; subtree signatures during handshake'
        if landmark:
            blob=(directory/'trust.bin').read_bytes();checkpoint=row['trust_base_bytes']+4
            sig_offset=checkpoint+6+8+32
            row['mtc_checkpoint_oob_bytes']=6+8+32+2+int.from_bytes(blob[sig_offset:sig_offset+2],'big')
    elif not scenario.endswith('-rpk'):
        row['trust_base_bytes']=ca_file.stat().st_size;row['predistributed_bytes']=row['trust_base_bytes']
    return row

compact_metadata={f:json.loads((scenarios.BATCH/f/'manifest.json').read_text()) for f in ['classic','pq']}
source=Path('/opt/mtc/benchmark.py').read_text()
def once(a,b):
    global source
    if source.count(a)!=1:raise ValueError('Measurement source drift: '+a)
    source=source.replace(a,b,1)
start="out=Path('/work/results')/('mtc-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ'));out.mkdir();(out/'logs').mkdir();(out/'server-metrics').mkdir()"
once(start,"out=Path(os.environ['MEASUREMENT_RUN_ROOT'])/os.environ['MEASUREMENT_CAMPAIGN_ID'];out.mkdir(exist_ok=True);(out/'logs').mkdir();(out/'server-metrics').mkdir()")
once("Path('/work/results').glob('mtc-server-*/'+key+'.json')","out.glob('server-*/'+key+'.json')")
once("    if not warm:rows.append(row);write_csv(out/'samples.csv',rows)","    row=enrich(row,log,scenario)\n    row['is_warmup']=int(warm)\n    if warm:warmup_rows.append(row);write_csv(out/'warmups.csv',warmup_rows)\n    else:rows.append(row);write_csv(out/'samples.csv',rows)")
once("k not in ['round','order','tree_size']","k not in ['round','order','tree_size','seed','round_id','order_in_round','scenario_order','is_warmup']")
# The saved secondary summary infers numeric fields from one row. Some new setup
# fields are explicitly unavailable for X509/RPK: summarize them in the final
# campaign-level analyzer instead of coercing missing values to zero.
once("values=[r[metric] for r in group]","values=[r[metric] for r in group if r[metric] is not None]\n        if not values:continue")
once("write_csv(out/'summary.csv',summary)","write_csv(out/'summary.csv',[{k:r.get(k,'') for k in sorted({k for q in summary for k in q})} for r in summary])")
exec(compile(source,'saved-mtc-benchmark-with-measurement-accounting','exec'))
