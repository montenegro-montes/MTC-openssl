#!/usr/bin/env python3
"""Read-only empirical reference audit and exact landmark-size crossover model.

No OpenSSL, Docker, TLS, tree generation or performance execution is invoked.
"""
import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import statistics

from landmark_size_model import audit, model, crossover, intervals, MAXIMUM_SUPPORTED_N, IMPLEMENTATION_LIMIT, require
from size_analysis import tls_certificate_message_size, REPO
from config import PROFILES
from core import certificate_parts, DRAFT
from crypto_profiles import SIGNATURE_PROFILES, TREE_SIZES


EFFECTIVE_THRESHOLDS_PCT = (1, 5, 10)


def effective_crossover(tbs, x509_bytes, pct):
    """Largest integer N preserving at least pct percent X.509 byte saving.

    Required condition:

        (X509 - MTC(N)) / X509 >= pct / 100

    Because message sizes are integer bytes, this is equivalent to:

        MTC(N) <= floor(X509 * (100 - pct) / 100)

    The existing crossover() helper finds the first integer N for which
    MTC(N) >= target. Searching target=max_mtc_bytes+1 therefore gives
    the first N that violates the requested practical margin.
    """

    require(
        isinstance(pct, int) and 0 < pct < 100,
        'invalid effective crossover percentage'
    )

    max_mtc_bytes = x509_bytes * (100 - pct) // 100
    failure = crossover(tbs, max_mtc_bytes + 1)

    if failure['status'] == 'CROSSED':
        first_fail_n = failure['crossover_N']

        if first_fail_n == 1:
            return dict(
                status='NO_N_WITH_REQUIRED_MARGIN',
                max_advantage_N='',
                first_fail_N=1,
                max_mtc_bytes=max_mtc_bytes,
            )

        return dict(
            status='CROSSED',
            max_advantage_N=first_fail_n - 1,
            first_fail_N=first_fail_n,
            max_mtc_bytes=max_mtc_bytes,
        )

    return dict(
        status='PRESERVED_THROUGH_PROTOCOL_RANGE',
        max_advantage_N=MAXIMUM_SUPPORTED_N,
        first_fail_N='',
        max_mtc_bytes=max_mtc_bytes,
    )


class Inputs:
    def __init__(self):
        self.hashes = {}
    def read(self,path):
        path=Path(path);data=path.read_bytes();key=str(path.resolve())
        digest=hashlib.sha256(data).hexdigest()
        require(key not in self.hashes or self.hashes[key]==digest,'input changed during analysis')
        self.hashes[key]=digest
        return data
    def json(self,path):return json.loads(self.read(path))
    def csv(self,path):return list(csv.DictReader(io.StringIO(self.read(path).decode())))
    def unchanged(self):
        for name,value in self.hashes.items():
            require(hashlib.sha256(Path(name).read_bytes()).hexdigest()==value,'input changed: '+name)
    def manifest_files(self,directory,hashes):
        for name,expected in hashes.items():
            p=Path(name)
            require(not p.is_absolute() and '..' not in p.parts,'unsafe manifest path')
            require(hashlib.sha256(self.read(directory/p)).hexdigest()==expected,'fixture hash mismatch: '+str(directory/p))


def write_csv(path,rows):
    with path.open('x',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)


def empirical(inputs,root,profile,depth,fixture_hash,static,mtc_provenance):
    result=dict(measured_tls_x509_bytes='',difference_bytes='',compatible=False,
                selected_reference_bytes=static,selected_reference_source='static X.509 fixture',
                TLS_signature_supported=False,explanation='No TLS measurement root supplied')
    if root is None:return result
    try:
        summary=inputs.csv(root/'summary.csv')
        matches=[r for r in summary if r['scenario']==f'{profile}-d{depth}']
        require(len(matches)==1,'no unique TLS summary row')
        row=matches[0];measured=float(row['certificate_message_bytes_median_of_campaign_medians'])
        result.update(measured_tls_x509_bytes=measured,difference_bytes=measured-static)
        require(row['TLS_signature_supported'] in ('True','true','1'),'TLS unsupported in recorded summary')
        m=inputs.json(root/'manifest.json');env=inputs.json(root/'environment.json')
        frozen=inputs.json(root/'fixture_hashes.json')
        require(frozen.get(f'{profile}/depth-{depth}/manifest.json')==fixture_hash,'TLS/static fixture manifest hashes differ; cannot mix fixtures')
        require(m['image_id']==env['image_id'],'TLS image metadata mismatch')
        require(mtc_provenance['source_commits']==env['source_commits'],'MTC/TLS cryptographic source revisions differ')
        require(mtc_provenance['liboqs_version']==env['versions']['liboqs'],'MTC/TLS liboqs versions differ')
        medians=[]
        for campaign in range(1,m['campaigns']+1):
            name=f'{profile}-d{depth}-c{campaign}'
            candidates=[root/name,*sorted(root.glob('resume/*/cells/'+name))]
            complete=[]
            for candidate in candidates:
                if (candidate/'data/validation.json').is_file():
                    status=inputs.json(candidate/'data/validation.json')
                    if status.get('passed') is True:complete.append((candidate,status))
            require(len(complete)==1,'no unique completed TLS cell: '+name)
            directory,status=complete[0]
            obs=inputs.csv(directory/'data/observations.csv')
            require(len(obs)==m['repetitions']==status['measured_handshakes'],'wrong completed observation count')
            for r in obs:
                require(r['success']=='1' and r['is_warmup']=='0','unsuccessful/nonmeasurement TLS row')
                require(r['scenario']==f'{profile}-d{depth}' and r['campaign']==name,'TLS cell identity mismatch')
                require(r['fixture_hash']==fixture_hash and r['image_id']==m['image_id'],'TLS row provenance mismatch')
            values=[int(r['certificate_message_bytes']) for r in obs]
            require(all(v==static for v in values),'observed Certificate bytes differ despite matching fixture manifest; investigate framing before using TLS reference')
            medians.append(statistics.median(values))
        require(statistics.median(medians)==measured,'summary differs from completed raw Certificate observations')
        require(measured==static,'static and TLS Certificate message boundary differs')
        result.update(compatible=True,selected_reference_bytes=int(measured),
                      selected_reference_source='real TLS Certificate message',TLS_signature_supported=True,
                      explanation='Identical static/TLS fixture hashes; completed observation bytes reproduce summary and static serialization. MTC uses its separate same-profile N16 anchor with matching cryptographic source revisions.')
    except (ValueError,KeyError,OSError,TypeError) as error:
        result['explanation']=str(error)+'; consistent static reference retained'
    return result


def run(a):
    require(not a.output.exists(),'Output exists; choose a fresh directory')
    missing = [str(a.baseline / name) for name in ('chain_sizes.csv', 'mtc_sizes.csv')
               if not (a.baseline / name).is_file()]
    if missing:
        raise SystemExit('Missing N=16 baseline: ' + ', '.join(missing)
                         + '. Run bin/cryptographic_scaling/mt-cert-scaling run 80 first '
                         'or supply --baseline pointing to its complete matching output. '
                         'Preserve any incomplete output; do not overwrite it.')
    inputs=Inputs();breakdowns=[];anchors={};provenance={};validation=[]
    gate=inputs.json(a.mtc_validation)
    expected={(name,mode) for name in PROFILES for mode in ('landmark','standalone')}
    require(gate.get('passed') is True and len(gate.get('cells',[]))==18 and {(r['profile'],r['mtc_mode']) for r in gate['cells']}==expected, 'N16 validation must cover nine profiles and both modes')
    require(all(r.get('tree_size')==16 and r.get('success') is True and r.get('handshakes')==1 for r in gate['cells']), 'incomplete N16 functional validation')
    inputs.manifest_files(a.mtc_fixtures,gate['fixture_hashes'])
    old=inputs.csv(a.baseline/'chain_sizes.csv')
    old_mtc=inputs.csv(a.baseline/'mtc_sizes.csv')
    for file in a.baseline.rglob('*'):
        if file.is_file():inputs.read(file)
    for profile in PROFILES:
        directory=a.mtc_fixtures/'batch16/mtc'/profile
        meta=inputs.json(directory/'manifest.json')
        require(meta['tree_size']==16 and meta['draft']==DRAFT and meta['merkle_hash']=='SHA-256','wrong N16/draft/hash anchor')
        for key in ('profile','ca_id','standard_name','implementation_algorithm','security_level'):
            require(meta[key]==SIGNATURE_PROFILES[profile][key],'MTC profile mismatch')
        require(meta['provenance']['image_id']==gate['provenance']['image_id'], 'N16 image/gate mismatch')
        for name in ('src/mtc/core.py','src/mtc/tls.c','src/mtc/mtc.c'):
            require(hashlib.sha256(inputs.read(REPO/name)).hexdigest()==meta['provenance']['source_hashes'][name], 'serializer/native semantics differ from validated anchor')
        inputs.manifest_files(directory,inputs.json(directory/'fixture-sha256.json'))
        raw=inputs.read(directory/'landmark-0000.der');tbs,b=audit(raw)
        old_rows=[r for r in old_mtc if r['algorithm']==profile and r['mtc_profile']=='landmark' and r['evidence']=='measured fixture' and r['tree_size']=='16']
        require(len(old_rows)==1 and int(old_rows[0]['certificate_der_bytes'])==len(raw),'baseline does not match N16 fixture')
        standalone=inputs.read(directory/'standalone-0000.der')
        b=dict(algorithm=profile,security_level=PROFILES[profile]['level'],**b,
               old_baseline_TLS_bytes=int(old_rows[0]['tls_certificate_message_bytes']),
               framing_correction_bytes=b['TLS_Certificate_message_bytes']-int(old_rows[0]['tls_certificate_message_bytes']),
               standalone_DER_bytes=len(standalone),evidence='measured fixture; byte-exact reserialization',
               fixture_sha256=hashlib.sha256(raw).hexdigest())
        breakdowns.append(b);anchors[profile]=tbs;provenance[profile]=meta['provenance']
    # Stop before extending the search if any anchor fails the audit above.
    crossings=[];sizes=[]
    for profile,tbs in anchors.items():
        for first,last,k in intervals():
            sizes.append(dict(algorithm=profile,security_level=PROFILES[profile]['level'],
                              interval_first_N=first,interval_last_N=last,**model(tbs,first),
                              evidence='exact serialization model',native_supported=first<=IMPLEMENTATION_LIMIT))
        for depth in (2,3,4,5):
            directory=a.fixtures/profile/f'depth-{depth}'
            meta=inputs.json(directory/'manifest.json')
            require(meta['profile']==profile and meta['depth_including_root']==depth and meta['root_transmitted'] is False,'X509 identity/depth/root mismatch')
            inputs.manifest_files(directory,meta['files_sha256'])
            positions=['server']+[f'intermediate-{i}' for i in range(depth-2,0,-1)]
            certs=[inputs.read(directory/(name+'.der')) for name in positions]
            static=tls_certificate_message_size(certs)
            previous=[r for r in old if r['algorithm']==profile and int(r['depth'])==depth]
            require(len(previous)==1 and int(previous[0]['tls_certificate_message_bytes'])==static,'static baseline differs from current X509 fixtures')
            digest=hashlib.sha256(inputs.read(directory/'manifest.json')).hexdigest()
            reference=empirical(inputs,a.measurements,profile,depth,digest,static,provenance[profile])
            validation.append(dict(algorithm=profile,security_level=PROFILES[profile]['level'],depth=depth,
                                   static_x509_bytes=static,**reference))
            target=reference['selected_reference_bytes'];cross=crossover(tbs,target)
            operational=crossover(tbs,target,IMPLEMENTATION_LIMIT)

            effective={
                pct: effective_crossover(tbs,target,pct)
                for pct in EFFECTIVE_THRESHOLDS_PCT
            }
            if cross['status'] == 'CROSSED':
                cross['crossover_relation'] = '>='
                cross['crossover_bound_N'] = cross['crossover_N']
                cross['crossover_display'] = str(cross['crossover_N'])
            else:
                cross['crossover_relation'] = '>'
                cross['crossover_bound_N'] = MAXIMUM_SUPPORTED_N
                cross['crossover_display'] = '> 2^48 - 1'
            #crossings.append(dict(algorithm=profile,security_level=PROFILES[profile]['level'],x509_depth=depth,x509_bytes=target,
            #                      **cross,maximum_supported_N=MAXIMUM_SUPPORTED_N,
            #                      implementation_limit=IMPLEMENTATION_LIMIT,implementation_crossover_N=operational['crossover_N'],
            #                      first_configured_workflow_N=next((n for n in TREE_SIZES if cross['crossover_N'] and n>=cross['crossover_N']),''),
            #                      reference_source=reference['selected_reference_source'],evidence='analytically derived crossover'))
            crossings.append(dict(
                algorithm=profile,
                security_level=PROFILES[profile]['level'],
                x509_depth=depth,
                x509_bytes=target,
                **cross,

                effective_1pct_max_N=effective[1]['max_advantage_N'],
                effective_1pct_first_fail_N=effective[1]['first_fail_N'],
                effective_1pct_max_mtc_bytes=effective[1]['max_mtc_bytes'],
                effective_1pct_status=effective[1]['status'],

                effective_5pct_max_N=effective[5]['max_advantage_N'],
                effective_5pct_first_fail_N=effective[5]['first_fail_N'],
                effective_5pct_max_mtc_bytes=effective[5]['max_mtc_bytes'],
                effective_5pct_status=effective[5]['status'],

                effective_10pct_max_N=effective[10]['max_advantage_N'],
                effective_10pct_first_fail_N=effective[10]['first_fail_N'],
                effective_10pct_max_mtc_bytes=effective[10]['max_mtc_bytes'],
                effective_10pct_status=effective[10]['status'],
                maximum_supported_N=MAXIMUM_SUPPORTED_N,
                implementation_limit=IMPLEMENTATION_LIMIT,
                implementation_crossover_N=operational['crossover_N'],
                first_configured_workflow_N=next(
                    (
                        n for n in TREE_SIZES
                        if cross['crossover_N'] and n >= cross['crossover_N']
                    ),
                    ''
                ),
                reference_source=reference['selected_reference_source'],
                evidence='analytically derived crossover'
            ))

    input_drafts={}
    for name in ('draft-ietf-plants-merkle-tree-certs-05.txt','draft-ietf-tls-trust-anchor-ids-04.txt'):
        file=REPO/'src/mtc/reference'/name;input_drafts[name]=hashlib.sha256(inputs.read(file)).hexdigest()
    source_hashes={}
    for name in ('landmark_size_model.py','crossover_extended.py','plot_crossover_extended.py','size_analysis.py','config.py'):
        file=Path(__file__).with_name(name);source_hashes[str(file.relative_to(REPO))]=hashlib.sha256(inputs.read(file)).hexdigest()
    for name in ('core.py','tls.c','mtc.c','crypto_profiles.py'):
        file=REPO/'src/mtc'/name;source_hashes[str(file.relative_to(REPO))]=hashlib.sha256(inputs.read(file)).hexdigest()
    metadata=dict(schema=2,result_domain='CERTIFICATE_SIZE_CROSSOVER',draft=DRAFT,merkle_hash='SHA-256',
                  boundary='TLS Certificate handshake header + body; excludes CertificateVerify, records, latency and CPU; MTC includes empty trust_anchors confirmation',
                  leaf_index=0,log_number=1,landmark_policy='initial cover(0,N), first covering subtree; not a population-wide maximum/average credential size',
                  maximum_supported_N=MAXIMUM_SUPPORTED_N,draft_limit=1<<48,draft_limit_definition='index space permits 2^48 entries; full-landmark end=2^48 cannot fit uint48',
                  draft_endpoint_limit=MAXIMUM_SUPPORTED_N,implementation_limit=IMPLEMENTATION_LIMIT,workflow_sizes=list(TREE_SIZES),
                  limiting_field='MTCProof.end uint48; local landmark size uint48',
                  limiting_reason='Complete initial landmark cover requires exclusive end=N. Largest wire value is 2^48-1; final uint48 leaf index cannot be covered with end=2^48. Native loader separately limits N to 1024.',
                  model='k(N)=max(0,ceil(log2(N))-1); proof=18+32*k. DER=TLV(TBS||ALG||TLV_BITSTRING(0||proof)); TLS=DER+17. All integer populations; fixed log=1/index=0 TBS. No tree is allocated.',
                  effective_crossover_thresholds_percent=list(EFFECTIVE_THRESHOLDS_PCT),
                  effective_crossover_definition=(
                      'largest integer N for which '
                      '(X509_bytes - MTC_bytes(N)) / X509_bytes '
                      'is at least the configured threshold'
                  ),
                  source_hashes=source_hashes,draft_source_hashes=input_drafts,fixture_provenance=provenance,
                  input_hashes=inputs.hashes,existing_n16_validation=str(a.mtc_validation),measured_anchor_count=len(anchors),reference_validation=validation,
                  limitations=['Synthetic N16 MTC population and X509 chain fixtures are separate issuance fixtures, not paired transformations of identical certificates.',
                               'Empty proof extensions, no wire cosignatures/root/trust material. Sizes only; modeled larger populations are not generated or validated TLS credentials.',
                               'Crossover depends on leaf index and landmark policy. Results are for leaf zero, matching the historical size analysis.',
                               'Largest-N model is beyond the native loader limit; no interoperability claim above 1024.'],
                  tls_campaign_executed=False,baseline_preserved=True)
    inputs.unchanged()
    a.output.mkdir(parents=True)
    for name,rows in [('serialization_breakdown.csv',breakdowns),('mtc_size_model.csv',sizes),('crossover_extended.csv',crossings),('x509_reference_validation.csv',validation)]:write_csv(a.output/name,rows)
    from plot_crossover_extended import plots
    plots(a.output,crossings,sizes)
    (a.output/'README.md').write_text(readme(crossings,breakdowns,metadata))
    inputs.unchanged()
    with (a.output/'analysis_extended.json').open('x') as f:json.dump(metadata,f,indent=2);f.write('\n')
    print(a.output)
    return crossings


def readme(crossings,breakdowns,metadata):
    text='''# Exact landmark-MTC / X.509 Certificate-size crossover

This is an offline size study, not a TLS/performance campaign. D includes the trusted
root, which TLS does not transmit. D=2 is root/server; D=3 is root/intermediate/server
and is the representative case. D=4/5 are sensitivity cases.

Landmark MTC carries the X.509/TBS envelope and SPKI, the MTC algorithm identifiers,
empty proof extensions, uint48 start/end, SHA-256 inclusion hashes and an empty
signature vector. No Merkle root or cosigner signature is transmitted in MTCProof.
The reconstructed root is checked against previously trusted landmark information.
No large SLH-DSA signature has been compressed: it is distributed out of band.
SLH-DSA-256s SPKI is 82 bytes versus 91 for ECDSA P-256, explaining its smaller
landmark fixture. Different identity/extension fields also contribute to the base.

The old model omitted the 4-byte empty trust_anchors CertificateEntry extension
(historically 0xffa7; currently provisional 0xca34, still uint16). This new
analysis corrects TLS=DER+17 for MTC; X509 uses 8+sum(DER+5). Existing files are
untouched. The N16 DER fixtures round-trip exactly, and the additive breakdown
sums to DER, then adds TLS framing. TBS extensions and SPKI AlgorithmIdentifier
are retained; proof signatures are empty, not hidden in another wire field.

For fixed leaf index zero/log one and initial cover(0,N),
k=max(0,ceil(log2(N))-1). Proof size=18+32*k; its three vectors have fixed uint16
length fields and endpoints have fixed uint48 widths. SHA-256 determines 32.
DER length octets are computed by the actual encoder, including transitions at
128 and 256; BIT STRING includes one unused-bits byte. TBS serial does not change
with N at leaf zero. Changing leaf index/log may change its DER integer size;
these results are neither worst-case nor average over all leaves.

All integer N from 1 to 2^48-1 are searched using only 48 constant-size intervals.
The draft index space has capacity 2^48, but the complete landmark's exclusive
end=N cannot encode 2^48. This endpoint edge is recorded explicitly rather than
asserting unrestricted support for that final index. Native loading supports only
N<=1024; the principal D=2 generation workflow selects 1,4,16,64,256. Larger values
are analytical format extrapolations, not working native TLS populations.

Crossover is the first N with MTC>=X509, with N-1 also reported. Hash step k begins
at N=2^k+1, not 2^(k+1); first_power_of_two_N is only a sampling-grid comparison.
No continuous interpolation is needed: the mathematical integer threshold is exact.
NO_CROSSOVER_WITHIN_PROTOCOL_RANGE means MTC is smaller throughout this complete
landmark model's wire range; absent crossings are not zero. implementation_crossover_N
separately indicates whether the crossing is inside the native range.

X509 reference compatibility checks fixture hashes, recorded cryptographic source
revisions, completion JSON, observation identities/counts and Certificate byte
values, then reproduces the existing summary's median of campaign medians.
Latency, CPU and CertificateVerify are never used. See x509_reference_validation.csv
for every pair and any fallback to static fixtures. MTC anchors use a separate
same-profile population, not the very same certificates/keys as X509. This fixture
choice is explicit and limits generalization. SLH-DSA TLS support is demonstrated
only where the existing completed measurement evidence passes these checks.

Measured fixtures, exact serialization model and analytically derived crossovers
are labeled separately. Version/image/draft/source/fixture hashes are retained in
analysis_extended.json. Plot D=3 emphasis denotes a representative scenario, not a
new cryptographic property: logarithmic proof growth is expected; concrete crossover
locations are the quantitative result.

## N16 byte breakdown

| Algorithm | TBS excluding SPKI | SPKI | Fixed proof | Hashes bytes | Signatures | Other DER | DER total | TLS total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
'''
    for r in breakdowns:
        text+='| '+ ' | '.join(str(r[k]) for k in ('algorithm','certificate_base_bytes','spki_bytes','proof_fixed_bytes','proof_hash_bytes','signatures_bytes','other_bytes','total_MTC_DER_bytes','TLS_Certificate_message_bytes'))+' |\n'
    text+='\n## Crossovers (D=2 and D=3 primary; D=4/5 sensitivity)\n\n| Algorithm | D=2 | D=3 | D=4 | D=5 |\n|---|---:|---:|---:|---:|\n'
    for name in PROFILES:
        rows=[r for r in crossings if r['algorithm']==name]
        text+='| '+name+' | '+' | '.join(str(r['crossover_N']) if r['crossover_N'] else '> '+str(MAXIMUM_SUPPORTED_N) for r in rows)+' |\n'

    text+='\n## Effective crossover margins\n\n'
    text+='N*τ is the largest integer N for which MTC retains at least τ percent fewer Certificate-message bytes than the selected X.509 reference.\n\n'
    text+='| Algorithm | Depth | N* | N*1% | N*5% | N*10% |\n'
    text+='|---|---:|---:|---:|---:|---:|\n'
    for r in crossings:
        nstar=(str(r['crossover_N']) if r['crossover_N']
               else '> '+str(MAXIMUM_SUPPORTED_N))
        values=[]
        for pct in EFFECTIVE_THRESHOLDS_PCT:
            status=r[f'effective_{pct}pct_status']
            if status == 'NO_N_WITH_REQUIRED_MARGIN':
                value='none'
            elif status == 'PRESERVED_THROUGH_PROTOCOL_RANGE':
                value='>= '+str(MAXIMUM_SUPPORTED_N)
            else:
                value=str(r[f'effective_{pct}pct_max_N'])
            values.append(value)
        text+=f"| {r['algorithm']} | {r['x509_depth']} | {nstar} | " + ' | '.join(values) + ' |\n'

    text+='\nAll numbers refer to Certificate messages only. D=3 is emphasized in the plots.\n'
    return text


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('fixtures','mtc-fixtures','mtc-validation','baseline','output'):p.add_argument('--'+arg,type=Path,required=True)
    p.add_argument('--measurements',type=Path)
    a=p.parse_args();run(a)

if __name__=='__main__':main()
