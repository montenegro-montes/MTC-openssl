# Certificate-chain and MTC proof-scaling experiment

This separate ideal-network experiment studies certificate size, X.509 chain
depth, authentication processing, and MTC proof scaling. Completed cells and their observations are immutable; resume attempts write
to new paths. Private fixtures and results remain below ignored `artifacts/`.

TLS is fixed to 1.3, X25519, `TLS_AES_256_GCM_SHA384`, server authentication,
no tickets, no resumption, and an unmodified Docker bridge. Depth includes the
offline root: D=2,3,4,5 transmit 1,2,3,4 certificates. X.509 hierarchy depth
and MTC tree depth are separate dimensions. Exact boundaries are documented in
[authentication representations](../../../docs/authentication-representations.md).

| Level | ECDSA | ML-DSA | SLH-DSA |
|---|---|---|---|
| 1 | P-256 | ML-DSA-44 | SLH-DSA-SHA2-128s |
| 3 | P-384 | ML-DSA-65 | SLH-DSA-SHA2-192s |
| 5 | P-521 | ML-DSA-87 | SLH-DSA-SHA2-256s |

Standard names and implementation identifiers are recorded separately. TLS eligibility
is detected from the actual image, not inferred from key generation. The explicit
Paper-1 MTC registry prepares all nine profiles with the same real signature
algorithm as X.509. The historical `classic`/`pq` aliases retain their original
P-256/ML-DSA-65 meaning. See the [N=16 functional gate](../mtc_profile_scaling/README.md)
before generating MTC fixtures or executing comparisons. Provider/TLS support still
requires manual validation; the mapping alone is not evidence of success.

## Independent prerequisites

First prepare the shared images without invoking an original campaign:

```sh
bin/cryptographic_scaling/mt-prepare run ALL
```

The [setup guide](../../../bin/cryptographic_scaling/README.md) describes each
image stage, Python dependencies and the independent N=16/protocol paths. The
certification menu opens setup with option10 or `mt-cert-scaling prepare`.
Stage40 uses this same setup launcher through image stage4. Existing images are
reused; rebuilding is explicit. No historical fixture directory is needed.

## Bash coordinator: quick and advanced crossover

```sh
bin/cryptographic_scaling/mt-cert-scaling menu
```

The default workflow generates and validates **N=16 for all nine profiles**,
then produces crossover CSVs and PDF plots. It does not generate the larger MTC
populations. Existing paths are stored in `.mt-state/cert-scaling/paths.env`;
`status` displays them. Menus, prompts, status messages and errors are in English.

```sh
# First use only; init/status/show do not execute Docker or generate fixtures.
bin/cryptographic_scaling/mt-cert-scaling init
bin/cryptographic_scaling/mt-cert-scaling status

# After the X.509 and nine-profile N=16 validations pass:
bin/cryptographic_scaling/mt-cert-scaling cross
# Equivalent: run 80

# Optional slower workflow, in a separate output directory:
bin/cryptographic_scaling/mt-cert-scaling cross-advanced
```

| Workflow | Real MTC fixtures | Analysis output | Plots |
|---|---|---|---|
| `cross` / `run 80` | N=16, nine profiles | STATIC_ROOT | STATIC_ROOT/plots |
| `cross-advanced` | N=1,4,16,64,256,1024, nine profiles | ADVANCED_ROOT | ADVANCED_ROOT/plots |

Both workflows search the same analytical powers of two (default through 2^20).
The advanced workflow adds **real serialization checks at more populations**;
it does not automatically expand the analytical search or guarantee a crossover.
It is not a timing experiment. N=16-only evidence verifies model agreement at
N=16, not at all other sizes. Larger modeled rows remain explicitly labeled.

`cross-advanced` generates the complete fixture set only if MTC_ALL is absent,
using the N=16 gate. If it already exists, its completion manifest and full profile/
size coverage are required before analysis; partial output is not resumed or
replaced. Existing N=16 and advanced results remain separate and immutable.
A plot failure preserves CSVs; choose a new output path for another attempt.
Matplotlib must be available in the Python environment used by the launcher.

New configurations use `artifacts/results/paper1-crossover-n16-DATE` and
`artifacts/results/paper1-crossover-advanced-DATE`. Existing configurations retain
STATIC_ROOT; ADVANCED_ROOT defaults to STATIC_ROOT plus `-advanced` without
rewriting the state file. If STATIC_ROOT already contains previous analysis,
select a fresh path with `set STATIC_ROOT PATH` before requesting another quick
crossover. Existing results are not reclassified as N=16-only evidence.

| Stage | Action | Default batch |
|---|---|---|
| 10 | Inspect measurement image and algorithms | yes |
| 20 | Generate X.509 fixtures | yes |
| 30 | Validate X.509 fixtures | yes |
| 40 | Ensure MTC image and missing parents via mt-prepare | yes |
| 50 | Generate nine-profile N=16 fixtures | yes |
| 60 | Validate N=16 with 18 TLS handshakes | yes |
| 70 | Generate all six MTC populations | **optional** |
| 80 | N=16 crossover CSVs and PDF plots | yes |
| 90 | Audit the quick analysis | yes |
| 100 | Advanced CSVs and plots from existing complete MTC_ALL | **optional** |

`run ALL` and `run --count X` use only the default stages: **70 and 100 are
excluded**. Completed stages are skipped and the first failure stops the batch.
Use `run 70` for generation only or `run 100` for advanced analysis only;
`cross-advanced` coordinates both. Stage numbers and full names remain valid.
The menu exposes advanced crossover as option9. No performance matrix is launched.
The original `mt-campaigns run ALL` retains its own stage list and behavior.

```sh
bin/cryptographic_scaling/mt-cert-scaling show 80
bin/cryptographic_scaling/mt-cert-scaling show 100
bin/cryptographic_scaling/mt-cert-scaling run --count 3
bin/cryptographic_scaling/mt-cert-scaling run ALL
```

Set CHAIN_FIXTURES and CHAIN_VALID to the actual X.509 fixture directory and its
successful validation JSON if they were generated separately. Change paths using
**Change path** or `set VARIABLE PATH` before execution. A directory alone is not
completion. All reports must use fresh output names. Locks cover this launcher,
not independently started campaigns. Generation prints a heartbeat and population
counters every30 seconds; reaching the certificate count does not mean MTC objects
are complete. No builds or changes should overlap a frozen scientific run.

Option6 (**MTC protocol**) opens the separate
[protocol workflow](../../protocol_validation/README.md), also accessible through
`bin/cryptographic_scaling/mt-cert-scaling protocol`. New configurations select Paper-1 mldsa65 from the saved N=16 fixture root.
Historical configurations retain legacy pq; crossover results are not required.

Define fresh immutable locations:

```sh
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
CHAIN_FIXTURES="artifacts/cert-chain-scaling/fixtures-$STAMP"
STATIC_ROOT="artifacts/results/cert-chain-static-$STAMP"
TLS_ROOT="artifacts/results/cert-chain-tls-$STAMP"
```

## Manual phases

1. Inspect the environment:

```sh
ENVIRONMENT="artifacts/cert-chain-scaling/environment-$STAMP.json"
python3 campaigns/cryptographic_scaling/cert_chain_scaling/inspect_environment.py --output "$ENVIRONMENT" --support-output "artifacts/cert-chain-scaling/algorithm_support-$STAMP.csv"
```

2. Preview and generate immutable fixtures:

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/generate_fixtures.py --output "$CHAIN_FIXTURES" --plan
python3 campaigns/cryptographic_scaling/cert_chain_scaling/generate_fixtures.py --output "$CHAIN_FIXTURES"
```

3. Validate all 36 chains, key/hash manifests, depths, and root omission:

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/validate.py "$CHAIN_FIXTURES" --output "$CHAIN_FIXTURES/validation.json"
```

4. Run static size analysis. X.509-only analysis needs only `CHAIN_FIXTURES`:

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/size_analysis.py "$CHAIN_FIXTURES" --output "$STATIC_ROOT"
```

To include MTC sizes and X.509–MTC crossover, first run the separate
[Paper-1 MTC profile preparation and N=16 gate](../mtc_profile_scaling/README.md).
It generates N=16 for nine algorithms and requires 18 successful handshakes
(one per mode/profile). It does not require the original scaling campaign.
Set `MTC_SCALING_ROOT` to the validated N=16 fixture root for the quick analysis,
or to the complete six-size root for the optional advanced analysis. Choose a new analysis output directory:

```sh
STATIC_ROOT="artifacts/results/cert-chain-with-mtc-$STAMP"
python3 campaigns/cryptographic_scaling/cert_chain_scaling/size_analysis.py "$CHAIN_FIXTURES" --mtc-fixtures "$MTC_SCALING_ROOT" --output "$STATIC_ROOT"
```

For historical **two-profile** reproduction only, the
[original scaling campaign](../../original_campaigns/scaling_campaign/README.md)
uses steps `20.scaling-init`, `21.scaling-tests-before`, `22.scaling-generate`
after its base prerequisites through `07.measurement-image`. Its fixture path is
recorded in `$SCALING_ROOT/fixture-location.json` (`host` field). Pass
`--legacy-mtc-fixtures` explicitly to analyze those `classic`/`pq` directories;
they cannot supply the seven additional profiles. Existing outputs remain intact.

This writes `key_sizes.csv`, `certificate_sizes.csv`, `chain_sizes.csv`,
`mtc_sizes.csv`, and `crossover.csv`. It measures real DER objects. MTC powers
through 2^20 use the real DER/MTCProof encoder with deterministic 32-byte proof
elements and are labeled `exact serialization model`.

The crossover status distinguishes absent data from implementation limits:

| Status | Meaning |
|---|---|
| `MTC_FIXTURES_NOT_PROVIDED` | A configured profile is supported, but `--mtc-fixtures` was omitted |
| `MISSING_MTC_FIXTURES` | A directory was supplied, but no matching MTC landmark fixtures were found for that supported profile |
| `UNSUPPORTED_MTC_PROFILE` | The MTC issuer does not implement this profile, independently of fixture availability |
| `CROSSED` | The model reaches the X.509 size within the evaluated range |
| `OUTSIDE_SEARCH_RANGE` | A model exists, but does not reach the X.509 size within that range |

Without MTC fixtures, X.509 analysis still runs, `mtc_sizes.csv` has no data
rows, and no crossover sizes are fabricated.

5. Inspect crossings:

```sh
column -s, -t < "$STATIC_ROOT/crossover.csv" | less -S
```

6. Run one functional X.509 handshake (do not merge it into study data):

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/run.py --fixtures "$CHAIN_FIXTURES" --output "artifacts/results/cert-chain-functional-$STAMP" --profile ecdsa-p256 --depth 3 --campaigns 1 --repetitions 2 --warmups 0 --execute
```

MTC functional validation uses the [dedicated N=16 sequence](../mtc_profile_scaling/README.md).
It is separate from the X.509 performance commands below.

7. Run one algorithm only:

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/run.py --fixtures "$CHAIN_FIXTURES" --output "$TLS_ROOT" --profile mldsa65 --execute
```

8. Run one depth only:

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/run.py --fixtures "$CHAIN_FIXTURES" --output "$TLS_ROOT" --depth 3 --execute
```

9. Run one security level only:

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/run.py --fixtures "$CHAIN_FIXTURES" --output "$TLS_ROOT" --security-level 3 --execute
```

10. **WARNING: FULL EXPERIMENT — MANUAL EXECUTION ONLY.** Preview first. The
full matrix needs both `--full-matrix` and `--execute`:

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/run.py --fixtures "$CHAIN_FIXTURES" --output "$TLS_ROOT" --campaigns 5 --repetitions 30 --warmups 5 --full-matrix --environment "$ENVIRONMENT" --dry-run
python3 campaigns/cryptographic_scaling/cert_chain_scaling/run.py --fixtures "$CHAIN_FIXTURES" --output "$TLS_ROOT" --campaigns 5 --repetitions 30 --warmups 5 --full-matrix --execute
```

11. MTC standalone is included in the dedicated functional gate. Further MTC
performance matrices are deferred until all nine profiles pass that gate.

12. Audit fixtures and static outputs:

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/validate.py "$CHAIN_FIXTURES" --analysis "$STATIC_ROOT" --output "$STATIC_ROOT/validation.json"
git status --short
```

13. Summarize manually generated TLS observations:

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/analyze.py "$TLS_ROOT"
```

The summary uses medians within campaigns and then the median of campaign
medians. Handshakes are not treated as independent campaigns.

14. Generate plots:

```sh
python3 -m pip install matplotlib
python3 campaigns/cryptographic_scaling/cert_chain_scaling/plots.py "$STATIC_ROOT" --measurements "$TLS_ROOT" --output "$STATIC_ROOT/plots"
```

The current plotter produces certificate DER, X.509 chain-scaling, and MTC
scaling figures. Processing-cost and total-TLS-byte figures require completed
manual data and are not fabricated during preparation.

## Cryptographic support versus TLS support

The environment manifest stores complete `version -a`, provider, public-key,
`-signature-algorithms` and `-tls-signature-algorithms` outputs, command exit
statuses, actual image ID, source commits, detected versions and configuration.
The support CSV records cryptographic and TLS support independently. Blank
X.509 sign/verify fields mean not probed, not unsupported. Pass `--fixtures`
to `inspect_environment.py` to add hash-valid fixture-builder evidence from
the exact same image ID and OpenSSL version; the builder writes its manifest only after standalone
chain verification. These static checks are not TLS handshakes.

Standardized SLH-DSA remains in key, SPKI, DER, signature and D=2..5 chain-size
analysis and standalone validation. MTC crossover uses the nine explicit same-algorithm profiles. Missing fixtures
receive `MISSING_MTC_FIXTURES`; unvalidated TLS capability is not inferred from
this mapping. SPHINCS+ names, hybrids and SLH-DSA fast variants
never substitute for the configured standardized algorithms.

For the former OpenSSL 3.5.8 stack, absent SLH-DSA TLS schemes mean explicit
`SKIPPED_UNSUPPORTED_TLS` cells (24 eligible and 12 unsupported per campaign
index if all six ECDSA/ML-DSA profiles are advertised). The user's replacement
OpenSSL 3.4.7 / liboqs 0.16.0 / oqs-provider 0.12.0-dev image advertises all
nine configured schemes. This observation is image-specific and is not a
claim of successful TLS measurements. A different image requires fresh
capability evidence and a separate measurement root.

## Resume and individual cells

For an existing result root with its original manifest and fixture hashes:

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/run.py --fixtures "$CHAIN_FIXTURES" --output "$TLS_ROOT" --resume --full-matrix --environment "$ENVIRONMENT" --dry-run
python3 campaigns/cryptographic_scaling/cert_chain_scaling/run.py --fixtures "$CHAIN_FIXTURES" --output "$TLS_ROOT" --resume --full-matrix --environment "$ENVIRONMENT" --execute
```

Resume inherits the frozen campaign count, repetitions, warmups and seed.
`--campaign 3` selects index 3; `--campaigns 5` specifies the original number
of campaigns and cannot change it on resume. Filters may be combined, e.g.
`--resume --profile mldsa87 --depth 5 --campaign 3`. Omit `--full-matrix` for
that selection. Every original cell is inspected; only selected missing or
incomplete eligible cells execute.

Completion requires passed validation, the expected measured/warmup row counts,
unique rounds and client randoms, successful rows, logs, matching server metrics,
and matching fixture/image/source/seed provenance. A directory alone is not
completion. Existing complete cells are skipped; incomplete attempts remain
untouched and retries go under `resume/<attempt>/cells/`. Duplicate complete
cells and changed images or fixtures block execution. Original manifests and
legacy rows (including blank security-level fields) remain unchanged. Newly
measured rows use `config.py` for complete profile metadata. Analysis enriches
legacy metadata only in derived output.

Failure diagnostics (`ps -a`, server logs, container inspection) are captured
under the attempt's failure directory before `compose down`. Resume attempts
also store a plan, support table, full environment and current source hashes.
A deleted result root cannot be resumed; do not fabricate an original manifest.

TLS summaries only include complete eligible cells. The summary sidecar lists
unsupported, missing and incomplete cells; none are imputed as zero or included
in performance denominators. Static plots remain independent. Re-analysis is
immutable: choose another `--output path/to/summary.csv` when a summary exists.

## Full TLS performance workflow

`run ALL` runs the default fixture validation and N=16 size-crossover stages;
it does not run the full TLS performance matrix. The optional TLS stages are:

| Stage | Action |
| --- | --- |
| 110 | Offline matrix preview using the recorded environment |
| 120 | Full TLS execution: 5 campaigns, 30 repetitions, 5 warmups |
| 130 | Aggregate completed eligible TLS observations |
| 140 | Generate size and TLS performance plots in `TLS_ROOT/plots` |

After the default workflow has completed, inspect paths and preview:

```sh
bin/cryptographic_scaling/mt-cert-scaling status
bin/cryptographic_scaling/mt-cert-scaling tls-full
```

**WARNING: FULL EXPERIMENT — MANUAL EXECUTION ONLY.** To explicitly run the
preview, matrix, analysis and plots in order, stopping at the first failure:

```sh
bin/cryptographic_scaling/mt-cert-scaling tls-full --execute
```

The menu exposes preview and execution separately. Individual stages accept
`show 120` or `run 120` (and likewise 110, 130, 140). The execution command uses
both `--full-matrix` and `--execute`, with the same recorded `ENVIRONMENT` as
the preview. Unsupported TLS algorithms remain explicitly excluded by the runner.

`TLS_ROOT` defaults to `artifacts/results/cert-chain-tls-$STAMP`, including for
older launcher configurations. Select another fresh location with
`mt-cert-scaling set TLS_ROOT artifacts/results/cert-chain-tls-NEW`.
The analysis writes `summary.csv`, `summary.json` and
`summary-algorithm_support.csv` under that root. Plots require the existing
N=16 crossover tables in `STATIC_ROOT` and Matplotlib. Existing output is
preserved; after a failure, inspect the log and use the individual remaining
stages or the documented runner resume procedure. The combined command does
not automatically resume or overwrite a previous TLS run.

## Primary static result: exact landmark crossover

Use `crossover_extended.py` for the extended Certificate-size analysis. It reads
existing fixtures, baseline size tables, the N16 validation gate and optional
completed TLS observations; it never starts Docker, OpenSSL, captures or campaigns.
Do not rerun a TLS matrix for this analysis. The previous tables remain historical.

The original MTC TLS size calculation omitted the four bytes of the empty 0xffa7
CertificateEntry confirmation. Future `size_analysis.py` output includes them.
The new model validates all nine N16 fixtures byte-for-byte before extending the
search. The main comparison is full Certificate-message bytes on both sides;
CertificateVerify, CPU and latency are excluded.

```sh
# Use an existing Python environment with matplotlib; do not install packages
# or regenerate fixtures as part of this analysis. Select a fresh output path.
PYTHONDONTWRITEBYTECODE=1 python3 campaigns/cryptographic_scaling/cert_chain_scaling/crossover_extended.py \
  --fixtures "$CHAIN_FIXTURES" \
  --mtc-fixtures "$MTC16" \
  --mtc-validation "$MTC_VALID/validation.json" \
  --baseline "$STATIC_ROOT" \
  --measurements "$TLS_ROOT" \
  --output artifacts/results/crossover-extended-NEW
```

This checkout also has an existing matplotlib environment at
`/Users/joseantoniomontenegromontes/anaconda3/bin/python`; the default Homebrew
Python did not have matplotlib during review. No packages were installed.
Omit `--measurements` when no compatible existing TLS results are available;
the report explicitly retains static references instead of inventing measurements.
The MTC anchor and X509 certificates are separate same-profile issuance fixtures,
not the same key/subject transformed into another format. That comparison scope
is reported explicitly.

New outputs: `serialization_breakdown.csv`, `mtc_size_model.csv`,
`x509_reference_validation.csv`, `crossover_extended.csv`,
`crossover-by-depth.pdf`, `crossover-curves.pdf`, `analysis_extended.json` and
`README.md`. PNG companions allow inexpensive visual inspection. D=3 is emphasized;
D=2 is retained and D=4/5 are sensitivity cases. No-crossing points are marked
above the maximum, never at zero.

For leaf zero/log one and the initial cover(0,N), the first proof with k hashes
starts at N=2^k+1 (k>=1). An exact crossover can therefore occur between old
power-of-two samples. The model covers every integer through 2^48-1 in only
48 size intervals. It reuses the real DER encoder, including length transitions.
The draft index capacity is 2^48, but a complete landmark's exclusive uint48 end
cannot represent 2^48; the model limit records that edge. Native MTC loading is
separately capped at N=1024, and the current generation workflow exposes only
1,4,16,64,256,1024. Analytical large-N results are not implementation/TLS support.

The reviewed `20260913T142141Z` input set reproduced all 36 X509 references exactly,
including completed SLH-DSA TLS observations. The extended crossover remains a size
study. At N16, corrected landmark Certificate bytes are P256=460, ML-DSA65=2343,
SLH-DSA256s=451. SLH-DSA landmark omits out-of-band cosignatures; it does not compress
those signatures into hundreds of bytes. Its SPKI is 82 bytes versus P256's 91.

Pinned source sections: MTC-05 §4.5.1 (initial cover), §5.2 (48-bit log indices),
§6.2 (DER envelope/proof, fixed uint48 endpoints and vectors), §6.4.4 (landmark
construction), and TA-04 §4.1/4.2 (empty CertificateEntry confirmation).

Cheap tests:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s campaigns/cryptographic_scaling/cert_chain_scaling \
  -p test_landmark_size_model.py
```
