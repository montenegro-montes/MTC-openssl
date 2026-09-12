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

## Bash coordinator (recommended)

Use `bin/cryptographic_scaling/mt-cert-scaling` for an interactive menu, persistent
paths, per-stage logs and progress counters. It only runs the stage you select.
It does not launch a performance matrix. Initialization and status never invoke
Docker or generate fixtures. Source files used by the N=16 hash gate are untouched
by this coordinator.

For the existing manual campaign:

```sh
bin/cryptographic_scaling/mt-cert-scaling init 20260912T203417Z
bin/cryptographic_scaling/mt-cert-scaling status
bin/cryptographic_scaling/mt-cert-scaling menu
```

The date selects `artifacts/paper1-mtc/n16-DATE`, `all-DATE` and
`artifacts/results/paper1-mtc-n16-DATE`. It does not infer completion from directory
existence. For the separately generated X.509 fixtures, set the actual paths via
the menu's **Cambiar ruta** option (`CHAIN_FIXTURES` and `CHAIN_VALID`). The latter
must refer to their successful validation JSON, often inside the fixture root.
Other paths can be changed with `set VARIABLE PATH`; previous execution logs are
preserved. Initialization refuses to replace existing coordinator state.

Option **6 — Protocolo MTC** opens the separate protocol-validation menu;
`bin/cryptographic_scaling/mt-cert-scaling protocol` opens it directly. It has its
own state and initially uses legacy pq N=16 fixtures. It does not require this
campaign's X.509 chain generation or crossover. See the
[protocol workflow](../../protocol_validation/README.md) for dependencies and gates.

Stages:

| Number | Action |
|---|---|
| 10 | Inspect measurement image and algorithms |
| 20 | Generate X.509 fixtures |
| 30 | Validate X.509 fixtures |
| 40 | Build MTC image using current dependencies |
| 50 | Generate nine-profile N=16 fixtures |
| 60 | Validate N=16, 18 TLS handshakes |
| 70 | Generate all sizes after the N=16 gate |
| 80 | Static sizes and crossover using successful validations |
| 90 | Audit X.509 fixtures and analysis output presence |

`show 70` prints the exact command; `run 70` executes it. While generation runs,
the coordinator prints a heartbeat and certificate counters every 30 seconds.
These counters are not a completion percentage: MTC objects are generated after
the population. Run `status` from another terminal to inspect a process started
manually too; heartbeat monitoring only applies to newly launched steps.

Do not rerun stages already completed manually or currently running. For the
existing all-size generation, wait for successful completion, configure the X.509
paths, then select stage **80**. Outputs are immutable: failures preserve partial
outputs; select a fresh path before a new attempt. A process lock serializes runs
started by this coordinator, but cannot detect independently launched campaigns.
A hard interruption may leave `.mt-state/cert-scaling/lock`; inspect the process
and log before manually removing that empty lock directory.

For a fresh campaign, run `init` without a date and review the saved paths.
The required measurement/profile base images must already exist. Stage 40 rebuilds
MTC only; do not select it during an active campaign. Stage 90 invokes Docker for
X.509 verification; it does not validate performance results or prove draft
compliance. TLS performance commands below remain separate manual operations.

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
(one per mode/profile) before the remaining sizes. It does not require the
original scaling campaign. Set `MTC_SCALING_ROOT` to the new complete fixture
root produced after that gate. Choose a new analysis output directory:

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
python3 -m pip install -r campaigns/original_campaigns/scaling_campaign/requirements-plots.txt
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
