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
is detected from the actual image, not inferred from key generation. The existing
MTC-experimental issuer supports P-256 (`classic`) and ML-DSA-65 (`pq`) only.
Other profiles remain in the static X.509 design and receive `UNSUPPORTED_MTC_PROFILE` in
crossover output. Falcon/FN-DSA and SLH-DSA fast variants are extension points,
not default profiles.

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

To include MTC sizes and X.509–MTC crossover, first prepare fixtures with the
[original Merkle population scaling campaign](../../original_campaigns/scaling_campaign/README.md),
located at `campaigns/original_campaigns/scaling_campaign/`. This is separate
from the Paper-1 certificate-chain campaign and from the exploratory MTC runner.

The dependency is **fixture generation and structural validation**, not the
full scaling timing campaign. The base, Compact and MTC fixtures and the
measurement image must already be prepared (original battery steps through
`07.measurement-image`). With an initialized battery, inspect its state:

```sh
bin/original_campaigns/mt-campaigns status
```

If these stages are still pending, run them in order; stop on any failure:

```sh
mkdir -p artifacts/results
bin/original_campaigns/mt-campaigns run 20.scaling-init &&
bin/original_campaigns/mt-campaigns run 21.scaling-tests-before &&
bin/original_campaigns/mt-campaigns run 22.scaling-generate
```

- `20.scaling-init` creates the scaling campaign metadata.
- `21.scaling-tests-before` runs the regression gate and records the image ID;
  its tests do include TLS connections inside the container.
- `22.scaling-generate` generates populations N=1,4,16,64,256,1024 and runs
  `structural.py` to validate the resulting Compact/MTC fixtures.

Only proceed when `22.scaling-generate` completes. Do not rerun completed
stages over immutable outputs. Steps `23.scaling-preflight` through
`26.scaling-analysis` belong to the full scaling measurement campaign and are
not required for this static comparison. Fixture generation itself can be
expensive and is a manual operation.

Obtain the actual fixture directory recorded by that campaign, from the
repository root:

```sh
. .mt-state/campaign-roots.env
MTC_SCALING_ROOT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["host"])' "$SCALING_ROOT/fixture-location.json")
```

`SCALING_ROOT` contains the campaign metadata; `MTC_SCALING_ROOT` contains the
`batch1`, `batch4`, …, `batch1024` fixture directories. They are different
paths. For a different battery, read its own `fixture-location.json` rather
than using the current battery's state.

Then run the combined static analysis. If the X.509-only command above already
created `STATIC_ROOT`, assign a **new output path** first, for example
`STATIC_ROOT="${STATIC_ROOT}-with-mtc"`; existing analyses are not overwritten.

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/size_analysis.py "$CHAIN_FIXTURES" --mtc-fixtures "$MTC_SCALING_ROOT" --output "$STATIC_ROOT"
```

This writes `key_sizes.csv`, `certificate_sizes.csv`, `chain_sizes.csv`,
`mtc_sizes.csv`, and `crossover.csv`. It measures real DER objects. MTC powers
through 2^20 use the real DER/MTCProof encoder with deterministic 32-byte proof
elements and are labeled `exact serialization model`.

The crossover status distinguishes absent data from implementation limits:

| Status | Meaning |
|---|---|
| `MTC_FIXTURES_NOT_PROVIDED` | P-256 or ML-DSA-65 is supported, but `--mtc-fixtures` was omitted |
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

Representative MTC N=16 landmark and standalone checks use the filtered MTC
runner and existing immutable scaling fixtures:

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/run_mtc.py --fixtures "$MTC_SCALING_ROOT" --output "artifacts/results/mtc-functional-$STAMP" --profile mldsa65 --scenario landmark --tree-size 16 --repetitions 2 --warmups 0 --execute
```

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

11. Run optional MTC standalone separately. Preview by omitting `--execute`:

```sh
python3 campaigns/cryptographic_scaling/cert_chain_scaling/run_mtc.py --fixtures "$MTC_SCALING_ROOT" --output "artifacts/results/mtc-standalone-$STAMP" --profile mldsa65 --scenario standalone --tree-size 16 --campaigns 5 --repetitions 30 --warmups 5
```

Do not mix standalone output into the primary X.509 result root.

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
analysis and standalone validation. MTC crossover remains restricted to the
existing P-256/ML-DSA-65 issuer implementation; other rows retain
`UNSUPPORTED_MTC_PROFILE`. SPHINCS+ names, hybrids and SLH-DSA fast variants
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
