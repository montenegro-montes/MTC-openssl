# Certificate-chain and MTC proof-scaling experiment

This separate ideal-network experiment studies certificate size, X.509 chain
depth, authentication processing, and MTC proof scaling. It never writes to an
existing path. Private fixtures and results remain below ignored `artifacts/`.

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

These identifiers were read from the current OpenSSL 3.5.8 image. The existing
MTC-experimental issuer supports P-256 (`classic`) and ML-DSA-65 (`pq`) only.
Other profiles work for X.509 and receive `UNSUPPORTED_MTC_PROFILE` in
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
python3 campaigns/cryptographic_scaling/cert_chain_scaling/inspect_environment.py --output "artifacts/cert-chain-scaling/environment-$STAMP.json"
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

4. Run static size analysis using the validated scaling-fixture directory:

```sh
MTC_SCALING_ROOT="artifacts/scaling/<validated-fixture-directory>"
python3 campaigns/cryptographic_scaling/cert_chain_scaling/size_analysis.py "$CHAIN_FIXTURES" --mtc-fixtures "$MTC_SCALING_ROOT" --output "$STATIC_ROOT"
```

This writes `key_sizes.csv`, `certificate_sizes.csv`, `chain_sizes.csv`,
`mtc_sizes.csv`, and `crossover.csv`. It measures real DER objects. MTC powers
through 2^20 use the real DER/MTCProof encoder with deterministic 32-byte proof
elements and are labeled `exact serialization model`.

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
python3 campaigns/cryptographic_scaling/cert_chain_scaling/run.py --fixtures "$CHAIN_FIXTURES" --output "$TLS_ROOT" --campaigns 5 --repetitions 30 --warmups 5 --full-matrix
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
