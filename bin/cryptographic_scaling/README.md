# Cryptographic scaling

Run `bin/cryptographic_scaling/mt-cert-scaling` from the repository root. The launcher covers X.509 and experimental MTC fixture generation, validation, crossover analysis, boundary audits, mutual-authentication crossover, and the D=2–5 scaling verification.

Each new configuration selects `X25519`, `X25519+ML-KEM768`, or
`ML-KEM-768`. TLS stages inherit that OpenSSL group, result paths include its
slug, and generated TLS CSV and JSON evidence records the selection.

The active profiles are ECDSA P-256/P-384/P-521, Ed25519, Ed448, ML-DSA-44/65/87 and SLH-DSA-SHA2-128s. Tree-size studies use the configured values shown by the launcher status. Outputs are new directories below `artifacts/`; `.mt-state/cert-scaling/` records resumable stage state.

Use the menu to initialize, inspect status, show a stage command, run one pending stage, or run the default battery. Image prerequisites are prepared through `bin/base/mt-prepare`. Existing output is never overwritten and its presence alone is not proof of successful validation.

### Advanced crossover prerequisite

Stage `100.cross-advanced` and `cross-advanced` require the N=16 baseline from
stage `80.crossover`: `STATIC_ROOT/chain_sizes.csv` and `STATIC_ROOT/mtc_sizes.csv`.
They now check these files before analysis (and before stage 95 generation in
`cross-advanced`). With existing validated fixtures, run:

```sh
bin/cryptographic_scaling/mt-cert-scaling run 80
bin/cryptographic_scaling/mt-cert-scaling run 100
```

Stage 80 analyzes existing fixtures and produces plots; it does not regenerate
fixtures or run TLS. Stage 100 retains its other prerequisite checks, including
stage 95 outputs. If `STATIC_ROOT` is partially populated, preserve it and select
a new path before rerunning stage 80. Do not substitute an unrelated baseline.

### Stage 110 capability evidence

Stage 110 probes the selected profiling image before planning measurements and
stores a fresh capability snapshot in `TLS_ROOT-capabilities-XXXXXX/`. Both the
dry-run and execution use that snapshot and its immutable image ID. The original
stage-10 `ENVIRONMENT` file and existing fixtures are preserved. A previous image
ID is not relabeled or accepted as evidence for the new image. Capability probes
run only during explicit `run 110`, not `show` or status. They do not run TLS.
The subsequent measurement phase does run TLS.
