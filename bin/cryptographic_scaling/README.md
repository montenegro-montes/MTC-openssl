# Cryptographic scaling

Run `bin/cryptographic_scaling/mt-cert-scaling` from the repository root. The launcher covers X.509 and experimental MTC fixture generation, validation, crossover analysis, boundary audits, mutual-authentication crossover, and the D=2–5 scaling verification.

The active profiles are ECDSA P-256/P-384/P-521, Ed25519, Ed448, ML-DSA-44/65/87 and SLH-DSA-SHA2-128s. Tree-size studies use the configured values shown by the launcher status. Outputs are new directories below `artifacts/`; `.mt-state/cert-scaling/` records resumable stage state.

Use the menu to initialize, inspect status, show a stage command, run one pending stage, or run the default battery. Image prerequisites are prepared through `bin/base/mt-prepare`. Existing output is never overwritten and its presence alone is not proof of successful validation.
