# Server-only MTC crossover by Merkle population size

This experiment studies the byte-level crossover between X.509 server-only authentication and MTC-experimental landmark authentication as the Merkle population size `N` varies.

It extends the chain-depth sensitivity experiment:

- `chain_depth_server_only`: fixed `N=16`, varies X.509 chain profile.
- `crossover_n_server_only`: varies `N`, keeps controlled TLS settings, and computes the first `N` where MTC becomes byte-efficient relative to X.509.

## Fixed TLS configuration

All measurements must keep TLS 1.3, X25519, TLS_AES_256_GCM_SHA384, server-only authentication, no client authentication, no session tickets, no resumption, and no 0-RTT.

## X.509 baselines

The X.509 baselines are inherited from `chain_depth_server_only`: `direct-server`, `ca-server`, and `root-intermediate-server`.

These names are preferred over informal L1/L2/L3 terminology because the relevant TLS quantity is the authentication material transmitted in the Certificate message.

## MTC configuration

The MTC configuration is `auth_family=mtc-experimental`, `mtc_mode=landmark`, pre-distributed `trust.bin`, and variable Merkle population size `N`.

The comparison is therefore a byte-level authentication transport comparison. It does not claim that trust distribution disappears.

## Pilot matrix

Initial profiles: `ecdsa-p256`, `ecdsa-p384`, `mldsa65`, `slhdsa128s`.

Tree sizes: `N=2`, `N=4`, `N=8`, `N=16`, `N=32`, `N=64`.

X.509 baselines: `direct-server`, `ca-server`, `root-intermediate-server`.

## Main outputs

The summary should produce `summary.csv`, `mtc-vs-x509-by-n.csv`, `crossover-n.csv`, `crossover-n-table.tex`, `manifest.json`, and `README-results.md`.

## Crossover definition

For each `(profile, chain_profile)`, define the byte-level crossover as the first tested tree size `N` satisfying:

```text
MTC Certificate-message bytes < X.509 Certificate-message bytes
```

If no tested `N` satisfies the condition, report `none`. If all tested `N` satisfy the condition, report the smallest tested `N`.

## Notes

Latency must be interpreted separately from bytes. MTC primarily reduces transmitted authentication material. For algorithms dominated by expensive signature operations, especially SLH-DSA, byte savings may not translate into proportional wall-clock reductions.

## Boundary audit integration

`boundary_audit.py` consumes the exact boundaries calculated by
`cert_chain_scaling/crossover_extended.py`. For each crossover within the native
`N<=256` D=2 range, it generates and measures only `N-1` and `N`. The audit passes
when the observed MTC Certificate message is smaller than the X.509 reference at
`N-1` and greater than or equal to it at `N`. The launcher exposes this as stage
`102.crossover-boundary-audit`; it remains outside the default workflow because
it creates fixtures and performs TLS handshakes.
