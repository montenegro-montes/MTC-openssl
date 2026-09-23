# MTC TLS experimental laboratory

This branch studies the experimental Merkle Tree Certificates draft alongside X.509. The active experiment surface is limited to MTC and X.509.

## Entry points

- `bin/base/mt-prepare`: base, MTC and capture images plus fixtures.
- `bin/base/mt-protocol-validation`: protocol, mutual-authentication and retry validation.
- `bin/performance/mt-handshake-performance`: native and PCAP handshake measurements.
- `bin/cryptographic_scaling/mt-cert-scaling`: certificate scaling and crossover studies.
- `bin/network/mt-network`: latency, bandwidth, loss and combined-network studies.
- `bin/containers/mt-containers`: current network Compose targets.
- `bin/artifacts/mt-report`: generated results and reports.

## Repository layout

| Directory | Purpose |
|---|---|
| `bin/` | User-facing launchers and HTML renderers |
| `campaigns/validation/` | Protocol and instrumentation validation |
| `campaigns/performance/` | Handshake performance |
| `campaigns/scaling/` | Certificate, tree and crossover scaling |
| `campaigns/network/` | Network-condition studies |
| `campaigns/common/` | Shared reporting, capture and image helpers |
| `docker/base/` | Base, experimental MTC and capture images |
| `docker/network/` | Network measurement images and Compose files |
| `src/mtc/` | Experimental MTC implementation and draft checks |
| `src/profiling/` | Native timing instrumentation used by MTC |
| `artifacts/` | Generated fixtures, observations and reports |

Run commands from the repository root. Campaign outputs use fresh directories below `artifacts/`. Use each launcher menu or `help` command for its staged workflow.

`bin/base/mt-prepare reset-all` requires typing `RESET ALL`. It removes generated laboratory data and project Docker resources while preserving tracked source and published `results/`.
