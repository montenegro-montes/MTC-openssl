# Experiment campaigns

| Directory | Scope |
|---|---|
| `performance/` | Handshake time and size measurements |
| `validation/` | Protocol, retry, mutual-authentication and Native/PCAP validation |
| `scaling/` | Cryptographic profiles, tree sizes, chain depth and crossover studies |
| `network/` | Latency, bandwidth, loss and combined conditions |
| `common/` | Shared capture, reporting and image-chain code |
| `future_implementation/` | Work excluded from the current experiment |

Launch campaigns through the corresponding command under `bin/`. Raw data, fixtures and reports remain below `artifacts/`; `.mt-state/` stores resumable launcher state. Every scientific run must use a fresh output directory.
