# Historical experiment campaigns

**Frozen archive.** Preserve these implementations for reproduction. New work
must copy only the required behavior into an active campaign and remove Compact
dependencies before use.

This category preserves the historical experimental line of the project:
controlled N=16 comparison, packet capture, Merkle population scaling,
network-condition campaigns and PCMA stages. Their scientific meanings and
result directories are unchanged.

| Directory | Experiment |
|---|---|
| `controlled_n16_campaign/` | Historical X.509, Compact and MTC comparison |
| `handshake_capture/` | Historical multi-scenario packet capture |
| `scaling_campaign/` | Original Merkle population scaling |
| `network_latency/` | Latency-only campaign |
| `network_bandwidth/` | Bandwidth-limited campaign |
| `packet_loss_campaign/` | Packet-loss-only campaign |
| `combined_network_campaign/` | Combined network profiles |
| `pcma/` | PCMA Stage A |
| `pcma_stage_a2/` | PCMA Stage A.2 |
| `pcma_stage_b/` | PCMA Stage B |

Commands must be run from the repository root using the new
`campaigns/historical_campaigns/<name>/` paths. The campaign manager already
uses these locations. Existing artifacts and publication snapshots have not
been moved or rewritten.

The [exploratory MTC scaling runner](mtc_exploratory_scaling/README.md) is kept separately from the controlled scaling study.
