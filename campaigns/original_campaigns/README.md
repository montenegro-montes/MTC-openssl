# Original experiment campaigns

This category preserves the first validated experimental line of the project:
the controlled comparison, Merkle population scaling, network-condition
campaigns, packet capture, and PCMA stages. Their scientific meanings and
result directories are unchanged; only their source location is grouped here.

| Directory | Experiment |
|---|---|
| `controlled_n16_campaign/` | Controlled N=16 authentication comparison |
| `scaling_campaign/` | Original Merkle population scaling |
| `network_latency/` | Latency-only campaign |
| `network_bandwidth/` | Bandwidth-limited campaign |
| `packet_loss_campaign/` | Packet-loss-only campaign |
| `combined_network_campaign/` | Combined network profiles |
| `handshake_capture/` | Optional TLS packet capture |
| `pcma/` | PCMA Stage A |
| `pcma_stage_a2/` | PCMA Stage A.2 |
| `pcma_stage_b/` | PCMA Stage B |

Commands must be run from the repository root using the new
`campaigns/original_campaigns/<name>/` paths. The campaign manager already
uses these locations. Existing artifacts and publication snapshots have not
been moved or rewritten.
