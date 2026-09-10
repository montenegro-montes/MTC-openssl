# Experiment campaigns

This directory contains the executable, reproducible campaign packages. Run every command from the repository root so that Compose files and `artifacts/` resolve consistently.

| Directory | Experiment |
|---|---|
| `paper_campaign/` | Controlled N=16 comparison |
| `scaling_campaign/` | Merkle population scaling |
| `network_latency/` | Latency-only campaign |
| `network_bandwidth/` | Bandwidth-limited campaign |
| `packet_loss_campaign/` | Packet-loss-only campaign |
| `combined_network_campaign/` | Representative combined network profiles |

Raw data, generated fixtures and immutable source snapshots stay under `artifacts/`; moving them would invalidate recorded paths and hashes. Dockerfiles and Compose definitions live under `docker/`, while their build contexts continue to use the repository root. Each package README contains its commands and validation gates.
