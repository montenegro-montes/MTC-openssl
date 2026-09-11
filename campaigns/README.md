# Experiment campaigns

This directory contains the executable, reproducible campaign packages. Run every command from the repository root so that Compose files and `artifacts/` resolve consistently.

| Directory | Experiment |
|---|---|
| `controlled_n16_campaign/` | Controlled N=16 comparison |
| `scaling_campaign/` | Merkle population scaling |
| `network_latency/` | Latency-only campaign |
| `network_bandwidth/` | Bandwidth-limited campaign |
| `packet_loss_campaign/` | Packet-loss-only campaign |
| `combined_network_campaign/` | Representative combined network profiles |
| `pcma/` | Progressive cross-credential Compact proof/cache simulation (prepared, not executed) |

Raw data, generated fixtures and immutable source snapshots stay under `artifacts/`; moving them would invalidate recorded paths and hashes. Dockerfiles and Compose definitions live under `docker/`, while their build contexts continue to use the repository root. Each package README contains its commands and validation gates.

## Recommended execution order

Run experiments independently and finish each one before starting the next:

1. `controlled_n16_campaign/`: controlled N=16 baseline.
2. `scaling_campaign/`: Merkle population scaling.
3. `network_latency/`: isolated RTT effect.
4. `network_bandwidth/`: isolated bandwidth effect.
5. `packet_loss_campaign/`: isolated packet-loss effect.
6. `combined_network_campaign/`: representative combined profiles.

PCMA is a separate proof/cache study rather than a continuation of the network
campaign sequence. See [`pcma/README.md`](pcma/README.md).

Completed historical campaigns do not need to be rerun merely to start a later
package, but their required fixtures, image IDs, reports and hashes must remain
available.

## Workflow used by every campaign

From the repository root:

1. Inspect `git status --short`, `git rev-parse HEAD`, Docker images,
   containers and required fixtures.
2. Choose a fresh timestamped directory below `artifacts/results/`.
3. Initialize reproducibility metadata and run the package's regression tests.
4. Run its preflight when available, inspect the status and network evidence,
   then run smoke when the package provides it.
5. Execute the full campaign without reusing or overwriting earlier output.
6. Generate analysis, plots and validation reports.
7. Run the final audit and confirm that tracked source and fixture hashes remain
   unchanged.
8. Commit that experiment separately and record the resulting commit hash in
   `metadata.json` and `report.md`.

Use the exact variable and commands shown in each package README. Never combine
results produced from different source commits without recording that
distinction. Do not commit private keys, packet captures, temporary Docker files
or large raw result directories.
