# Experiment campaigns

This directory contains the executable, reproducible campaign packages. Run every command from the repository root so that Compose files and `artifacts/` resolve consistently.

For an ordered execution that can be stopped and resumed across days, use:

```sh
bin/historical_campaigns/mt-campaigns init
bin/historical_campaigns/mt-campaigns list
bin/historical_campaigns/mt-campaigns status
bin/historical_campaigns/mt-campaigns next
```

Progress and timestamped result roots are stored locally in `.mt-state/`. The
manager exposes each initialization, test, preflight, smoke, full run, analysis
and audit as a separate step. `show STEP` prints its exact command; `mark STEP
skipped` records an intentional omission such as packet capture.

| Category | Scope |
|---|---|
| `performance/` | Comparable handshake time and size measurements |
| `validation/` | Functional, negative-case, transcript, retry, and native/PCAP validation |
| `scaling/` | Algorithm, chain-depth, proof-size, and crossover studies |
| `common/` | Shared capture and reporting code; not an executable campaign |
| `future_implementation/` | Experiments excluded from the current study |
| `historical_campaigns/` | Validated controlled, scaling, network, capture, and PCMA campaigns |

Raw data, generated fixtures and immutable source snapshots stay under `artifacts/`; moving them would invalidate recorded paths and hashes. Dockerfiles and Compose definitions live under `docker/`, while their build contexts continue to use the repository root. Each package README contains its commands and validation gates.

## Recommended execution order

Run experiments independently and finish each one before starting the next:

1. `historical_campaigns/controlled_n16_campaign/`: historical controlled N=16 comparison.
2. `historical_campaigns/scaling_campaign/`: Merkle population scaling.
3. `historical_campaigns/network_latency/`: isolated RTT effect.
4. `historical_campaigns/network_bandwidth/`: isolated bandwidth effect.
5. `historical_campaigns/packet_loss_campaign/`: isolated packet-loss effect.
6. `historical_campaigns/combined_network_campaign/`: representative combined profiles.

PCMA is a separate proof/cache study rather than a continuation of the network
campaign sequence. Stage A and A.2 select and validate the advertisement model;
Stage B validates it in end-to-end TLS. See
[`pcma/README.md`](historical_campaigns/pcma/README.md),
[`pcma_stage_a2/README.md`](historical_campaigns/pcma_stage_a2/README.md), and
[`pcma_stage_b/README.md`](historical_campaigns/pcma_stage_b/README.md).

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

## Start over without an archive

From the repository root, run:

```sh
bin/historical_campaigns/mt-campaigns reset-all
```

Read the warning and type `RESET ALL` to confirm. Any other answer or end of
input cancels before Docker is contacted. There is no `--yes` bypass. The same
action is available as option 6 in the campaign menu, even without an initialized
battery. Stop active campaign processes first.

The reset deletes `artifacts/` and `.mt-state/` without making a backup or
publication snapshot. It removes containers, networks and volumes labelled with
the laboratory Compose projects (including temporary `pcmab*` Stage B projects
and `certchainscaling`) and removes `mt-tls-*` image tags. Docker cleanup must
succeed before local files are deleted. A failure can leave Docker partially
cleaned; inspect the error before retrying.

Source files and published `results/` remain intact. Fixtures/results configured
outside `artifacts/` are not deleted. Other projects and the shared Docker build
cache are preserved; this is a reset of laboratory data and images, not a purge
of the Docker installation. Future builds can reuse that cache.

Then initialize a new battery and advance one step at a time:

```sh
bin/historical_campaigns/mt-campaigns init
bin/historical_campaigns/mt-campaigns next
```

A new battery records its normal progress and measurement outputs. The reset
itself creates no backup of discarded data.
