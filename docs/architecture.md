# Architecture and review guide

Run repository commands from the repository root. Start with `bin/` for routine
operation, `src/` for implementation, and `campaigns/` for experimental protocols.

## Repository responsibilities

| Directory | Responsibility |
|---|---|
| `bin/original_campaigns/` | Public commands: `mt-containers`, `mt-campaigns`, `mt-archive`, `mt-check-publication` |
| `src/integration/` | Initial Merkle wire encoding, bundle generation and OpenSSL TLS integration |
| `src/compact/` | Compact credentials, verification, OpenSSL patches and component runtime |
| `src/mtc/` | Experimental MTC encoder/verifier, TLS adapter, fixture builders and component runtime |
| `src/profiling/` | Timing instrumentation, OpenSSL patches and instrumented component runtime |
| `scripts/` | Shared internal fixture builders and initial laboratory runtime |
| `campaigns/` | Per-study configuration, orchestration, analysis and campaign tests |
| `tests/` | Initial laboratory integration and shared fixture-generation tests |
| `docker/` | Image builds and Compose service definitions |
| `tools/` | Developer inspection utilities |
| `docs/` | Protocols, methodology and review guides |
| `results/` | Published, checksummed evidence |
| `artifacts/` | Ignored local fixtures, keys and generated results |
| `codigoOriginal/` | Received sources retained with their original provenance |

## Suggested reading order

1. Read the root README for the research questions and experimental status.
2. Read `src/integration/mt_wire.h` and `mt_wire.c` for the initial wire format.
3. Review `src/compact/compact.c`, then its fixture builder and OpenSSL patch.
4. Review `src/mtc/core.py` and `mtc.c`, then `tls.c` and `patch.py`.
5. Review `src/profiling/profile.h` and `profile.c` for timing definitions.
6. Choose a study from `campaigns/README.md`; read its protocol, runner and
   analysis before interpreting its published results.

C, Python and shell files remain grouped by component. Component tests stay
beside that component where they use local imports or are copied together into
Docker. `test_tls.py` files require the TLS laboratory; they are not offline
unit tests. Campaign-specific tests stay with their campaign.

The `benchmark.py`, `serve.py` and `scenarios.py` files in components are runtime
adapters used by the Docker image chain. They are not interchangeable campaign
entrypoints. `src/mtc/prepare_scaling.py` is a shared fixture builder; its former
host runner is now `campaigns/original_campaigns/mtc_exploratory_scaling/run.py`.
PCMA Stage B native code stays under that campaign because its driver, cache
protocol and TLS callbacks implement the Stage B experiment.

## Build and runtime boundaries

The image chain is base → Compact → profiling → MTC → measurement → network.
Dockerfiles copy from `src/` but preserve `/opt/mt/integration`, `/opt/compact`,
`/opt/profiling`, `/opt/mtc` and the flat `/opt/lab` runtime interface. The PCMA
image contains a repository-shaped `/opt/pcma-repo/src/` tree for relative C
includes and source hashing.

`scripts/runtime/benchmark-initial.py` is installed as `/opt/lab/benchmark.py`
for compatibility with the initial runtime. It measures fresh client processes
for the original four scenarios; use a campaign runner for controlled studies.

## Migration and evidence

| Previous repository path | Current path |
|---|---|
| `compact/`, `integration/`, `mtc/`, `profiling/` | Matching directories under `src/` |
| `scripts/manage-containers.sh` | `bin/original_campaigns/mt-containers` |
| `scripts/manage-campaigns.sh` | `bin/original_campaigns/mt-campaigns` |
| `scripts/archive-results.py` | `bin/original_campaigns/mt-archive` |
| `scripts/check-published-artifacts.py` | `bin/original_campaigns/mt-check-publication` |
| `scripts/generate-*.sh` | `scripts/fixtures/` |
| `scripts/client.sh`, `scripts/server.sh` | `scripts/runtime/` |
| `scripts/benchmark.py` | `scripts/runtime/benchmark-initial.py` |
| `scripts/scenario.sh` | `scripts/lib/scenario.sh` |
| `mtc/run_scaling.py` | `campaigns/original_campaigns/mtc_exploratory_scaling/run.py` |

Update personal commands to the current paths; old host entrypoints are not
retained as duplicate scripts. Local `.mt-state/` progress remains in place.
Archived results and preservation manifests retain their original bytes and
historical paths. Resolve historical paths using this table or the recorded
commit; do not rewrite evidence to make it resemble the current checkout.
New campaign manifests record the current source paths. A source-layout change
requires newly built images for future runs; existing images retain their
previous source identity. Builds and TLS campaigns are manual operations.

## Validation of this migration

Offline checks passed: Python syntax for 131 files, shell syntax, all 35 Docker
COPY source operands and their ignore rules, management command listing,
publication checks, MTC draft vectors (12,807 inclusion evaluations), two
certificate-chain static tests, the packet-loss driver guard, mocked fixture
generation, and four native PCMA unit tests. The PCMA executable also compiled
against local Homebrew OpenSSL and returned its version without connecting.

Published evidence, received source files and the relocated preservation
manifest were compared byte-for-byte by SHA-256. Protocol component source
contents are unchanged; PCMA include paths changed to reference `src/compact/`.
Docker images were not rebuilt and no TLS experiments were executed.
