# PCMA Stage B — real TLS 1.3 integration and experimental validation

**Prepared for manual execution. No TLS experiment, smoke handshake, Docker
campaign or network-impairment experiment was run during preparation.** The
native executable compiles; offline native/Python tests exercise the real
serializers, partial proofs and cache. End-to-end TLS and full lab execution
remain unvalidated until the operator executes them.

## 1. Objective and relationship to Stage A/A.2

Determine whether the communication savings demonstrated in Stage A.2 translate
to real TLS byte/latency/CPU benefits. This is protocol validation, not another
advertisement search. Stage A/A.2 source and results stay unchanged.

The selected Stage-A.2 `analysis/summary.csv` reports audited ranges results.
`configs/stage-b1.json` records its path, SHA-256 and the best mean-net-saving
policy for each selected N/workload/budget. This is a deterministic design input,
not a new evaluation. Policy comparisons in A.2 used different seeds, so small
policy differences are not robust causal evidence. The campaign runner does
not tune policies or protocol behavior after seeing Stage-B results.

## 2. Confirmed Compact warm and PCMA TLS flows

See [PROTOCOL.md](PROTOCOL.md) for source functions, trust checks, native OpenSSL
boundaries and byte-for-byte layouts. The existing `src/compact/compact.c` source is
included unchanged by `native/tls.c`; it exports the original warm/cold functions
alongside the new PCMA functions. No existing OpenSSL app or scenario module is
patched by this laboratory.

```text
Compact cold: full MTP1 + signed root in EncryptedExtensions
Compact warm: preverified signed root; full MTP1 in EncryptedExtensions
PCMA ranges:  preverified signed root + root-scoped authenticated node state;
              PCA2 ranges in ClientHello; PCB1/MTP2 in EncryptedExtensions
```

All retain native TLS Certificate, CertificateVerify and Finished. Compact/PCMA
use RPK Certificate plus credential-to-SPKI binding. PQ uses X.509. PCMA learning
is staged during verification and persisted only after successful SSL_connect
and the driver's verification/control checks.

## 3. Wire protocol

PCMA extension type is **0xffa7**, separate from Compact **0xffa6**. The
ClientHello payload is exactly A.2 `PCA2 | 1 | ranges=4 | root[32] | U(N) |
U(count) | ranges`. Server payload is `PCB1 | u16(credential length) |
credential | u16(MTP2 length) | MTP2`. Root and tree identifiers are never
truncated. No cached hash is sent in ClientHello.

MTP2 is unchanged from A/A.2: magic, N, leaf, root, depth, bitmap length, bitmap,
then only required 32-byte siblings. Bitmap decoding is strict. Maximal ordinal
ranges describe exact nodes, not inferred descendants. Optional baseline PCA1
TLS encoding is intentionally omitted to keep a single protocol candidate.
Coordinates, bitmaps and hybrid are not alternative TLS modes.

## 4. Cache, server generation and client verification

`native/protocol.c` implements ranges, MTP2, LRU/upper-level and local PCS1
persistence. `native/tls.c` integrates it with actual OpenSSL custom-extension
and certificate-verification callbacks. The server has a verified MTP1 for the
selected credential and filters its siblings using decoded advertised state.
The client reconstructs the path, then performs the existing Compact trust,
identity, time, SPKI and cryptographic inclusion checks.

Logical storage remains 69 bytes per node. Budget defaults are 2/4 KiB; the
config supports integer KiB budgets up to native capacity, with explicitly
selected policies for any additional cells. PCS1 factors the common root out
on disk, so physical file/RAM size differs from logical budget. Cache files are
private and transactionally replaced only after successful authentication.
A new campaign starts with an absent cache file, and each budget has its own
independent trajectory. Warmup learning is retained into measured accesses.

The client/server are fresh processes per access, matching the previous
new-process methodology. Only the PCMA node file persists. Server restarts
select the correct credential/key/bundle before timing; there is no generic TLS
session cache, resumption, ticket or 0-RTT. Root/credential/key/cache-file setup
and cache-file commit are outside the timed handshake. ClientHello encoding and
pending proof verification/learning occur inside it. Each server handles one
connection; readiness uses a file, never a TLS probe.

## 5. Security, privacy and downgrade

All PCMA errors fail explicitly; fallback count is always zero. Missing required
state, malformed ranges/bitmap/proof, wrong root, stale cache, incorrect hash,
wrong credential and invalid coordinates never bypass inclusion or TLS checks.
No authenticated state is persisted from a failed client authentication.
The runner records failure rows and aborts, without hidden retries.

Advertising is explicitly opt-in through an operator-selected fixture mapping
of hostname, authority and signed root. It is not automatically enabled for
arbitrary servers. This does not authenticate an endpoint before ClientHello:
DNS redirection or observers can still learn the advertisement. History
inference, linkability, fingerprinting, cache probing and cross-service
correlation remain unresolved. This is an experimental prototype, not a
deployment recommendation. See PROTOCOL.md for trust-file and concurrency limits.

Negotiation cannot fall back silently to warm/cold. Those are separate explicit
scenarios. The PCMA verifier requires its extension and authenticated credential;
normal CertificateVerify/Finished remain mandatory. Loss of optimization must
never become loss of authentication.

## 6. Scenarios, fixtures and trust domains

Primary scenarios: `pq`, `pq-compact-warm`, `pq-compact-pcma`. Existing `pq-rpk`,
Compact cold, and both MTC scenarios are untouched and not included in this new
matrix. The driver does not replace their existing launchers.

The config references existing Stage-A fixture metadata and
`artifacts/certs/pq`. For each accessed leaf, the runner selects its actual
Compact credential/proof/bundle and corresponding key/certificate:
leaf 0 uses `server.pem/server.key`; other leaves use `issued/i.pem/i.key`.
Expected DNS is extracted from the verified credential (`server` or
`member-i.lab`). It verifies fixture proof/root identity and hashes all used
credential, proof, bundle, root, certificate, key and CA inputs before TLS.
Nothing is regenerated or overwritten. Fixture validity remains enforced by
native Compact/X.509 during execution; expired fixtures cause failure.

Secrets stay in the existing read-only artifacts mount. Manifests contain only
paths/hashes, not private-key bytes. Do not publish the artifact directory or
private cache files as part of releasing the source lab.

## 7. Trees, workloads, budgets and policies

Primary N: 16, 256, 1024. N=64 remains configurable with an explicit policy
selection. Workloads use the unchanged Stage-A generator: uniform, zipf and
clustered. One exact sequence per campaign is used for every arm.

```text
seed = base_seed + N*10000 + workload_index*100 + repetition
workload_index: uniform=0, zipf=1, clustered=2, targeted=3
```

The same seed/sequence is reused across network profiles for a selected B.2
cell. `sequences.json` saves exact leaves and deterministically shuffled arm
order before the first TLS handshake. A separate cache per PCMA budget makes
arm order irrelevant to cache semantics, while reducing fixed order bias.

Ranges policy snapshot (2 KiB / 4 KiB):

| N | uniform | zipf | clustered |
|---|---|---|---|
|16|LRU / LRU|LRU / upper-level|LRU / upper-level|
|256|upper-level / upper-level|upper-level / upper-level|LRU / LRU|
|1024|upper-level / upper-level|upper-level / upper-level|LRU / LRU|

## 8. TLS and network controls

TLS 1.3, X25519, TLS_AES_256_GCM_SHA384, ML-DSA-65 server keys, server-only
authentication, no tickets, no resumption. All three arms use the same newly
built driver and the same existing OpenSSL shared libraries from the validated
image. No OpenSSL library rebuild, ML-KEM or unrelated parser optimization is
introduced. Native controls check negotiated version/group/cipher, peer key
algorithm and nonresumption. Actual CertificateVerify scheme and peer-key
verification are recorded in raw endpoint JSON.

B.1 uses a normal isolated Docker **bridge** with no imposed delay/loss/rate.
Both endpoints' qdiscs are recorded and checked. This differs explicitly from
the older combined-network profile called `baseline`, which added 10 ms RTT.
B.1 honors the requested unconstrained baseline instead.

B.2 reuses `campaigns/historical_campaigns/combined_network_campaign/network.py` command generation
and validation: WAN adds 25 ms each way, 20 Mbps and 0.5% loss per egress;
constrained adds 50 ms each way, 5 Mbps and 1% loss per egress. These are netem
configured percentages, not a claim about measured bidirectional loss. There is
no new jitter, reordering, duplication or network model. Rate-limited profiles
reuse TBF → netem and existing queue/burst definitions. The runner does not add
ping/iperf measurements to the timed campaign.

## 9. Metrics and accounting

Raw CSV retains campaign/round/access/leaf/scenario/N/workload/seed/policy/budget/
profile, success/failure, complete native client/server JSON, cache-file hash
chain and log paths. Successful rows include:

- TLS handshake wall time, client CPU and server CPU;
- directional BIO transport bytes (TLS record stream, **not TCP/IP packet bytes**);
- directional plaintext handshake-message bytes, including handshake headers;
- ClientHello, PCMA extension including its four-byte extension header;
- server authentication message bytes = EncryptedExtensions + Certificate +
  CertificateVerify; this includes all EE contents, not just authentication;
- actual credential/MTP1 or MTP2 sizes and reused/transmitted hashes;
- logical cache nodes/bytes, hits/misses, additions/evictions and zero fallbacks;
- encoding, server advertisement parsing, range lookup, partial construction,
  cache lookup, reconstruction and verification component times.

The A.2 metric remains `advertisement + partial proof`, with MTP1-relative net
saving. Full observed plaintext TLS saving should equal that saving **+36 B**,
because warm already sends a 34-byte root offer and PCB1 removes two bytes of
root-length framing. Audit checks this. Record-stream savings can differ due
to TLS records/fragmentation. PQ's proof-only metric is unavailable, not zero.

CPU/monotonic timers use the same process-clock and message/BIO accounting
principles as `src/compact/metrics.c`. Setup and app/process/HTTP windows are not
interchangeable with handshake timing; this driver does not issue HTTP.
Subtimers overlap: lookup is inside reconstruction, and range lookup is inside
partial generation. Native PCMA defensively repeats Merkle verification while
staging learning; the separately labelled credential verifier includes the first
Merkle/SPKI/identity check. Do not sum overlapping timing components or claim
that the pure Merkle timer includes all credential verification.

## 10. Environment and manual build

Run from the repository root. Host tools: Python 3.10+, Docker Compose, a C11
compiler for optional local validation. The manual image build requires the
existing `mt-tls-network:latency` image. It reuses its OpenSSL 3.5.x installation
and adds the new executable plus tcpdump for optional captures. Matplotlib is
needed only for plots; reuse the existing PCMA plotting requirements.

```sh
# MANUAL BUILD — no TLS launched, but Docker build may be expensive
# Review the Dockerfile before running; preparation did not execute this command.
docker build -f campaigns/historical_campaigns/pcma_stage_b/Dockerfile -t mt-tls-pcma:stage-b-v1 .
```

The build produces `/opt/pcma-bin/pcma_tls`, `build-version.txt` and
`build-inputs.json`. The runner checks image binary/source hashes against the
workspace before any TLS operation. Rebuild a new versioned image after code
changes; do not silently reuse a stale image. Source and OpenSSL build/commit/
library hashes plus the image ID are retained in results.

For local compilation without Docker (OpenSSL must support native ML-DSA and
RPK APIs), choose a **new** output directory:

```sh
./campaigns/historical_campaigns/pcma_stage_b/build.sh /opt/homebrew/opt/openssl@3 /tmp/pcma-b-local-build
/tmp/pcma-b-local-build/pcma_tls --help
```

Local compilation is only a functional check; campaign comparisons use the
same pinned Docker image, not the host OpenSSL build.

## 11. Lightweight validation and plans

These commands never create a socket or start a container:

```sh
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh --help
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh --validate \
  --openssl-prefix /opt/homebrew/opt/openssl@3
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh --stage-b1 --plan
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh --diagnostic --plan
```

On Linux use your OpenSSL installation prefix, e.g. `/opt/openssl`. Validation
compiles only a small protocol shared library, runs native/Python round trips,
negative/trust/cache tests, parser/design and campaign-statistics tests. N=1024
checks manipulate coordinates, not large TLS campaigns. Tiny handcrafted
N=4/8 paths verify exact A.2 byte/cache equivalence. See VALIDATION.md for the
checks actually executed during preparation.

## 12. ONE manual diagnostic sequence

N=16, leaves `[0,1,2,8]`, baseline network, 2 KiB LRU, no warmup, one repetition.
There are **8 handshakes**: four Compact warm and four PCMA, paired across
credentials. This validates more than repeated access to one server.

```sh
# MANUAL EXECUTION — DO NOT RUN DURING PREPARATION
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh --diagnostic
```

It creates a unique result directory and prints its path. First review native
client/server logs, then audit that directory. A failed run is preserved and
cannot pass audit. Do not reuse or overwrite its output path.

## 13. Stage B.1

Defaults follow the controlled N=16 methodology: **10 independent campaign
repetitions**, **5 warmup** and **30 measured** logical accesses. Each independent
campaign resets PCMA state. Warmups are excluded from inference but included in
the state trajectory; those phases are saved explicitly. Thirty accesses are a
short real-TLS validation trajectory, not a repeat of A.2's 1000-access workload.

```text
3 N × 3 workloads × 10 repetitions = 90 campaign cells
Each access: PQ + Compact warm + PCMA 2 KiB + PCMA 4 KiB = 4 handshakes
Measured: 90 × 30 × 4 = 10,800
Warmup:   90 ×  5 × 4 =  1,800
Total:                    12,600 handshakes
```

PQ and Compact warm are not duplicated for each PCMA budget. Each PCMA arm is
paired to the same warm observation for that access. These are comparisons
within this new driver; historical TLS measurements are not silently pooled.

```sh
# MANUAL EXECUTION — DO NOT RUN DURING PREPARATION
B_RESULTS="artifacts/results/pcma-stage-b1-$(date +%Y%m%d-%H%M%S)"
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh --stage-b1 \
  --config campaigns/historical_campaigns/pcma_stage_b/configs/stage-b1.json --output "$B_RESULTS"
```

The script never runs B.2 automatically. A new Compose project is used for the
run and its containers/bridge are removed afterwards. OpenSSL server/client
processes are fresh per attempt; containers share the run, as in previous
shared-Docker-session experiments. This does not imply independent machines
or independently reset thermal/network environments.

## 14. Stage B.2 selection and execution

`configs/stage-b2-selection.json` is **disabled by default**. After reviewing
B.1, copy it, choose a small N/workload/budget subset and set
`selection_approved=true` with a written `selection_justification` referring to
B.1 evidence. Retain the frozen protocol. This is an explicit configuration
requirement, not automatic statistical selection or a request to run now.

```sh
cp campaigns/historical_campaigns/pcma_stage_b/configs/stage-b2-selection.json /tmp/pcma-b2-selected.json
# Edit /tmp/pcma-b2-selected.json after reviewing Stage B.1.
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh --stage-b2 --plan \
  --config /tmp/pcma-b2-selected.json
# MANUAL EXECUTION — DO NOT RUN DURING PREPARATION
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh --stage-b2 \
  --config /tmp/pcma-b2-selected.json
```

If the template's illustrative N=1024/clustered/2 KiB cell is explicitly retained,
three profiles × ten repetitions produce 30 campaigns and 3,150 handshakes
(2,700 measured +450 warmup; three arms per access). This is a planning count,
not a justified final selection or an execution result.

## 15. Audit and Stage-A.2 consistency

```sh
# MANUAL ANALYSIS — may read/replay many rows; launches no TLS
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh --audit --results "$B_RESULTS"
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh --check-model --results "$B_RESULTS"
```

Both commands run a complete audit including the A.2 model comparison. Checks
cover expected campaigns/rounds, every handshake, unique/balanced arms, exact
sequence/seed/root/fixture matching, negotiated TLS controls, no resumption,
byte equations, +36-byte plaintext framing adjustment, cache budgets/evolution,
before/after transaction chains, endpoint byte agreement and output hashes.
Model replay uses the real fixture credentials and exactly the saved access
sequence. It compares advertisement/proof sizes, reuse counts and the SHA-256
of the exact expected PCS1 persisted state after each access. It does not launch
TLS. Missing completion markers or inconsistent data fail loudly.

## 16. Analysis, plots and tables

```sh
# MANUAL ANALYSIS — launches no TLS; requires completed audited observations
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh --analyze \
  --results "$B_RESULTS" --output "$B_RESULTS/analysis"
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh --tables \
  --results "$B_RESULTS" --output "$B_RESULTS/tables"
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh --plots \
  --results "$B_RESULTS" --output "$B_RESULTS/plots"
```

Use another new output directory to rerun analysis. Plot dependencies can be
installed separately using `campaigns/historical_campaigns/pcma/requirements-plots.txt`. No tables or
figures are fabricated before data exist.

CSV/LaTeX outputs cover handshake and authentication bytes, net saving, latency,
CPU/components and paired wall-time difference with 95% campaign-bootstrap CI.
The analysis reuses existing quantile and paired-effect helpers. It computes
within-campaign medians and medians of access-paired effects, then resamples
**campaign effects** 10,000 times (seed 20260910), adapting the helper to a
configurable repetition count. Individual handshakes are not bootstrap units.
A single diagnostic campaign has no inferential CI.

Figures show bytes/latency versus N by workload/network/arm, net saving and
cache evolution versus position, proof/advertisement decomposition, reuse counts
and component processing. CSVs retain budget and network dimensions. Primary
paper comparison remains PQ X.509 vs Compact warm vs PCMA ranges; the main
PCMA contrast is warm vs PCMA. A CI including zero is unresolved timing, not
proof of latency equivalence. Outcome labels distinguish fewer bytes+lower
latency, fewer bytes+unresolved timing, fewer bytes+higher latency, and no
real-record-byte advantage. Do not optimize protocol after observing outcomes
without creating a new version/experiment.

## 17. Optional packet capture

A dedicated capture mode runs the same small diagnostic and captures client
eth0 traffic on port 4433. It does not run alongside the primary performance
campaign by default. TCP/IP packet sizes, retransmissions and fragmentation are
in the pcap; they are not silently added to BIO or handshake-message metrics.
ClientHello is visible; encrypted server records can be inspected for sizes,
not decoded as plaintext credentials without keys. No TLS key-log secrets are
created. Capture failure aborts rather than silently omitting the pcap.

```sh
# MANUAL EXECUTION — DO NOT RUN DURING PREPARATION
./campaigns/historical_campaigns/pcma_stage_b/run_pcma_stage_b.sh --capture
```

## 18. Output structure and reproducibility

```text
artifacts/results/pcma-stage-b-UNIQUE/
  manifest.json          protocol/config/fixture/source/image provenance
  sequences.json         exact leaves and arm order, written before TLS
  environment.json       endpoint binary, OpenSSL commit/build/library identity
  observations.csv       raw joined metrics, warmups and measured attempts
  nN-workload-profile-rXX/
    logs/                 native client/server log for each attempt
    *.ready               readiness markers, not connection probes
    network.json          actual endpoint qdiscs
    cache-BUDGET-POLICY.bin  private final PCMA state
    complete.json
    capture.pcap          dedicated capture mode only
  complete.json          whole-run completion and file hashes
  analysis/ tables/ plots/  explicit later commands, unique output directories
```

Every TLS campaign requires a new directory under `artifacts/results`. Producer
files use exclusive creation, except the intentionally transactional **new
Stage-B cache files** and uniquely named native client logs. Frozen experiment
files and prior results are never overwritten. Interrupted runs have no global
completion marker. The source-hash/build-input check prevents using a stale
image; manifests preserve source identity even with uncommitted code. Subsequent
encoding/cache/proof/timing changes require a new protocol version and image tag.

## 19. Known implementation and validation limits

The implementation includes native TLS callbacks, a native endpoint driver,
paired Docker runner, model audit, analysis, plots and tables. It is more than a
protocol skeleton. **Compilation/offline validation do not establish successful
end-to-end TLS operation**, Docker image construction, real-data audit behavior,
performance, capture quality or publication layout. Those remain manual checks.

No generic discovery/trust-domain negotiation, fallback, root rotation,
revocation, concurrent cache writers, crash-proof directory commit, privacy
mechanism, MTC expansion, broad network sweep or protocol optimization is added.
Persistent cache disk I/O occurs outside the handshake clock and may matter for
application latency; no overall application speedup is claimed. Fresh endpoint
process startup and Docker exec overhead are likewise outside that clock.
The shared host/session and short per-campaign sequences limit inference.
