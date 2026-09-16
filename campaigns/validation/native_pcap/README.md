# Native ↔ PCAP paired timing validation

This validation campaign checks the relationship between the native OpenSSL timing
instrumentation and independent packet-capture timing.

This is an instrumentation-validation experiment, not an authentication
performance comparison.

## Scientific question

Determine whether native and PCAP measurements of the same successful TLS
connection behave coherently across controlled network conditions while
preserving their different clock domains and measurement boundaries.

No equality between Native and PCAP timing is assumed or required.

## Timing pairs

The three diagnostic pairs are:

- Native TCP:
  `tcp_connect_wall_ms_native`

  versus PCAP TCP:
  `tcp_connect_wall_ms`

- Native TLS:
  `handshake_wall_ms`

  versus PCAP TLS:
  `tls_from_pcap_wall_ms`

- Native full connection establishment:
  `connection_establishment_wall_ms_native`

  versus PCAP full connection establishment:
  `connection_handshake_wall_ms`

All reported paired differences use:

    Native - PCAP

The full timing values are directly measured values. They must not be
reconstructed as TCP + TLS.

## Timing semantics

Native and PCAP measurements use different clocks and boundaries.

Native TCP covers the current OpenSSL client connection operation from its
instrumented entry until successful connection return. It may include resolver,
address-selection, socket and related client-side work.

Native TLS remains:

    SSL_CB_HANDSHAKE_START -> SSL_CB_HANDSHAKE_DONE

Native full connection establishment starts at the native connection-operation
entry and ends at that same handshake-done event.

PCAP TCP is:

    first TCP SYN -> TCP established

PCAP TLS is:

    ClientHello -> client Finished

PCAP full connection establishment is:

    first TCP SYN -> client Finished

Therefore Native/PCAP validation does not treat Native and PCAP values as interchangeable
measurements and does not derive correction factors between them.

## Authentication scenario

Use exactly:

    pq

Native/PCAP validation does not compare X.509, Compact Merkle and MTC authentication
performance. One fixed PQ X.509 scenario is sufficient to validate the timing
instrumentation.

Keep fixed:

- TLS 1.3
- X25519
- TLS_AES_256_GCM_SHA384
- server-only authentication
- no tickets
- no resumption
- N = 16
- existing frozen fixtures
- existing measurement implementation

## Network conditions

### local

Use:

    compose.network-latency.yaml

with:

    additional RTT = 0 ms
    bandwidth = unconstrained
    loss = 0%

No artificial qdisc delay is applied.

### latency-100

Use:

    compose.network-latency.yaml

with:

    NETWORK_HALF_DELAY_MS = 50

The intended additional RTT is 100 ms:

    client egress delay = 50 ms
    server egress delay = 50 ms

No artificial bandwidth limit or packet loss is configured.

### constrained

Use:

    compose.network-combined.yaml

with the existing constrained profile:

    additional RTT = 100 ms
    half delay = 50 ms
    bandwidth = 5 Mbit/s
    independent per-egress loss = 1%

Preserve the existing combined-network qdisc hierarchy and validation rules.

Do not reimplement the network configuration.

## Association

Successful measured observations must be associated fail-closed using:

    campaign_id
    round_id
    scenario
    is_warmup

and, for successful TLS handshakes:

    client_random

The PCAP association must refer to the same TLS connection.

Do not associate observations using timestamps, filename proximity or
execution order alone.

## Populations

PCAP-enabled observations form a separate validation population.

Do not merge Native/PCAP validation observations into existing uncaptured scientific
performance campaigns.

Native/PCAP validation does not modify historical campaign results.

## Preflight

Before the full validation, execute only:

    3 conditions
    x (1 warmup + 1 measured pq handshake)

for a total of:

    3 measured PCAP-enabled observations
    3 uncaptured warmup observations

The three measured observations must contain all six timing metrics and pass
identity/association checks.

The constrained preflight must also pass its network validation.

An independently measured host monotonic probe wall duration must be retained
for network probes. A reported ping RTT greater than that independently
measured probe wall duration is physically inconsistent and must fail closed.

The probe wall duration is an integrity bound only. It is not a network timing
metric.

Do not proceed to the full Native/PCAP validation validation if the preflight fails.

## Full validation

Only after a successful preflight:

    3 conditions
    x 5 warmups
    x 30 measured pq handshakes

Total:

    15 warmups
    90 measured paired Native/PCAP observations

Warmups are not part of the paired statistical analysis.

## Primary outputs

Produce at least:

    metadata.json
    preflight-status.json
    paired-observations.csv
    validation-summary.csv
    validation-summary.json
    report.md

Preserve raw per-condition evidence including:

    samples.csv
    warmups.csv
    pcap-metrics.jsonl
    PCAP files
    capture status
    network probe output
    network validation
    qdisc evidence

## Paired analysis

For every successful measured observation compute:

    delta_tcp_ms =
        tcp_connect_wall_ms_native
        - tcp_connect_wall_ms

    delta_tls_ms =
        handshake_wall_ms
        - tls_from_pcap_wall_ms

    delta_full_ms =
        connection_establishment_wall_ms_native
        - connection_handshake_wall_ms

Report per condition:

- number of attempted measured handshakes
- number of successful TLS handshakes
- number of valid Native/PCAP pairs
- median Native timing
- median PCAP timing
- median paired difference
- 95% bootstrap CI for the median paired difference

Use 10,000 bootstrap resamples of paired observations within each condition.

Secondary descriptive analysis may include rank correlation and distribution
summaries, but Native/PCAP validation must not claim equivalence from correlation.

Do not:

- force Native = PCAP;
- calculate a correction factor;
- reconstruct full timing as TCP + TLS;
- mix captured and uncaptured populations;
- use Native/PCAP validation to rank authentication schemes;
- rerun or overwrite historical scientific campaigns.

All deviations, missing measurements, failed TLS attempts and failed capture
associations must remain explicit.

## Three-condition preflight execution

`run.py --preflight --root <initialized-root>` now executes local, latency-100
and constrained in order, with exactly one uncaptured warmup and one captured
measurement per condition. It stops on the first failed prerequisite or result;
existing preflight outputs are never overwritten or retried automatically.

The latency server receives root netem delay 50ms before qdisc inspection and
probing. The constrained server and client reuse the historical Combined helper
for root TBF 5Mbps followed by child netem delay 50ms/loss 1%; this is not a
root-delay-only configuration. Existing Combined reverse-bandwidth validation
and RTT ±10ms are preserved. Latency uses ±15ms; local median RTT must be ≤3ms.
The independent ping wall-time integrity check remains fail-closed.

The frozen tested network/capture image IDs are passed explicitly to Compose.
Each result records server/probe-client/measured-client qdisc evidence, network
validation, TLS/capture/analysis success, client_random pairing, all three timing
pairs and actual/capture/extractor SHA-256 integrity. The aggregate gate is
`preflight-status.json`; per-condition evidence is under `preflight-<condition>`.

At the initial preflight-only stage, `--full` remained blocked. The prepared full
entrypoint below now requires explicit immutable preflight evidence and a new
output root; it has not been executed.

Native timing remains primary, especially `handshake_wall_ms`; PCAP is an
independent observation. Captured and uncaptured populations remain separate.
There are no correction factors and no reconstruction of full timing as TCP+TLS.
This preflight does not quantify packet-capture overhead.

## Latest preflight evidence

The preflight at the preserved earlier preflight directory
passed local. Latency-100 passed both endpoint qdisc checks (50ms per egress),
measured median RTT 102ms, TLS and packet capture, but Stage-1 analysis failed
closed because the PCAP contains two TCP streams on port 4434. Stream 0 contains
one ACK from another connection; stream 1 contains the measured ClientHello
matching the native client_random. No timestamp/nearest-stream guessing was used.
The runner stopped before constrained and full remains blocked.

The earlier `20260916T150705Z` output retains a client import failure before any
TLS handshake. The override now sets PYTHONPATH=/opt/measurement; a network-disabled
`measure.py --help` invocation verified the corrected import.

No successful observation was repeated to replace its measured values. Further
work must address explicit stream association using the existing extractor's
`tcp_stream` capability, preserving these failed diagnostics and all raw values.

## Deterministic ClientHello stream association

Native/PCAP validation capture analysis opts into `--client-random` through the shared core.
Native client_random → matching TLS ClientHello → unique tcp_stream → the existing
Stage-1 extractor restricted to that stream. Tshark supplies the protocol match;
no separate packet parser, first-stream rule or timestamp heuristic is used.
Repeated ClientHello observations on the same stream (e.g. retransmission) do not
create a second candidate. Missing/malformed random, no match, multiple matching
streams, a conflicting configured stream or mismatched extractor identity fail
closed. Existing tuple, keylog and PCAP SHA-256 checks remain in force.

Unrelated traffic remains in the raw PCAP/packet table; the measured stream is
selected by the exact protocol identifier, not by ignoring packets heuristically.
Native timing and Native-minus-PCAP differences are unchanged. This code has only
been checked offline; latency-100 and constrained are not newly declared PASS.
Failed preflight evidence is preserved and `--full` remains blocked. Manual reruns
must use a fresh initialized root with a passing regression gate.

## Prepared full execution — manual only

**Native/PCAP validation three-condition preflight: PASS**, following the user-run preflight at
the approved immutable preflight directory.
**Native/PCAP validation full scientific execution: NOT EXECUTED.** This remains instrumentation
validation, not an authentication-performance experiment.

Both modes share `execute_condition`: preflight retains one warmup and one
measurement; full uses five warmups and 30 measured attempts per condition.
Local, latency-100 and constrained remain unchanged: **15 total warmups and 90
measured attempts**, exactly one `pq` scenario. Capture is measured-only, and the
shared capture session receives the measured count solely for coordination sizing.
Server/client qdisc and historical reverse-only Combined bandwidth gates are
unchanged.

Full constrained measurement alone enables failure-aware recording. Nonzero TLS
returns/timeouts produce identity-bearing `failures.csv`, raw logs and available
native diagnostic sidecars using NATIVE_CONNECTION_METRICS. TCP is retained only
when actually measured; incomplete TLS/full values remain null, never zero or
TCP+TLS. Warmup failures are counted separately. Local/latency and preflight still
fail on a TLS failure. Missing required evidence after a reported successful TLS
handshake is an infrastructure error, not a reliability outcome.

Failed measured constrained attempts reuse `allow_failed=True`. With a valid
client_random, exact ClientHello selection remains required. Without a ClientHello
random, only the established unique observation-tuple/strict incomplete-stream
analysis is available; ambiguity still fails. A clean capture with zero recorded
and zero filter-received packets is retained as unavailable only for a failed
connection with no native TCP success and no client_random. Capture corruption,
startup/finalization errors, invalid hashes and ambiguous identity invalidate the
run. Partial attempts never create successful timing pairs or TLS/full deltas.

Successful pairing requires the complete campaign/round/scenario/is_warmup tuple,
matching Native/PCAP/extractor client_random, client_random association confidence,
integer tcp_stream, keylog identity and actual/capture/extractor PCAP SHA-256.
CSV/JSONL order is irrelevant. Successful and failed measured rows must exactly
cover all 30 unique attempts; warmup rows/failures cover all five warmups.
Per-condition accounting separates attempts, TLS successes/failures, successful
pairs and incomplete/unpairable observations.

`paired-observations.jsonl` is derived audit data, per condition and aggregated;
it preserves stream/hash/identity, all three timing pairs and **Native−PCAP**
differences. Original samples, failures, PCAP metrics, captures, summaries and
logs remain canonical evidence. Full-status.json contains network/image/source
validation, reliability counts and paired summaries.

For each condition/delta, bootstrap uses **10,000 paired-observation resamples**
and seed **900009**, resampling a shared observation-index vector for all three
deltas. Report n, median and the nearest-rank 2.5%/97.5% bootstrap median limits.
Only successful measured pairs enter analysis; conditions remain separate. Fewer
than two successful pairs explicitly fails the analysis instead of inventing a
CI. Small surviving samples remain a limitation, not evidence of equivalence.
No optional correlation/equality tests were added.

`--full` requires an explicit `--preflight-root`: passing tests, passing aggregate
and all three condition statuses, validated original pairs/hashes and unchanged
fixture/protocol inventories. The approved root is read-only and referenced with
an evidence-hash inventory; it is not copied or regenerated. Full writes a new
source snapshot and refuses an existing output root, retry or overwrite. It never
runs preflight or rebuilds images automatically.

One exact, auditable source transition is listed in `source-transitions.json`:
the shared core's successful stream selection is unchanged; failed attempts
without client_random may use its pre-existing incomplete mode. Only the recorded
before/after digest pair is accepted against older preflight source inventories;
any other drift fails. The full output records this transition and freezes current
Native/PCAP validation sources. Existing preflight source snapshots and raw evidence stay intact.

Manual execution, after review:

```sh
PREFLIGHT_ROOT="<approved-preflight-root>"
FULL_ROOT="artifacts/results/native-pcap-full-$(date -u +%Y%m%dT%H%M%SZ)"
python3 campaigns/validation/native_pcap/run.py --full --root "$FULL_ROOT" --preflight-root "$PREFLIGHT_ROOT"
```

Native remains primary, especially handshake_wall_ms. PCAP remains independent
on-wire observation; captured observations stay separate from uncaptured scientific
populations. No correction factors, equality/equivalence claims or retrospective
correction of historical results. Full timing is directly measured, never TCP+TLS.
This study does not quantify packet-capture overhead.
