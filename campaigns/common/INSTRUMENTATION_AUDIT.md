# Stage 8 instrumentation audit — 2026-09-16

Source-level native timing and shared full/partial PCAP definitions pass offline
validation. `handshake_wall_ms` remains primary TLS performance instrumentation;
PCAP is independent on-wire observation, never a timing replacement or calibration.
BIO counters, TCP payload, IP and frame counts have different boundaries/headers.
Captured and uncaptured runs remain separate populations; warmups are uncaptured.

## Corrected pre-existing compatibility defects

Controlled N16's client folder mount hid the copied PCAP module, and its capture
shim depended on a repository layout absent inside the capture container. The
runner now mounts the common module explicitly for the instrumented client and
uses the common capture command/session. Controlled and latency now use the
existing bounded shared session to stop pending requests before extraction and
namespace teardown. No network/scenario/timeout/statistical definitions changed.

The controlled driver now accepts both known benchmark summary versions: the
legacy line needing null filtering and the current already-filtered line. Unknown
summary drift is still rejected. Regression mocks now include tcpdump's required
captured-packet counter. Deterministic tests cover the corrections without TLS.

## Installed-image readiness blocker

Read-only, network-disabled inspection of `mt-tls-network:latency` found no native
init_client start/done hooks and no native metric emission in its measurement C
source. Its installed OpenSSL binary SHA-256 is
`2a6180ec345856b1e60bbf0028df02f082ac66c7f036e3ae18229c0dbc5be729`.
The earlier native/PCAP smokes compiled corrected clients inside disposable
containers; their numeric metrics do not certify this installed scientific binary.
Before paired native/PCAP validation or scientific runs requiring the new metrics,
refresh and validate the measurement/network image chain against frozen sources.
Stage 8 does not build images or run a new TLS attempt.

## Preserved methodology limitations

Combined probes both iperf directions but gates the last/reverse result. Preserve
this behavior now; consider independently recorded directional gates in a future,
versioned methodology revision rather than changing historical acceptance.

The loss smoke recorded four ICMP values near 274,494–274,495 ms, also present in
ping's own summary, despite a total probe duration of 2,806 ms. This is not caused
by the Python parser or conversion to seconds. Root cause is unresolved; existing
median acceptance can pass with a small number of such outliers. Investigate the
Docker/host clock and probe environment before scientific collection; do not infer
actual network latency or silently change the frozen validator from this smoke.

Controlled/latency/bandwidth retain an 8-second observation finalization wait;
loss/combined explicitly allow 12 seconds. Shared host finalization allows 12
seconds. The core separately bounds drain (1.2 s), SIGINT close (5 s) and
readability (5 s); an infrastructure deadline can mark capture unavailable while
leaving native TLS accounting intact. These bounds are not harmonized for style.

All inspected smoke populations are marked integration-only, non-scientific and
non-comparable. Legacy latency metadata lacks explicit pcap_enabled and complete
native timing records; do not invent them. Historical artifacts remain untouched.

## Stage 8.1 remediation

Remediation source commit: `7540d3641f4d1ae206d8ca4c6b65c1d2b0c1c983`; working tree was dirty with the reviewed Stage-8 corrections. No commit, push or tag was created.

### Review of Stage-8 changes

| File/change | Classification | Review |
|---|---|---|
| Controlled measure.py | Correctness fix | Accepts both known summary hooks; rejects unknown drift; preserves null filtering. |
| Controlled run.py | Correctness fix | Explicit common module mount avoids shadowing; existing shared session finalizes capture before teardown. |
| Controlled test_capture.py | Regression tests | Packet counter fixture, known/unknown driver versions, mount and exception-finalization coverage. |
| Latency run.py | Correctness fix | Existing shared bounded session replaces premature extraction/teardown. |
| Latency test_pcap_adapter.py | Regression test | Checks shared session before post-measurement namespace operations. |
| compose.measurement.yaml | Correctness fix | Capture invokes explicitly mounted shared core instead of missing repository-layout shim. |
| Handshake-capture README and audit document | Documentation clarification | Strict success and explicit partial analysis are distinguished; original blocker preserved. |

No reviewed change was unnecessary or reverted. PCAP-OFF remains a no-op session and receives no extra client mounts. Scenario, count, timeout, TLS and statistical definitions remain unchanged.

### Dependency/root-cause evidence

The native patch belongs to profile, not measurement. The chain is compact → profile → MTC → measurement → network/capture. All four network campaigns use `mt-tls-network:latency`; their campaign-specific scripts are mounted, not separately compiled binaries. Rebuilding parent tags does not update existing children.

The old profile/MTC/measurement/network layers form exact parent prefixes. Installed profiling patch SHA-256 was `ade327aaafc7435f02ece6d3885faa48b7fe4445e1b491657b584dc1a31750c2`, versus current `1b8c12fc513c7794a58ccdf102990dca55717963891d8bb7c5e10423a48bb719`; metrics source also differed. Native commit `3bfb52a` (2026-09-16 11:30:43 +0200) postdates the old network build (08:44 UTC). Measurement copied the already-stale MTC source tree and only patched setup accounting. This proves stale profiling ancestry, rather than a wrapper/PATH defect. No evidence requires disabling Docker cache.

A further concrete context defect was corrected: measurement COPY references `campaigns/common/pcap_capture.py`, but its Dockerfile-specific ignore rules excluded it. Added only the two necessary inclusion rules and a deterministic regression.

### Rebuild provenance

Each command used repository root context and normal cache: `docker build --progress=plain -f docker/original_campaigns/Dockerfile.<name> -t <tag> .`. No `--no-cache` or protocol patch workaround. Compact/base images were not rebuilt.

| Tag | Before image ID | After image ID |
|---|---|---|
| mt-tls-profile:local | `sha256:93d5493c57dfa7a66c170d2ba9e03ff95182563aaade540eaec35c068b871448` | `sha256:3fffedb4a6534bb05adfddc429884fc689c451f2692e86f2ea6c35c2e3b55bf5` |
| mt-tls-mtc:local | `sha256:7172bbe8962801992dd7c840de5f9132062e75a3fbcaa2f33281a0e2f45fe9de` | `sha256:2cfcce849af47deca3d8bf769a7f903c78bfd13727b41bbb0a3a4cfaca9790cd` |
| mt-tls-measurement:local | `sha256:1d67a8b9c6db4edd60bed01a176775085345c44dbde6767a2ee26edefcd8cd4c` | `sha256:c8b011844dedf98032f9213ff8e525cb706e497e056bb8228485fad6d30a0cb4` |
| mt-tls-network:latency | `sha256:7ad42238e6d670908687997d37795c0f931242eb62158805d61261fc9823338b` | `sha256:ee947a241409af550f3d204b2403ace46fc5a088e493c061263621a7867a081e` |
| mt-tls-capture:local | `sha256:6cf2ce1a51f595a352cdc0b5f96513e4224cb5291bbb0c041ffb08bcaf06aec4` | `sha256:87546bfa65359c96958a10a55ce40af00beeebdc746ef07ac85a9867758cfbc7` |

Old network executable SHA-256: `2a6180ec345856b1e60bbf0028df02f082ac66c7f036e3ae18229c0dbc5be729`. New measurement/network executable SHA-256: `2497ae3631612cbcf7637118756d3c3cec8de77a1b0759a7dd93000ed6b745b2`.

The campaign command is `/opt/measurement/openssl.sh`, which executes `/opt/openssl-measurement/bin/openssl` with `LD_LIBRARY_PATH=/opt/openssl-mtc/lib:/opt/oqs/lib`. Bare `command -v openssl` selects `/opt/openssl/bin/openssl`; campaigns intentionally use the explicit wrapper. `ldd` resolves SSL/crypto to MTC libraries; measurement and network binary/library hashes match exactly. OpenSSL is 3.4.7 on linux-aarch64. The inherited OpenSSL build timestamp alone does not establish instrumentation freshness.

### Runtime validation

| Disposable check | Native TCP ms | Native TLS ms | Native full ms |
|---|---:|---:|---:|
| measurement-native (one PCAP-OFF handshake) | 0.870875 | 2.867 | 3.897625 |
| latency-native (one PCAP-OFF handshake) | 0.195083 | 0.94325 | 1.1645 |

Both actual installed campaign executables emitted numeric native fields and passed nonnegative TCP, positive TLS and full≥TCP/TLS guards. Full remains directly measured; no sum-equality requirement. Disposable EC X.509 material was used solely for instrumentation checks; PQ/MTC scientific scenarios were not run.

Combined, bandwidth and loss use the same network image and explicit measurement wrapper; binary/library identity proves the constrained path without an additional Combined handshake.

One additional PCAP-enabled latency handshake passed Native emission, capture, extraction, association and the complete SHA-256 chain (`165df91b90a455ecdca97099422313f59ec75c1bd5f6f3d39b15e6c87d9bfb04`). It used the rebuilt capture sidecar and unmodified shared core/extractor; no in-container recompilation. All three smokes are integration-only, non-scientific and non-comparable. Disposable containers/namespaces were removed; historical results and fixtures were untouched.

Post-build deterministic validation: native 1, common 3, extractor 6, Controlled 14, latency 4, bandwidth 8, loss 22, Combined 21, reporting 14 = 93 unit tests PASS; seven frozen guards PASS; 79 Python and 11 Bash syntax checks and ten OFF/ON Compose configurations PASS.

### Ping anomaly

Original raw lines retain icmp_seq 197–199 `time=274494 ms`, seq 200 `time=274495 ms`; ping summary reports 200 transmitted/199 received, time 2806ms and max 274494.558ms. Original and rebuilt images both use iputils ping 20221126. The recorded tool output is anomalous; underlying cause remains UNRESOLVED, not a demonstrated Python parser defect.

Scientific command remains `ping -n -c "$LOSS_PROBE_PACKETS" -i 0.01 -W 2 server || true`, normally 200 packets. `-W 2` is a reply-wait option, not a whole-process deadline; no `-w` deadline or `-D` timestamp prefix is used. Collection captures one Compose subprocess output then appends stderr; no evidence proves stale replies, mixed invocations, ICMP identifier contamination or clock-source failure. Old wall evidence is ping’s own summary, not independently instrumented process wall time.

A single bounded reproduction used the same 25ms/1% netem on both disposable namespaces, with 20 probes, a 15s outer diagnostic bound and POSIX locale. Wall duration 0.375373s; RTT min/median/max 50.1/52.05/104.0ms: NOT REPRODUCED, not fixed. No retry/search sweep. Scientific median/loss tolerances, parser and sample counts remain unchanged.

### Stage 8.2 — ping probe integrity

The historical anomalous ping output is CONFIRMED IN RAW TOOL OUTPUT. Its underlying root cause remains UNRESOLVED. It is not attributed to iputils, netem, Docker, the kernel, or the Python parser without supporting evidence.

A second disposable diagnostic used 200 probes and an independent host-side monotonic timer around the complete `docker compose run --rm client probe` subprocess. It produced 199 RTT observations, 0.5% measured loss, RTT min/median/max 25.0/25.5/51.1ms, and an external wall duration of 3162.216ms. The historical approximately 274494ms RTT anomaly was NOT REPRODUCED. This diagnostic was not an exact reproduction of the symmetric scientific network condition because the disposable server namespace had been disconnected/reconnected while adding its DNS alias; it is retained only as probe-integrity evidence and is not scientific campaign data.

Packet-loss collection now records `probe_wall_ms` using host `time.monotonic_ns()` around the complete probe subprocess. After parsing the raw ping output, a fail-closed integrity guard requires the reported maximum RTT not to exceed that independently measured subprocess wall duration. A non-positive wall duration is also rejected. Because the measured wall includes Docker Compose/container startup and teardown overhead, it is a conservative upper bound rather than a timing metric for network performance.

The guard does not alter or filter RTT observations. It does not remove outliers, impose a heuristic max/median ratio, introduce an arbitrary RTT ceiling, or change the existing configured-RTT median gate, loss acceptance, probe count, qdisc validation, TLS measurement, or statistical methodology. If an impossible RTT/wall relationship occurs again, the campaign aborts rather than repairing or discarding the observation.

`probe_wall_ms` is stored in new per-campaign `validation.json` records and propagated to `network-validation.csv`. Historical campaign records predate this instrumentation; their wall duration is not reconstructed or inferred. Reanalysis therefore represents missing historical `probe_wall_ms` as null while retaining fail-closed access for all previously mandatory validation fields.

Deterministic regression coverage includes a normal 50ms RTT with a 3000ms wall duration, the historical-shape 274494ms RTT with a 3000ms wall duration, and rejection of a non-positive wall duration. `git diff --check`, Python compilation of the modified packet-loss modules, and `test_network.py` PASS.

Stage 8.2 disposition: historical anomaly CONFIRMED IN RAW TOOL OUTPUT; root cause UNRESOLVED; bounded reproductions NOT REPRODUCED; correctness-supported fail-closed mitigation IMPLEMENTED AND TESTED. No scientific results or historical fixtures were modified.

### Final readiness

Stage-8 corrections/source native instrumentation, rebuilt measurement/network instrumentation, runtime emission, association/integrity, PCAP regression and image/source consistency: PASS. Capture lifecycle: PASS WITH DOCUMENTED LIMITATIONS (bounded waits can mark infrastructure unavailable).

Stage-9 local, latency and constrained-loss instrumentation prerequisites: PASS; their dedicated Stage-9 fixture/network/output preflight remains required. The historical ping anomaly remains unresolved, but Stage 8.2 provides a correctness-supported fail-closed integrity guard based on an independently measured host monotonic probe wall duration. Overall paired validation readiness: PASS FOR PREFLIGHT. No scientific Stage-9 campaign has been executed.

Combined’s reverse-only bandwidth acceptance remains unchanged and documented. No capture-overhead estimate or performance conclusion follows from these checks.

Ignored evidence directory: `artifacts/integration-smoke/stage8-1-20260916-remediation`. Build logs, full before/after image inspections, executable/library hashes, commands, raw ping and capture artifacts are canonical disposable evidence.

### Complete executable hash inventory

| Image | Before executable SHA-256 | After executable SHA-256 |
|---|---|---|
| mt-tls-profile:local | `5acd0e0032987f03eb0a8289c541b5b1da395c3398f26b02aa2653e594250b1c` | `e042499d451579d959862c785efea33e22442e40410c6f3e5de272b50ed15dbe` |
| mt-tls-mtc:local | `540569a1b723c544ab9f760bbd1409e5f8f8ee3b41c0dc1bf3e3f84c605c1467` | `77827dc0fd0b6db083fc4947a5bd69ba3147fc6b7e7064424a49c9dc6b648523` |
| mt-tls-measurement:local | `2a6180ec345856b1e60bbf0028df02f082ac66c7f036e3ae18229c0dbc5be729` | `2497ae3631612cbcf7637118756d3c3cec8de77a1b0759a7dd93000ed6b745b2` |
| mt-tls-network:latency | `2a6180ec345856b1e60bbf0028df02f082ac66c7f036e3ae18229c0dbc5be729` | `2497ae3631612cbcf7637118756d3c3cec8de77a1b0759a7dd93000ed6b745b2` |
| mt-tls-capture:local | `2a6180ec345856b1e60bbf0028df02f082ac66c7f036e3ae18229c0dbc5be729` | `2497ae3631612cbcf7637118756d3c3cec8de77a1b0759a7dd93000ed6b745b2` |

All five rebuilt images have resolved library provenance. Capture inherits the same new measurement executable. Profile and MTC have intentionally different application executables because subsequent protocol/setup patches produce distinct builds; all native instrumentation originates from the refreshed profile source. These parent binaries are not substituted for the campaign executable.
