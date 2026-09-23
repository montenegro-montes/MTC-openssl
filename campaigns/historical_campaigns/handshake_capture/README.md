# TLS handshake packet-capture campaign

This package captures one diagnostic TLS 1.3 connection per selected PQ
authentication scenario. It is independent of all timing, latency, bandwidth,
loss and combined-network campaigns. Do not merge its timings with performance
results: `tcpdump`, key logging and file I/O can perturb execution.

The capture sidecar shares only the server network namespace and observes
`eth0`; it does not alter OpenSSL. The client enables OpenSSL `-keylogfile` so
that tshark can decode encrypted TLS 1.3 handshake records. The default scenarios
are PQ X.509, RPK, Compact warm/cold and MTC landmark/standalone.

PCAP and `tls.keys` files are ignored through the repository-wide `artifacts/`
rule. The key log decrypts captured sessions and must never be committed or
published as a reusable secret.

## Step 1 — inspect inputs

Run from the repository root and do not start while another campaign is active:

```sh
git status --short
git rev-parse HEAD
docker ps
test -f artifacts/compact/batch16/pq/manifest.json
test -f artifacts/mtc/batch16-v2/pq/manifest.json
python3 -m campaigns.common.image_chain measurement
```

## Step 2 — build the dedicated capture image

```sh
docker build -f docker/base/Dockerfile.capture -t mt-tls-capture:local .
docker run --rm --network none mt-tls-capture:local \
  sh -c 'tcpdump --version && tshark --version | head -1'
```

## Step 3 — choose a fresh output

```sh
CAPTURE_ROOT="artifacts/captures/handshake-$(date +%Y%m%d-%H%M%S)"
echo "$CAPTURE_ROOT"
```

`run.py` refuses an existing directory and captures one handshake per default
scenario. It always stops its Compose project and records startup, client,
tcpdump and shutdown logs.

```sh
python3 campaigns/historical_campaigns/handshake_capture/run.py --root "$CAPTURE_ROOT"
```

To capture a subset:

```sh
python3 campaigns/historical_campaigns/handshake_capture/run.py --root "$CAPTURE_ROOT" \
  --scenarios pq pq-compact-warm pq-mtc-experimental-landmark
```

## Step 4 — decode and summarize

Run tshark inside the dedicated image, so no host installation is required:

```sh
CAPTURE_ROOT_ABS="$PWD/$CAPTURE_ROOT"
CAPTURE_ROOT="$CAPTURE_ROOT_ABS" \
  docker compose -f docker/historical_campaigns/compose.capture.yaml run --rm analyzer

python3 campaigns/historical_campaigns/handshake_capture/validate.py "$CAPTURE_ROOT"
```

Inspect:

```sh
cat "$CAPTURE_ROOT/summary.json"
cat "$CAPTURE_ROOT/validation.json"
```

The output contains `handshakes.pcap`, `tls.keys`, per-scenario client logs,
`packets.csv`, `summary.json`, metadata and SHA-256 values. `wire_bytes` includes
captured frame bytes; `tcp_payload_bytes` is TCP payload and is distinct from the
existing TLS BIO byte metric. A shared server-port mapping attributes packets to
each scenario. Experimental Compact/MTC certificate bodies may still require the
repository's binary inspectors after TLS decryption.

## PCAP connection-handshake metrics (Stage 1)

`analyze.py` adds the following fields to each scenario in `summary.json` without
changing existing fields or OpenSSL instrumentation. Analysis uses two-pass tshark
with the existing key log. A port must identify exactly one `tcp.stream`; otherwise
analysis fails. For an intentional multi-connection capture, specify `tcp_stream`
on the corresponding `connections.json` item. Existing port-wide summary fields
remain port-wide; the new fields below describe only the selected stream.

- `tcp_stream`, `syn_frame`, `syn_ack_frame`, `tcp_established_frame`,
  `client_hello_frame`, `client_finished_frame`, and each boundary's
  `*_time_epoch` expose the calculation boundaries.
- `tcp_connect_wall_ms`: first SYN to the client's first ACK matching both initial
  sequence numbers plus one (modulo 2^32). This ACK may carry ClientHello.
- `tls_from_pcap_wall_ms`: ClientHello to **client** Finished.
- `connection_handshake_wall_ms`: first SYN to client Finished.
- `connection_handshake_packets`: selected-flow frames within those inclusive
  frame-number boundaries, excluding subsequent ACKs and shutdown traffic.
- `connection_handshake_frame_bytes`: sum of `frame.len`, the original frame
  lengths reported by the capture, not necessarily the stored snapshot lengths.
  This campaign captures server-side container `eth0`: link headers are included
  as exposed by the capture; physical preamble, inter-frame gaps and normally FCS
  are absent. Virtual interfaces/offloading can change observed segmentation;
  these counts do not claim physical-medium occupancy.
- `connection_handshake_ip_bytes`: sum of IPv4 `ip.len`, including IP headers.
- `connection_handshake_tcp_payload_bytes`: sum of `tcp.len`, excluding TCP/IP
  headers but including every observed retransmitted payload.
- `connection_handshake_retransmission_frames`: frames marked by any of tshark's
  retransmission, fast-retransmission or spurious-retransmission diagnostics,
  counted once per frame. This is a dissector classification, not proof of loss.

The first implementation supports single-layer IPv4, ordinary TCP establishment
and one ClientHello/client Finished per selected stream. Missing SYN/ACKs,
ambiguous handshakes (including retries), IPv6, TCP Fast Open, invalid lengths or
non-monotonic timestamps fail explicitly. Multiple handshake types in one frame
are parsed individually, and server Finished is never used as the endpoint.
TLS reassembly assigns message completion to a frame: timing uses that frame's
capture timestamp. The whole endpoint frame is counted, including any coalesced
payload. Without a decryptable client Finished, no new metrics are produced.

`handshake_wall_ms` remains the primary OpenSSL TLS timing and excludes TCP
establishment. `transport_total_bytes`, `transport_read_bytes` and
`transport_written_bytes` keep their BIO definitions. BIO bytes, observed TCP
payload, IP bytes and captured frame bytes are distinct accounting layers; do not
expect equality. PCAP timing is secondary and capture can perturb performance.
Historical results are not estimated or rewritten using these fields.

Offline tests (no Docker or new experiment):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s campaigns/historical_campaigns/handshake_capture -p test_analyze.py
```

Stage 1 validation uses deterministic frame tables, including zero retransmissions,
retransmission de-duplication, multiple streams and unavailable Finished. No existing
PCAP was available under `artifacts/captures` during implementation; live tshark
and PCAP/OpenSSL cross-checks remain pending. Campaign integration remains deferred.


## Metric semantics and sanity comparison (Stage 2)

### Timing boundaries

| Metric | Measurement boundary | Role |
| --- | --- | --- |
| `handshake_wall_ms` | Existing OpenSSL-instrumented TLS handshake interval; excludes TCP connection establishment | Primary TLS timing; unchanged |
| `tls_from_pcap_wall_ms` | Captured ClientHello completion frame to client Finished completion frame | Secondary TLS timing validation |
| `tcp_connect_wall_ms` | Captured first SYN to matching final ACK of the three-way handshake | TCP establishment at the capture point |
| `connection_handshake_wall_ms` | Captured first SYN to client Finished completion frame | Combined connection/handshake interval at the capture point |

OpenSSL measures an application-side interval; PCAP measures frame timestamps at
server-side `eth0`. Scheduling, buffering, transit to the capture point, segmentation,
and reassembly completion can therefore produce different durations. Neither a
fixed offset nor numerical equality is required. The client Finished endpoint does
not include arbitrary later ACKs. It need not coincide with the return of the
instrumented OpenSSL call.

Within a valid capture, `connection_handshake_wall_ms >= tls_from_pcap_wall_ms`.
The difference is SYN-to-ClientHello time, not necessarily `tcp_connect_wall_ms`:
there may be a gap between the final TCP ACK and ClientHello. Do not add TCP time
to `handshake_wall_ms` and label the result an OpenSSL TLS measurement.

### Byte accounting layers

| Metric | What is counted | What is outside this layer |
| --- | --- | --- |
| `transport_total_bytes` | Existing OpenSSL/BIO total, retaining the existing read/written counters and measurement scope | TCP retransmission copies and TCP/IP/link headers |
| `connection_handshake_tcp_payload_bytes` | Sum of observed TCP payload in both directions, first SYN through client Finished frame inclusive | TCP/IP/link headers |
| `connection_handshake_ip_bytes` | Sum of IPv4 packet lengths over the same frames, including IP/TCP headers and payload | Link headers |
| `connection_handshake_frame_bytes` | Sum of captured-interface original frame lengths over the same frames | Physical-medium overhead absent from the capture |

These are successive accounting layers, not interchangeable byte metrics. All
three PCAP byte sums include observed retransmissions; BIO counters do not count
kernel retransmission copies. ACK-only frames add IP/frame bytes but zero TCP
payload. Whole-frame inclusion may count coalesced data beyond the semantic TLS
endpoint. Different BIO sampling boundaries, capture loss, or offloading can also
prevent equality between BIO total and observed TCP payload. There is no general
required inequality between those two differently scoped measurements.

For the supported capture layout, the extractor checks frame bytes >= IP bytes
>= TCP payload bytes. `frame.len` must never be described simply as "TCP bytes".
The frame-length and virtual-interface caveats in Stage 1 apply unchanged.

### Cross-check status and interpretation

Stage 2 checked only the known `artifacts/captures` location; that directory was
absent. No immediately available PCAP and corresponding OpenSSL observation were
identified, so **the numerical cross-check was not performed**. No broad data
search, capture, campaign, Docker operation, or historical-result rewrite was
performed. This documentation validation is not a successful empirical comparison.

When a matching pair is available, compare `handshake_wall_ms` with
`tls_from_pcap_wall_ms`, and `transport_total_bytes` with
`connection_handshake_tcp_payload_bytes`, for the same observation and selected
TCP stream. Record both values and their differences without requiring equality
or inventing missing historical values. A missing decryptable client Finished is
an unavailable measurement, not zero. Key-log contents must not enter reports.

Capture and key logging may perturb execution. Such a comparison checks
instrumentation semantics only; it cannot establish performance equivalence with
uncaptured experiments or support scientific performance conclusions. The next
stage is an integration plan only; no experimental campaign has been modified.


The strict successful-handshake requirements above describe the default mode.
Stage 6B.3 added explicit `--allow-incomplete` analysis in this same extractor:
a valid incomplete attempt may report observed TCP establishment and partial
capture diagnostics, while TLS/full timing and successful-handshake byte/packet
metrics remain null without client Finished. Partial retransmission diagnostics
cover the entire selected captured TCP attempt. This does not weaken the default
success definitions; shared association and SHA-256 checks still fail closed.
