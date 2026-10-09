# `mt-handshake-performance` CSV data dictionary

This document describes the CSV files written by
`bin/performance/mt-handshake-performance`. It reflects the literal headers and
measurement boundaries in that launcher and in `pcap_handshake.py`.

## Experimental identity shared by both CSV files

| Column | Unit | Meaning and source |
|---|---|---|
| `profile` | identifier | Credential signature profile used by both peers where applicable: `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `mldsa44`, `mldsa65`, `mldsa87`, `slhdsa128s`, `slhdsa192s`, or `slhdsa256s`. |
| `case` | identifier | Authentication/credential scenario. `x509-simple`, `mtc-simple-landmark`, and `mtc-simple-standalone` authenticate only the server. Their `*-mutual` counterparts authenticate client and server with the same `profile`. X.509 runs carry a `-d2` through `-d5` suffix identifying the configured path depth. |
| `key_establishment` | label | Human-readable configured KEM/group label: `X25519`, `X25519+ML-KEM768`, or `ML-KEM-768`. This is configuration provenance, not an independent packet decode. |
| `openssl_group` | OpenSSL identifier | Exact group supplied to the TLS 1.3 client and server: `X25519`, `X25519MLKEM768`, or `mlkem768`. Successful TLS validation provides negotiation evidence. |
| `phase` | category | `warmup` or `measured`. Warmups execute first and are retained in the CSV but excluded from `summary.json` statistics. |
| `repetition` | one-based integer | Iteration within one `profile`/`case`/`phase` cell. It restarts at one for each cell and phase. |

X.509 depth includes the local root. Therefore D=2 transmits one certificate,
D=3 transmits two, and so on; the root is not transmitted. The selected depth
is also retained in `x509-depth.json` and `summary.json`. MTC remains N=16 and
does not vary with X.509 depth.

The generated configuration supplies the same `RUNS` and `WARMUPS` to Native
and PCAP. `RUNS` controls measured repetitions and `WARMUPS` controls warmup
repetitions. Only rows with `phase=measured` enter descriptive statistics; for
PCAP, the row must additionally have `analysis_status=OK`.

## `native.csv`

Native timing comes from monotonic clocks instrumented inside the OpenSSL
client, except `process_wall_ms`, whose clock surrounds the complete Docker
client invocation in the host launcher.

| Column | Unit | Meaning and method |
|---|---|---|
| `profile` | identifier | See the shared identity table. |
| `case` | identifier | See the shared identity table. |
| `key_establishment` | label | See the shared identity table. |
| `openssl_group` | OpenSSL identifier | See the shared identity table. |
| `phase` | category | See the shared identity table. |
| `repetition` | integer | See the shared identity table. |
| `tcp_connect_wall_ms_native` | ms | Monotonic time from entry into the instrumented client connection operation until successful `BIO_do_connect()` return. It measures TCP connection establishment from inside the native client, not packet timestamps. |
| `handshake_wall_ms` | ms | Monotonic time from OpenSSL's `SSL_CB_HANDSHAKE_START` callback to `SSL_CB_HANDSHAKE_DONE`. It is the native TLS handshake interval and excludes the preceding TCP connect interval. |
| `connection_establishment_wall_ms_native` | ms | Monotonic time from native connection entry, before TCP connect, through TLS handshake completion. This is the value labelled `complete` in progress output. It is measured directly and should not be reconstructed by adding independently rounded columns. |
| `process_wall_ms` | ms | Host monotonic time immediately before launching the Docker client command through command completion. It includes process/container invocation, TCP, TLS, the piped HTTP request/response handling, output and shutdown overhead. It is broader than connection establishment. |
| `tls_bytes_read` | bytes | OpenSSL `s_client`'s reported “SSL handshake has read … bytes”: handshake bytes received by the client from the server. It is captured after successful verification and does not represent Ethernet/IP/TCP headers or the later HTTP response body. |
| `tls_bytes_written` | bytes | OpenSSL `s_client`'s reported handshake bytes written by the client to the server. It excludes Ethernet/IP/TCP headers and the piped HTTP request. |
| `tls_bytes_total` | bytes | `tls_bytes_read + tls_bytes_written`. This is the value labelled `tls_bytes` in progress output. It is bidirectional OpenSSL handshake accounting, not file size, TCP payload for the whole connection, or on-wire traffic. |

### Interpreting Native `tcp`, `tls`, `complete`, `process`, and `tls_bytes`

- `tcp` in console output is `tcp_connect_wall_ms_native`.
- `tls` is `handshake_wall_ms`.
- `complete` is `connection_establishment_wall_ms_native`, spanning TCP plus
  TLS from the native connection entry point.
- `process` is `process_wall_ms` and includes substantial work outside TCP/TLS.
- `tls_bytes` is `tls_bytes_total`: client-read plus client-written TLS
  handshake bytes. Direction is always expressed from the client's viewpoint.

These values have different boundaries. In particular, `process` must not be
treated as TLS latency, and `tls_bytes_total` must not be compared directly
with PCAP on-wire bytes that include network headers and retransmissions.

## `pcap.csv`

The PCAP analyzer selects one TCP stream from its initial client SYN, correlates
the TCP/TLS/application events, reassembles logical TLS records by `tcp.seq`,
and fails closed when required boundaries are missing or ambiguous.

| Column | Unit | Meaning and method |
|---|---|---|
| `profile` | identifier | See the shared identity table. |
| `case` | identifier | See the shared identity table. |
| `key_establishment` | label | See the shared identity table. |
| `openssl_group` | OpenSSL identifier | See the shared identity table. |
| `phase` | category | See the shared identity table. |
| `repetition` | integer | See the shared identity table. |
| `tcp_handshake_ms` | ms | Capture timestamp from the initial client SYN to the unique client ACK that completes the corresponding TCP three-way handshake. |
| `tcp_syn_to_clienthello_ms` | ms | Initial client SYN to the correlated ClientHello frame. |
| `tls_clienthello_to_client_finished_ms` | ms | ClientHello to the client Finished that completes the measured TLS handshake interval. |
| `tcp_syn_to_first_application_request_ms` | ms | Initial SYN to the first decrypted client HTTP request after Finished. This includes TCP, TLS, and the delay to the request. |
| `tls_client_handshake_bytes` | bytes | Logical complete TLS records sent client-to-server from ClientHello through client Finished. TCP retransmissions are deduplicated; each TLS record's five-byte header is counted once. |
| `tls_server_handshake_bytes` | bytes | Logical complete TLS records sent server-to-client over the same ClientHello-through-client-Finished interval, with retransmissions deduplicated. |
| `tls_handshake_bytes` | bytes | `tls_client_handshake_bytes + tls_server_handshake_bytes`. This is bidirectional logical TLS-record size, not on-wire size. |
| `tls_client_handshake_wire_bytes` | `frame.len` bytes | Sum of captured frame lengths for client-to-server frames carrying TCP payload in the TLS interval. Includes link/IP/TCP headers and retransmitted frames; pure ACKs are excluded. |
| `tls_server_handshake_wire_bytes` | `frame.len` bytes | Equivalent server-to-client on-wire sum over the same interval. |
| `tls_handshake_wire_bytes` | `frame.len` bytes | Client plus server TLS-handshake wire bytes. |
| `tcp_handshake_wire_bytes` | `frame.len` bytes | Sum of SYN, corresponding SYN/ACK, and the ACK completing TCP establishment. |
| `connection_handshake_wire_bytes` | `frame.len` bytes | Union of the TCP three-way-handshake frames and TLS-handshake payload frames. If the completing ACK also carries TLS data, that frame is counted once. |
| `tls_client_handshake_packets` | frames | Number of client-to-server TCP-payload frames in the TLS interval. |
| `tls_server_handshake_packets` | frames | Number of server-to-client TCP-payload frames in the TLS interval. |
| `tls_handshake_packets` | frames | Total client and server TCP-payload frames in the TLS interval. |
| `tls_client_certificate_bytes` | bytes | Complete client TLS Certificate handshake message, including its four-byte handshake header. Zero when no client Certificate was requested/present; mutual cases require it to be analyzable. Applies to X.509 and project MTC credentials carried in Certificate. |
| `tls_server_certificate_bytes` | bytes | Complete server TLS Certificate handshake message, including its four-byte handshake header. This is distinct from the TLS CertificateVerify message. |
| `tcp_stream` | tshark integer | Selected `tcp.stream` identifier. It is capture-local and is not comparable as a magnitude between runs. |
| `client_random` | 64 hexadecimal characters | ClientHello random used as connection identity/correlation evidence. |
| `analysis_status` | category | `OK` when every fail-closed selection and boundary check succeeds; otherwise `ERROR`. Only `OK` measured rows enter PCAP statistics. |
| `analysis_error` | text | Diagnostic explaining a failed PCAP analysis; empty when status is `OK`. Failed rows retain blank metric cells rather than invented zeros. |
| `tcp_retransmission_packets` | frames | Frames within the TLS interval marked by tshark as retransmission, fast retransmission, or spurious retransmission. They remain in wire/packet counts but are deduplicated from logical TLS bytes. |

## Measurement limitations and correct comparison

- Native clocks and PCAP timestamps have different observation points. Native
  `handshake_wall_ms` is not interchangeable with
  `tls_clienthello_to_client_finished_ms`, and neither is process time.
- Native `tls_bytes_*` are OpenSSL handshake counters from the client viewpoint.
  PCAP `tls_*_handshake_bytes` reconstruct complete TLS records in a bounded
  interval; PCAP `*_wire_bytes` additionally include captured network headers
  and retransmissions. These families should be reported separately.
- `frame.len` depends on capture encapsulation. Loopback and Ethernet results
  are not directly comparable without accounting for link-layer differences.
- The TLS interval ends at client Finished. HTTP, alerts, post-handshake
  messages and connection teardown are outside logical handshake-byte metrics.
- Certificate-message sizes include TLS handshake framing. They are not raw DER
  certificate sizes and do not include CertificateVerify.
- A configured KEM/group column records experimental configuration. Protocol
  conclusions should also retain the successful validation/log evidence.
- X.509 depth changes only X.509 cases. MTC remains N=16, so depth must not be
  interpreted as an MTC tree or proof parameter.
- Warmups remain useful operational evidence but must not enter means, medians,
  standard deviations, or confidence intervals. `summary.json` uses measured
  rows only and excludes PCAP rows whose analysis did not return `OK`.
- Comparisons should hold profile, authentication mode, KEM, X.509 depth,
  capture environment, image, fixture provenance, and repetition policy fixed.
