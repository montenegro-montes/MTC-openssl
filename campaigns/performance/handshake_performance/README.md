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

## PCAP CSV: Data Dictionary

The PCAP analyzer selects one TCP stream from its unique initial client SYN,
correlates the TCP and TLS events, and reassembles logical TLS records by
`tcp.seq`. The measured TLS interval starts at ClientHello and ends at the
client Finished, both inclusive. ClientHello, the server Certificate and
CertificateVerify, and client Finished remain mandatory and unambiguous. An
HTTP request is not a handshake boundary and is optional: when tshark cannot
identify it, only `tcp_syn_to_first_application_request_ms` is null and the
remaining TLS measurements are retained.

### A. Experiment identification

| Column | Unit/type | Meaning and method | Zero, null, or not applicable |
|---|---|---|---|
| `profile` | identifier | Credential signature profile selected by the campaign; see the shared identity table above. | Required. |
| `case` | identifier | Exact X.509, MTC landmark, or MTC standalone simple/mutual scenario. X.509 may carry a `-d2` to `-d5` suffix. | Required. |
| `key_establishment` | label | Configured human-readable key-establishment selection. | Required configuration provenance. |
| `openssl_group` | OpenSSL identifier | Exact TLS group configured in client and server. | Required configuration provenance. |
| `phase` | category | `warmup` or `measured`. | Required. Warmups are retained here but excluded from `summary.json` statistics. |
| `repetition` | integer | One-based repetition inside the profile/case/phase cell. | Required; never zero. |

### B. Timing metrics

| Column | Unit/type | Meaning and method | Zero, null, or not applicable |
|---|---|---|---|
| `tcp_handshake_ms` | ms | Capture time from the initial client SYN to the unique ACK completing its TCP three-way handshake. | Required for `analysis_status=OK`; a genuine measured zero is possible only at timestamp resolution. |
| `tcp_syn_to_clienthello_ms` | ms | Initial SYN to the first and unique ClientHello of the selected stream. | Required for `OK`. |
| `tls_clienthello_to_client_finished_ms` | ms | ClientHello to client Finished, the fixed end of the TLS handshake interval. | Required for `OK`. |
| `tcp_syn_to_first_application_request_ms` | ms | Initial SYN to the first uniquely identified decrypted HTTP request after client Finished. | Null when HTTP is not identified; this does not invalidate other TLS metrics. |

### C. Logical TLS handshake bytes

| Column | Unit/type | Meaning and method | Zero, null, or not applicable |
|---|---|---|---|
| `tls_client_handshake_bytes` | bytes | Complete logical TLS records sent client-to-server from ClientHello through client Finished. Reassembled by TCP sequence; retransmissions are deduplicated and every TLS record header is counted once. | Required and normally nonzero. |
| `tls_server_handshake_bytes` | bytes | Complete logical TLS records sent server-to-client over that same interval. | Required and normally nonzero. |
| `tls_handshake_bytes` | bytes | `tls_client_handshake_bytes + tls_server_handshake_bytes`. | Required; logical TLS-record bytes, not packet bytes. |

### D. Network-transmitted bytes

| Column | Unit/type | Meaning and method | Zero, null, or not applicable |
|---|---|---|---|
| `tls_client_handshake_wire_bytes` | `frame.len` bytes | Sum of complete captured frame lengths for client TCP-payload frames in the TLS interval. Includes link/IP/TCP headers and retransmissions; excludes pure ACKs. | Required for `OK`. |
| `tls_server_handshake_wire_bytes` | `frame.len` bytes | Equivalent server-to-client on-wire sum. | Required for `OK`. |
| `tls_handshake_wire_bytes` | `frame.len` bytes | Client plus server handshake wire bytes. | Required for `OK`. |
| `tcp_handshake_wire_bytes` | `frame.len` bytes | SYN + corresponding SYN/ACK + first ACK completing TCP establishment. | Required for `OK`. |
| `connection_handshake_wire_bytes` | `frame.len` bytes | Union of TCP-establishment frames and TLS-interval payload frames. A completing ACK carrying TLS data is counted once. | Required for `OK`. |

`tls_handshake_bytes` counts reconstructed TLS records and their five-byte
record headers. `tls_handshake_wire_bytes` counts captured frames and therefore
also link, IP, TCP, and retransmission cost. `connection_handshake_wire_bytes`
adds the unique TCP three-way-handshake frames. None is a raw sum of Certificate
or CertificateVerify messages.

### E. Packets and retransmissions

| Column | Unit/type | Meaning and method | Zero, null, or not applicable |
|---|---|---|---|
| `tls_client_handshake_packets` | frames | Client-to-server TCP-payload frames in the TLS interval. | Required for `OK`. |
| `tls_server_handshake_packets` | frames | Server-to-client TCP-payload frames in the TLS interval. | Required for `OK`. |
| `tls_handshake_packets` | frames | Sum of the preceding directional frame counts. | Required for `OK`. |
| `tcp_retransmission_packets` | frames | TLS-interval frames marked by tshark as retransmission, fast retransmission, or spurious retransmission. | Zero means tshark marked none; retransmissions remain in wire counts but are deduplicated from logical TLS bytes. |

### F. Certificate and CertificateVerify

| Column | Unit/type | Meaning and method | Zero, null, or not applicable |
|---|---|---|---|
| `tls_client_certificate_bytes` | bytes | Complete client Certificate handshake message: body plus its four-byte TLS handshake header. | Zero in server-only authentication; mandatory and nonzero in a valid mutual case. |
| `tls_server_certificate_bytes` | bytes | Complete server Certificate handshake message: body plus its four-byte TLS handshake header. Applies to X.509 and MTC credentials carried in Certificate. | Mandatory and nonzero. |
| `tls_client_certificate_verify_bytes` | bytes | Complete client CertificateVerify handshake message, including its four-byte handshake header. Its TLS 1.3 algorithm and signature-vector encoding are validated. | Zero in server-only authentication; mandatory in a valid mutual case. |
| `tls_server_certificate_verify_bytes` | bytes | Complete server CertificateVerify handshake message, including algorithm, signature-vector length, signature, and four-byte handshake header. | Mandatory and nonzero. |
| `tls_client_certificate_verify_signature_bytes` | bytes | Only the cryptographic signature vector contents inside client CertificateVerify, after validating the declared vector length. | Zero in server-only authentication. It excludes algorithm, length, and handshake header. |
| `tls_server_certificate_verify_signature_bytes` | bytes | Only the cryptographic signature vector contents inside server CertificateVerify. | Mandatory and nonzero. It is smaller than the complete CertificateVerify message. |

Certificate size, complete CertificateVerify size, cryptographic signature
size, TLS-record size, and TCP-frame size are separate quantities and must not
be interchanged.

### G. MTCProof and Merkle path

| Column | Unit/type | Meaning and method | Zero, null, or not applicable |
|---|---|---|---|
| `tls_client_mtc_proof_bytes` | bytes | Complete client MTCProof taken from the octet-aligned certificate `signatureValue` after the canonical project parser accepts it. | Null for X.509 and server-only; unavailable if tshark does not expose client Certificate DER. |
| `tls_server_mtc_proof_bytes` | bytes | Complete server MTCProof extracted and parsed identically. | Null for X.509; unavailable if DER extraction is unavailable. |
| `tls_client_mtc_merkle_path_bytes` | bytes | Client MTCProof inclusion-path vector contents, excluding its two-byte vector length. | Null when MTC client authentication is not applicable or unavailable. |
| `tls_server_mtc_merkle_path_bytes` | bytes | Server inclusion-path vector contents. | Null for X.509 or unavailable extraction. A valid empty path is represented by zero bytes. |
| `tls_client_mtc_merkle_path_hashes` | count | Client path byte length divided by the validated 32-byte SHA-256 hash size. | Null when not applicable/unavailable; zero means a valid empty path. |
| `tls_server_mtc_merkle_path_hashes` | count | Server path hash count calculated identically. | Same distinction between zero and null. |

MTCProof is already inside the Certificate message counted by
`tls_*_certificate_bytes`. It must **not** be added again to Certificate or
authentication totals. Landmark proofs must contain no subtree signatures;
standalone proofs must contain them.

### H. Signed Certificate Timestamps

| Column | Unit/type | Meaning and method | Zero, null, or not applicable |
|---|---|---|---|
| `tls_client_sct_bytes` | bytes | Sum of exact SCT-list extension-value contents in parsed client X.509 Certificate entries, including the SCT-list's own encoded framing. | Zero means parsed X.509 certificates contain no SCT; null for server-only, MTC, or unavailable DER. |
| `tls_server_sct_bytes` | bytes | Equivalent server X.509 SCT-list size. | Zero means no SCT extension in successfully parsed X.509 certificates; null for MTC or unavailable DER. |

### I. Authentication bytes

| Column | Unit/type | Meaning and method | Zero, null, or not applicable |
|---|---|---|---|
| `tls_client_authentication_bytes` | bytes | `tls_client_certificate_bytes + tls_client_certificate_verify_bytes`. | Zero in server-only authentication. |
| `tls_server_authentication_bytes` | bytes | `tls_server_certificate_bytes + tls_server_certificate_verify_bytes`. | Mandatory and nonzero for an accepted server-authenticated handshake. |
| `tls_authentication_bytes` | bytes | `tls_client_authentication_bytes + tls_server_authentication_bytes`. | Required when Certificate/CertificateVerify parsing succeeds. |

These totals include each Certificate and CertificateVerify handshake header
once. They exclude TLS record headers, encryption expansion, TCP/IP/link
headers, CertificateRequest, Finished, MTC trust anchors, and all
retransmissions. Embedded MTCProof and SCT bytes are already part of Certificate
and are not added separately.

### J. Analysis status and traceability

| Column | Unit/type | Meaning and method | Zero, null, or not applicable |
|---|---|---|---|
| `authentication_components_status` | category | `OK` when every applicable DER-dependent component was extracted; `UNAVAILABLE` when core handshake metrics succeeded but tshark did not expose Certificate DER needed for MTCProof or SCT. | Never a numeric zero. |
| `authentication_components_error` | text | Specific explanation for `UNAVAILABLE`. | Empty when component status is `OK`. |
| `tcp_stream` | capture-local integer | Unique selected tshark `tcp.stream`. | Required for `OK`; identifier only, not a measurement. |
| `client_random` | 64 hexadecimal characters | Unique ClientHello random retained as correlation evidence. | Required for `OK`. |
| `analysis_status` | category | `OK` after all mandatory TCP/TLS boundaries and structures pass; otherwise `ERROR`. | Only `OK` measured rows enter statistics. Missing HTTP alone does not produce `ERROR`. |
| `analysis_error` | text | Fail-closed diagnostic for an invalid, missing, or ambiguous mandatory structure. | Empty for `OK`; failed metrics remain empty rather than zero. |
| `source_capture` | relative path | Present only in a historically reprocessed `pcap.csv`; identifies the immutable per-run capture directory below `SOURCE` used to derive the row. It is not part of newly captured campaign rows. | Required in reprocessed output; not applicable to the primary capture-time CSV schema. |

In Python/JSON, unavailable values are `null`. Python's CSV writer serializes
that value as an empty field. Therefore an empty CSV field does not mean zero.
A numeric zero is an observed applicable value: for example, no client
Certificate in server-only authentication, no retransmissions, no SCT in a
successfully parsed X.509 certificate, or a valid empty Merkle path. A null can
instead mean not applicable (MTC fields for X.509), unavailable structured DER,
or a deliberately optional observation such as unidentified HTTP. Use
`case`, `analysis_status`, `authentication_components_status`, and their error
columns to distinguish these conditions. `summary.json` also records null when
a metric has no usable observations; `report.html` does not manufacture a
statistic for it.

### Interpreting example rows

- In an X.509 server-only row, client Certificate and CertificateVerify sizes
  are zero. Server authentication bytes equal
  `tls_server_certificate_bytes + tls_server_certificate_verify_bytes`.
  X.509 MTCProof fields are null. If `tls_server_sct_bytes` is zero, the parsed
  transmitted chain contained no SCT extension.
- In an MTC landmark row, `tls_server_mtc_proof_bytes` is a component already
  contained in `tls_server_certificate_bytes`; it is reported for explanation,
  not added to `tls_server_authentication_bytes`. SCT fields are null because
  they are not applicable to that MTC credential. A missing HTTP decode leaves
  only `tcp_syn_to_first_application_request_ms` empty.

### Historical PCAP reprocessing and evidence files

Existing captures can be analyzed into a new directory without repeating TLS:

```sh
bin/performance/mt-handshake-performance reprocess-pcap \
  SOURCE \
  DESTINATION
```

`SOURCE` must contain `pcap.csv` and its referenced per-run `handshake.pcap`
and `keylog.txt` files. `DESTINATION` must not exist and must be below
`artifacts/results/`; historical files are never overwritten. The retained
`keylog.txt` lets tshark decrypt TLS 1.3, while `handshake.pcap` remains the raw
packet evidence. Derived per-observation values are written to `pcap.csv`,
measured `phase=measured` rows with `analysis_status=OK` feed `summary.json`,
and `report.html` renders those statistics. Warmup rows remain in `pcap.csv`
but never enter the summary or HTML statistics.

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
