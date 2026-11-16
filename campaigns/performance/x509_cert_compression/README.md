# X.509 certificate compression comparison

This focused host experiment compares the same X.509 chain for each selected
profile, ML-DSA-65 or SLH-DSA-192s, sent as a TLS 1.3 `Certificate` and as an
RFC 8879 `CompressedCertificate`. Both use `X25519MLKEM768` and
`TLS_AES_256_GCM_SHA384`. The client disables certificate reception
compression only for the ordinary condition; the server uses `-cert_comp` to
precompress its certificate in both conditions. OpenSSL chooses the enabled
algorithm from its preference list. The raw `-msg` transcript must show
`CompressedCertificate` only for the compressed condition.

Each fixture is an existing D=3 server-only X.509 chain (leaf and one
intermediate transmitted; the root stays local). The D=2 ML-DSA-65 leaf alone
barely shrinks with zlib, so it is unsuitable for testing a negotiated
`CompressedCertificate` in this OpenSSL build. The campaign alternates
conditions, runs 5 warmups and then 100 measured handshakes for each condition. It stops
the server between samples; server startup is outside the native TLS timing.

From the repository root, first inspect a plan (omit `--execute`):

```bash
python3 campaigns/performance/x509_cert_compression/run.py \
  --x509-fixture artifacts/x509/chromium-x509-depth-matrix-v1/mldsa65/d3 \
  --profile mldsa65 --hostname server.mtc.example.com \
  --output artifacts/results/x509-cert-comp-mldsa65-d3-NEXT
```

For SLH-DSA-192s, use
`artifacts/fixtures/handshake-chain-server-20261013T135142.495751Z/slhdsa192s/depth-3`
with `--profile slhdsa192s --hostname server` and a distinct output path.
Check the certificate's validity period before a future run.

The standard `mt-tls-mtc:local` image was built without zlib, Brotli, or Zstd.
Build the separate zlib image, then the image with the scoped provider-backed
certificate precompression fix:

```bash
docker build -f campaigns/performance/x509_cert_compression/Dockerfile.zlib \
  -t mt-tls-mtc-cert-comp:local .
docker build -f campaigns/performance/x509_cert_compression/Dockerfile \
  -t mt-tls-mtc-cert-comp-pq:local .
```

Then add `--execute` to the plan command and use a fresh output path for every
attempt. The script checks the image for `-lab_metrics`, `-no_rx_cert_comp`,
and `-cert_comp` before creating an output directory. It fails if TLS
verification, native timing, byte accounting, or the expected compression
transcript is missing. Partial output
and server logs remain for diagnosis after a failure.

`samples.csv` retains every sample. `summary.json` includes only measured
samples. `handshake_wall_ms` is the client native TLS interval;
`credential_verification_total_ms` is the inclusive X.509 verification
interval. `tls_bytes_read` is the server-to-client OpenSSL handshake byte
count, and `tls_bytes_total` adds both directions. These are handshake bytes,
not certificate file size or link-layer wire bytes. The raw logs under `logs/`
are the evidence for whether compression was actually negotiated.

## Locally available intermediate control

The `--intermediate-elision` mode adds four arms: full/ordinary, full/zlib,
elided/ordinary, and elided/zlib. The server sends the same leaf and optional
intermediate from an existing D=3 fixture. The client uses `-verifyCAfile`
with the root alone and the experiment-specific `-verify_untrusted` option
with the intermediate only in the elided arms. The latter adds an untrusted
issuer to the peer verification context; it does not add a trust anchor.
The callback requires a validated three-certificate chain with the exact
intermediate. The one-sample pilot prints all three verified DER SHA-256
hashes; every sample parses the TLS `Certificate` or `CompressedCertificate`
trace and checks the sent leaf/intermediate hashes and count. A zlib offer may
still result in an ordinary `Certificate` for the elided leaf, which the CSV
records as the actual message and algorithm.

Rebuild `mt-tls-mtc-cert-comp-pq:local` from the existing
`mt-tls-mtc-cert-comp:local` image before using this mode. Run a new pilot
with `--warmups 0 --runs 1 --execute` for each profile and a fresh output
directory. A full campaign requires that pilot's `summary.json` via
`--pilot-summary`; the runner checks the image ID, fixture certificate
hashes, profile, hostname and the full-chain byte reference before starting.
The P-384 one-sample reference permits the observed one-byte ECDSA DER
signature length variation. Use `--warmups 5 --runs 100` for the full campaign.
The report script compares archived Landmark measurements only after checking
the group, depth, fixture binding and directional X.509 byte counters. Its
Landmark timing comes from another measurement block.

### SLH-DSA-192s with the intermediate omitted

In `artifacts/results/commag-x509-elision-slhdsa192s-full-20261115b/`, all
105 full-chain zlib samples (5 warmups and 100 measured) sent
`CompressedCertificate` without a server precompression error. All 105
elided-chain zlib-offer samples logged `Error compressing certs on ctx` and
sent an ordinary `Certificate`. Both arms used image
`sha256:5a8b523dd976e28debc474f42b67b2a6a0f33013ae3b889e4c9562d3336e281e`.

The exact TLS 1.3 `Certificate` body from measured trace 1 contains the
certificate request context and certificate list, including per-certificate
lengths and extensions. For the full chain it is 33,196 bytes; zlib produces
33,047 bytes. The complete `Certificate` handshake message is 33,200 bytes.
Adding the `CompressedCertificate` handshake header (4 bytes), algorithm
(2 bytes), uncompressed length (3 bytes), and compressed-vector length
(3 bytes) gives 33,059 bytes, a 141-byte saving. The zlib output exactly
matches the compressed bytes in the full-chain trace.

With only the same leaf, the `Certificate` body is 16,612 bytes and zlib
produces 16,617 bytes. A `CompressedCertificate` would therefore occupy
16,629 bytes, 13 bytes more than the actual 16,616-byte `Certificate`.
The experiment image's `patch_provider_cert.py` discards the active
provider-backed certificate's precompressed result when
`compressed_length >= original_body_length`. Here `16,617 >= 16,612`, so
`SSL_CTX_compress_certs()` returns 0 and `s_server` emits its generic error
message. The certificate remains selectable and the TLS handshake succeeds;
this is a size-policy fallback, not a certificate-selection failure. The
policy compares compressed and original bodies and does not need the extra
8 bytes of `CompressedCertificate` overhead to reject this sample.
