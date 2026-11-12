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
