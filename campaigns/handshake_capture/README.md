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
docker build -f docker/Dockerfile.capture -t mt-tls-capture:local .
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
python3 campaigns/handshake_capture/run.py --root "$CAPTURE_ROOT"
```

To capture a subset:

```sh
python3 campaigns/handshake_capture/run.py --root "$CAPTURE_ROOT" \
  --scenarios pq pq-compact-warm pq-mtc-experimental-landmark
```

## Step 4 — decode and summarize

Run tshark inside the dedicated image, so no host installation is required:

```sh
CAPTURE_ROOT_ABS="$PWD/$CAPTURE_ROOT"
CAPTURE_ROOT="$CAPTURE_ROOT_ABS" \
  docker compose -f docker/compose.capture.yaml run --rm analyzer

python3 campaigns/handshake_capture/validate.py "$CAPTURE_ROOT"
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
