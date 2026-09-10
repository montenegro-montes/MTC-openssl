# Latency-only network experiment

This experiment uses the frozen N=16 protocol implementation and measurement
driver. `Dockerfile.network` derives from `mt-tls-paper:local` and adds only
`iproute2`, `iputils-ping` and `iperf3`. It does not rebuild OpenSSL.

Symmetric latency is configured as `netem delay RTT/2` on client and server
`eth0` egress. No bandwidth, loss or jitter options are used. Before each
campaign a separate client namespace receives the same qdisc and sends twenty
ping probes. A full measurement client receives the same qdisc again.

The experiment uses six RTT targets, five campaigns per target, five warmup and
thirty measured randomized rounds over six PQ scenarios. Final bootstrap
inference resamples five campaign effects at fixed RTT 10,000 times.

Reproduction uses a new output directory:

```sh
FINAL="artifacts/results/network-latency-final-$(date +%Y%m%d-%H%M%S)"
python3 network_latency/control.py init "$FINAL"
docker build -f Dockerfile.network -t mt-tls-network:latency .
python3 network_latency/control.py tests "$FINAL"
python3 network_latency/run.py "$FINAL" --smoke
python3 network_latency/run.py "$FINAL"
python3 network_latency/analyze.py "$FINAL"
python3 network_latency/plots.py "$FINAL"
python3 network_latency/control.py audit "$FINAL"
```

Smoke data are stored separately and excluded. The driver refuses to overwrite
or retry a campaign. Large results and private fixture keys remain under the
ignored `artifacts/` tree.
