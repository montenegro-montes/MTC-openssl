# Controlled packet-loss TLS campaign

Preparation commit: `PENDING_PREPARATION_COMMIT`

This directory prepares a manual packet-loss-only experiment. It reuses the
validated N=16 authentication implementation and `/opt/paper/measure.py` metric
definitions. `measure.py` only adds explicit failure/timeout accounting around
the saved driver. No OpenSSL, Compact, MTC, encoding or cryptographic source is
changed. MTC remains experimental draft-ietf-plants-merkle-tree-certs-05.

The fixed additional RTT is 50 ms: client and server independently apply
`netem delay 25ms`. Loss values 0%, 0.1%, 0.5%, 1%, 2% and 5% are independently
applied to both egress directions. This is not an end-to-end loss probability.
No bandwidth limiter, jitter, reordering, duplication or corruption is used.

The timeout is fixed at 30 seconds before collection. Individual failed samples
are recorded and never retried. TCP retransmission/segment counters are collected
at campaign/container level; they cannot be assigned reliably to one handshake,
and retransmitted bytes are unavailable. Optional packet capture is described
below and disabled by default.

## Prerequisites

- Repository containing commit `b4a4b33286037a385f27e770fd23c1d741b197bc`
  or its documented successors.
- Docker image `mt-tls-network:latency`, derived from the exact validated paper
  image and containing `tc`, `ping`, `nstat` and the frozen OpenSSL executable.
- Fixtures `artifacts/compact/batch16`, `artifacts/mtc/batch16-v2` and
  `artifacts/certs`.
- Docker `NET_ADMIN`; privileged mode is not used.
- A clean, new result path under `artifacts/results/`.

## Step 1 — inspect environment

```sh
git status --short
git rev-parse HEAD
docker image inspect mt-tls-network:latency --format '{{.Id}}'
docker ps
docker network ls
test -d artifacts/compact/batch16
test -d artifacts/mtc/batch16-v2
test -d artifacts/certs
```

Do not continue if the latency or bandwidth experiment is still running. Commit
their completed source separately before initializing this experiment.

Choose one new result path and reuse it in every following command:

```sh
LOSS_ROOT=artifacts/results/network-loss-YYYYMMDD-HHMMSS
python3 packet_loss_campaign/control.py init "$LOSS_ROOT"
```

Initialization records the current commit, full `git status`, source hashes and
fixture hashes. It refuses an existing directory.

## Step 2 — build if necessary

The packet-loss experiment reuses the network-tools image. If it is absent,
build it without changing the authentication binary:

```sh
docker build -f Dockerfile.network -t mt-tls-network:latency .
```

## Step 3 — run tests and preflight

```sh
python3 packet_loss_campaign/control.py tests "$LOSS_ROOT"
python3 packet_loss_campaign/run.py --root "$LOSS_ROOT" --preflight
```

Expected regression marker in `tests.log`:

```text
ALL REGRESSION AND NEGATIVE TESTS PASS
```

Preflight checks the tested image, Git/source/fixture baseline, N=16 fixtures,
NET_ADMIN/qdisc operation, absence of TBF/HTB/rate qdiscs, connectivity and all
six authentication modes. Successful connections must retain TLS 1.3, X25519,
CertificateVerify, no resumption and the expected RPK/Compact/MTC verification.
Fixtures are mounted read-only.

## Step 4 — inspect without running

This command prints the complete plan, seeds, counts, Docker command and qdisc
template. It does not create the result directory, touch qdiscs or open TLS:

```sh
python3 packet_loss_campaign/run.py \
  --root artifacts/results/network-loss-dry-run \
  --dry-run
```

## Step 5 — smoke test

```sh
python3 packet_loss_campaign/run.py --root "$LOSS_ROOT" --smoke
```

Smoke uses loss 0%, 1% and 5%, one campaign each, three warmups and five measured
rounds: 90 measured attempts plus 54 warmup attempts. It is stored under
`$LOSS_ROOT/smoke/` and excluded from final analysis.

Inspect before continuing:

```sh
cat "$LOSS_ROOT/smoke-status.json"
find "$LOSS_ROOT/smoke" -name validation.json -exec cat {} \;
find "$LOSS_ROOT/smoke" -name failures.csv -exec wc -l {} \;
find "$LOSS_ROOT/smoke" -name '*qdisc*' -type f -print
```

Do not proceed if `passed` is false, RTT differs by more than the declared
±10 ms gate, the zero-loss probe observes loss, a qdisc contains TBF/HTB/rate
limiting, authentication controls fail, attempt counts disagree, or infrastructure
is marked invalid. At nonzero loss, TLS failures are scientific outcomes when
the infrastructure validation passes.

## Step 6 — full experiment

One copy-paste command launches all 30 campaigns:

```sh
python3 packet_loss_campaign/run.py --root "$LOSS_ROOT"
```

Expected full counts are 5,400 measured attempts and 900 warmup attempts. The
full probe sends 2,000 pings before every campaign. At 0.1% loss, even that finite
sample need not equal the configured rate; the qdisc is authoritative and the
observed estimate is reported separately.

## Step 7 — monitor without interruption

In a second terminal:

```sh
docker ps --filter label=com.docker.compose.project=mtloss
cat "$LOSS_ROOT/campaign-status.json"
find "$LOSS_ROOT/campaigns" -name driver.log -exec tail -n 3 {} \;
docker compose -f compose.network-loss.yaml exec server tc -s qdisc show dev eth0
du -sh "$LOSS_ROOT"
```

## Step 8 — analyze

```sh
python3 packet_loss_campaign/analyze.py "$LOSS_ROOT"
/tmp/mt-scaling-plots-venv/bin/python packet_loss_campaign/plots.py "$LOSS_ROOT"
python3 packet_loss_campaign/validate.py "$LOSS_ROOT"
python3 packet_loss_campaign/control.py audit "$LOSS_ROOT"
```

The plotting command needs matplotlib; the existing scaling plotting environment
is shown, or create a venv using `scaling_campaign/requirements-plots.txt`.

## Step 9 — inspect results

- `report.md`: interpretation and limitations.
- `scenario-summary.csv`: latency, CPU, bytes and failure rates.
- `bootstrap-comparisons.csv`: campaign effects and 10,000-resample intervals.
- `failures.csv`: every failed measured/warmup attempt.
- `retransmissions.csv`: campaign-level kernel counters.
- `network-validation.csv`, `qdisc-config.txt`, `qdisc-statistics.txt`: actual network evidence.
- `plots/`: four supported figures. Figure 5 is deliberately omitted because
  per-connection retransmission attribution is unavailable.

## Optional capture for one validation campaign

Capture is deliberately outside the full runner. In one terminal, after a smoke
server is running, identify its container and capture only the selected validation:

```sh
mkdir -p "$LOSS_ROOT/captures"
SERVER_ID=$(docker compose -f compose.network-loss.yaml ps -q server)
docker exec "$SERVER_ID" timeout 60 tcpdump -i eth0 -w /tmp/selected-loss.pcap
docker cp "$SERVER_ID:/tmp/selected-loss.pcap" "$LOSS_ROOT/captures/"
```

The current network image may not contain `tcpdump`; if absent, do not install it
inside a running validated container. Build and record a separate capture image.
Capture bytes are network-wire observations and must remain separate from TLS BIO
counters. Capture is optional and not used by the default analysis.

## Step 10 — cleanup

Normal exit attempts Compose shutdown even after Ctrl+C. Run the cleanup explicitly:

```sh
sh packet_loss_campaign/cleanup.sh
```

It removes experiment root qdiscs where containers still exist and stops only
the `mtloss` Compose project. It preserves results, fixtures and images.

## Step 11 — emergency cleanup

The same idempotent command is safe after interruption:

```sh
sh packet_loss_campaign/cleanup.sh
```

Verify afterward:

```sh
docker ps --filter label=com.docker.compose.project=mtloss
```

## Final Git state and tag

After the full manual experiment, analysis and audit, create a separate final
experiment commit if source/documentation changed, record it in the ignored result:

```sh
python3 packet_loss_campaign/record_commit.py "$LOSS_ROOT"
```

Then tag the validated final state separately, for example:

```sh
git tag -a v0.6.0-packet-loss -m "Validated packet-loss TLS experiment"
```

Do not add `artifacts/`, private keys, pcaps or transient Docker logs to Git.
