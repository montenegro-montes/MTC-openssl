# Controlled N=16 measurement campaigns

This layer measures the saved laboratory; it does not change authentication rules.
MTC remains **MTC-experimental**, targeting draft-ietf-plants-merkle-tree-certs-05.
The saved protocol baseline is commit `91fd70a7a8de81a9433f364c0f30ea105fcf071f`.

The only native-code addition is a pair of wrappers around `compact_client()` and
`mtc_client()` in an isolated s_client. They measure wall/process CPU before TLS
and return exactly the original result. The original libraries and sources stay
unchanged. Setup includes configuration loading, validation and callback registration,
including nested diagnostic logging; the new MEASUREMENT_SETUP output is outside its timer.

## Completed run

See [the validated N=16 report](../../artifacts/results/paper-n16-20260910T050955152797Z/report.md). The directory retains its legacy name because it is immutable experiment evidence.
Ten campaigns, seeds 42–51, 14 scenarios, 5 warmup and 30 measured paired rounds:
4200 measurements plus 700 warmups. A separate measurement preflight (28 + 14)
and security tests are not counted as campaign observations. No scaling was run.

## Step 1 — inspect the frozen inputs

Run from the repository root. Use a new directory for every experiment. The existing driver deliberately refuses
to overwrite a campaign or silently retry a failed campaign. The N=16 inputs are
`artifacts/compact/batch16` and `artifacts/mtc/batch16-v2`. No fixture generation
is part of this measurement workflow.

```sh
git status --short
git rev-parse HEAD
python3 -m campaigns.common.image_chain measurement
test -d artifacts/compact/batch16
test -d artifacts/mtc/batch16-v2
test -d artifacts/certs
```

## Step 2 — initialize the reproducibility metadata

Choose a timestamped path and initialize its reproducibility metadata:

```sh
N16_ROOT="artifacts/results/controlled-n16-$(date +%Y%m%d-%H%M%S)"
echo "$N16_ROOT"
python3 campaigns/original_campaigns/controlled_n16_campaign/control.py init "$N16_ROOT"
```

Record Git commit/status, SHA-256 of tracked source and N=16 fixtures, and local
   Docker image IDs/digests in the new experiment directory. The completed run's
   `baseline*.json`, `fixture-sha256.json` and `environment-before.json` show the
   schemas expected by the runner. Inventory private keys by hash only; never copy
   their contents into the result/source snapshot or Git.

The initializer records the current Git commit/status, measurement image,
environment, source hashes and N=16 fixture hashes. It accepts an existing empty
directory so a failed setup attempt can be recovered, but refuses any directory
that already contains campaign data. It never copies historical measurements.

## Step 3 — build the measurement image

Build the measurement image on the recorded local MTC image. BuildKit uses a
   local tag rather than a raw image ID in FROM. Verify that the base tag points
   to the recorded ID before building:

   ```sh
   docker build -f docker/original_campaigns/Dockerfile.measurement --build-arg BASE_IMAGE=mt-tls-mtc:local -t mt-tls-measurement:local .
   ```

## Step 4 — run and record the regression gate

Run the regression gate through the campaign control command. It executes
`sh /opt/measurement/tests.sh` inside that image with `artifacts` mounted
read-only at `/work`, captures `tests.log`, and saves `tests-status.json` with
the exit code and actual image ID. Any failure blocks the experiment.
   The original `mtc_tests` demo uses exit 1 for success; `test_legacy.py` verifies
   both that convention and its positive output instead of altering the demo.

```sh
python3 campaigns/original_campaigns/controlled_n16_campaign/control.py tests "$N16_ROOT"
```

Record the exit code and exact image ID in `tests-status.json`. Do not continue
after a failed test.

## Step 5 — run the measurement preflight

The root must be a new
   initialized directory beneath `artifacts/results/`:

   ```sh
   python3 campaigns/original_campaigns/controlled_n16_campaign/run.py --root "$N16_ROOT" --preflight
   cat "$N16_ROOT/measurement-preflight-status.json"
   ```

## Step 6 — run the full campaign

```sh
python3 campaigns/original_campaigns/controlled_n16_campaign/run.py --root "$N16_ROOT"
```

Each campaign recreates the server container but retains the same bridge throughout
the ten campaigns. Resource settings and server container IDs are recorded and checked.
Docker Desktop itself is not restarted. Servers persist across rounds; every sample
starts a new client process. Source/fixture hash mismatches, repeated campaign directories,
failed handshakes or incorrect counts/control fields abort the run. No automatic retries.

## Step 7 — monitor from a second terminal

```sh
docker ps --filter label=com.docker.compose.project=controlledn16
cat "$N16_ROOT/campaign-status.json"
find "$N16_ROOT" -name driver.log -exec tail -n 3 {} \;
du -sh "$N16_ROOT"
```

## Step 8 — test the analyzer and generate results

```sh
python3 campaigns/original_campaigns/controlled_n16_campaign/test_analysis.py
python3 campaigns/original_campaigns/controlled_n16_campaign/analyze.py "$N16_ROOT"
cat "$N16_ROOT/report.md"
ls -lh "$N16_ROOT"/*.csv
```

## Step 9 — preserve the completed experiment

```sh
git status --short
git rev-parse HEAD
```

Commit this experiment separately from scaling and network experiments. Record
the resulting experiment commit in `metadata.json` and `report.md`. Keep raw
results, snapshots and private keys under ignored `artifacts/`.

## Accounting and analysis

`measure.py` extends the saved driver without rewriting its TLS metric definitions.
Campaign and seed identifiers, round/order, warmups, full configuration setup CPU/wall
and protocol-specific sizes are retained. Empty fields mean unmeasured/not applicable.

Transport bytes, handshake messages, raw signatures, DER and local trust-file sizes
are distinct quantities. Generic predistributed bytes include the local CA/config
base; incremental bytes separately identify the root/landmark addition. Compact's
base file is PEM, MTC's binary. Neither is a measured remote distribution protocol.
A 3399-byte PQ Compact root produces a 3367-byte cold/warm TLS difference because
warm additionally advertises a 32-byte root identifier in ClientHello.

Warm root and landmark validation repeats in every client process. No persistent
cache or amortization is measured. `trust_validation_ms` is nested within setup:
only root-signature verification for Compact warm, checkpoint signatures for MTC
landmark. It must not be added to setup or treated as all setup work.

`analyze.py` first calculates scenario medians and round-paired median differences
within each campaign. Its final bootstrap resamples ten campaign effects, 10000
times with seed 20260910. It never treats 300 handshakes as independent replicates.
The saved within-campaign 2000-resample comparisons remain secondary.

CV means sample SD/mean of the ten campaign medians. Timing sign instability means
at least two campaigns of each sign; an interval crossing zero is also uncertain.
Outliers use within-campaign/scenario Tukey 1.5-IQR fences; all observations remain.
No null-hypothesis significance tests are performed.

Compact/MTC pairs are architectural comparisons, not protocol-equivalent. Standalone
MTC includes a local cosigner while the X509 reference has no SCTs. The previous
component profile's SPKI-encoding cost must not be relabelled as Merkle hashing cost.

## Optional per-observation PCAP accounting (Stage 4)

Capture is disabled by default. To opt in for a **new instrumented run**, add
`--pcap` to `run.py` (including the measurement preflight if capture is desired
there). This option does not reduce the existing campaign loops: do not use it
as a one-handshake smoke command. All existing image/test/preflight gates remain.
An existing `mt-tls-capture:local` image is required; the integration does not build
it. Initialize fresh source provenance after applying this patch. Capture scripts
are mounted read-only; no native measurement-image rebuild is needed for this adapter.

The persistent capture sidecar shares server networking and observes `eth0`.
Measured observations request one tcpdump process each, filtered by server port;
warmups do not request captures. A `listening on eth0` message confirms readiness
before the client starts. Each client uses its observation's `tls.keys` via
`-keylogfile`. After the original sample function returns or raises, the driver
requests shutdown. The sidecar allows 1.2 seconds for buffer delivery, sends
SIGINT, waits for clean exit, checks size and tests readability with tcpdump.
All coordination/draining is outside the existing process and OpenSSL timers.

After the measurement driver finishes, the adapter invokes the unchanged
`handshake_capture/analyze.py` once per successful observation capture. No tshark
analysis runs alongside measured handshakes. It remains the only metric parser.

Artifacts live under `<root>/<campaign_id>/pcap/sample-<zero-based-round>-<scenario>/`:

- `observation.json`: existing campaign, one-based `round_id`, zero-based `round`,
  scenario, order, warmup flag and links to the existing sample CSV/client log.
- `connections.json`, `handshakes.pcap`, `tls.keys`: Stage-1 input layout.
- `request.json`, `ready.json`, `stop`, `capture-status.json`, `tls-status.json`,
  optional `client-capture-error.json`, and `tcpdump.log`: coordination/audit trail.
- `packets.csv`, `summary.json`, `analysis.log`, `tshark.log`, `derived.json`:
  extractor outputs and the joined observation result.

`<campaign_id>/pcap-metrics.jsonl` joins the observation tuple to the successful
sample's existing `client_random`, PCAP hash, artifact directory, boundary fields
and eight Stage-1 metrics. The adapter checks the key log against that same
`client_random`; no key material is copied into derived reports. Key logs and
captures remain sensitive ignored artifacts. No compression or retention changes
are introduced; storage grows with the number and size of captured observations.

Capture status is `SUCCESS` or `CAPTURE_FAILURE`. Analysis status is `SUCCESS`,
`ANALYSIS_FAILURE` or `NOT_EXECUTED`. TLS status separately records `SUCCESS` or
`TLS_MEASUREMENT_FAILURE`; existing handshake/telemetry failures still abort the
campaign. Capture/analysis failures preserve successful TLS rows and set derived
`metrics` to JSON `null`, never fabricated zeros. An analyzer-container failure is
also recorded in `pcap-analysis-status.json` and campaign status. No measurements
are retried. A capture coordination timeout is bounded and recorded explicitly.

Existing `samples.csv`, warmups, statistical analysis, `handshake_wall_ms`,
`transport_total_bytes`, `transport_read_bytes` and `transport_written_bytes`
retain their definitions. `handshake_wall_ms` remains primary; PCAP timing is
secondary. Campaign status records `pcap_enabled`, capture image identity and
`performance_comparable_to_uncaptured: false`. Do not pool instrumented timings
with historical uncaptured runs: key logging/capture load and between-sample
coordination can perturb execution even though timer boundaries are unchanged.
See the [extractor semantics](../handshake_capture/README.md) for byte layers,
retransmissions, frame-completion endpoints and IPv4 limitations.

Lightweight validation:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s campaigns/original_campaigns/controlled_n16_campaign -p test_capture.py
```

Tests cover mocked readiness/drain/SIGINT/readability coordination, observation
joining, extractor delegation, null failure metrics, key-log mismatch, disabled
capture, warmups and source transformation guards. A tiny synthetic PCAP is read
by local tcpdump when available. These checks are not an end-to-end Docker/TLS
validation; a live capture remains unexecuted. No full campaign was run for this
integration. Latency, bandwidth, loss and combined campaigns remain unchanged.
