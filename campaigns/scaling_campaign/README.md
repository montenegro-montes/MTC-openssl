# Controlled Merkle scaling

This layer preserves the exact N=16 measurement image:
`sha256:4b04891fc50251a422c3357f35f355151ea50150d0e678dadde8c8f97b968b43`.
No native protocol, Merkle algorithm, encoding or timer implementation is changed.
The baseline repository commit is `d6771842a42b32ccdd56fc35978fc6ecfcc5c95a`.

The prior preflight found a missing `leaf0_spki_bytes` field in the old exploratory
scaling generator. The user authorized new fixture metadata and separately
identified campaigns using the existing detailed timers. `generate.py` calls the
saved encoders, adds the actual SPKI DER length, and preserves server identity,
validity and MTC signing keys. It creates a common population and prefix snapshots.
Existing fixtures and earlier N=16 results are never overwritten.

## Design

N = 1, 4, 16, 64, 256, 1024. At each N, five independent campaigns use seeds
1000+N through 5000+N. Each has five warmup and thirty measured paired rounds.
The twelve primary scenarios include six classic and six PQ modes: X.509, RPK,
Compact warm/cold, MTC standalone/landmark. Baselines are repeated for paired
comparisons. This totals 10,800 primary handshakes plus 1,800 warmups.

Thirty separate detail campaigns run the four PQ Merkle scenarios with the same
round policy, totaling 3,600 measurements plus 600 warmups. They enable existing
PROFILE_DETAIL=1 timers in the same binary. The primary `/opt/paper/measure.py`
remains unchanged; `detail_measure.py` changes only the separate collector's
expected detail flag. MTC inclusion-proof-only CPU is not instrumented and is
reported as unavailable; generic peer_auth is not relabelled as proof CPU.
Nested timers are never summed.

Every campaign recreates the server container, retains the same bridge/resource
settings, records public ClientHello random correlation, and validates both
endpoints. Authentication success for MTC includes exact ID negotiation and
Certificate confirmation, with a landmark-specific ID where applicable. Population
N is linked through immutable fixture hashes, parsed proof/checkpoint values and
sample metadata; the native log does not independently print N. No failed sample
or outlier is silently dropped; a campaign error stops the run.

N=1 is a no-sibling corner case. For N≥4, the saved MTC covering subtrees require
one fewer sibling level than the full Compact tree. Actual encoded objects, DER
boundaries and TLS bytes are measured separately from theoretical hash-path sizes.

## Step 1 — inspect the environment

Run from the repository root with the exact local Docker image available.
Confirm the Git state, frozen image and N=16 regression fixtures:

```sh
git status --short
git rev-parse HEAD
docker image inspect sha256:4b04891fc50251a422c3357f35f355151ea50150d0e678dadde8c8f97b968b43 --format '{{.Id}}'
docker ps
test -d artifacts/compact/batch16
test -d artifacts/mtc/batch16-v2
```

## Step 2 — initialize a new result directory

```sh
SCALING_ROOT="artifacts/results/scaling-$(date +%Y%m%d-%H%M%S)"
echo "$SCALING_ROOT"
python3 campaigns/scaling_campaign/control.py init "$SCALING_ROOT"
```

The command refuses existing paths. Keep this variable for the complete run.

## Step 3 — run the pre-generation regression gate

```sh
python3 campaigns/scaling_campaign/control.py tests-before "$SCALING_ROOT"
cat "$SCALING_ROOT/tests-status.json"
```

Do not generate fixtures unless this gate passes.

## Step 4 — generate and structurally validate fixtures

```sh
python3 campaigns/scaling_campaign/control.py generate "$SCALING_ROOT"
python3 campaigns/scaling_campaign/structural.py "$SCALING_ROOT"
```

Inspect the generated manifests and structural report before measuring. Existing
N=16 fixtures and previous outputs are not overwritten.

## Step 5 — run the measurement preflight

```sh
python3 campaigns/scaling_campaign/run.py "$SCALING_ROOT" --preflight
cat "$SCALING_ROOT/preflight-run-status.json"
```

The six short preflight campaigns collect 96 checks and 48 warmups and remain
outside full-campaign inference.

## Step 6 — run the full experiment

```sh
python3 campaigns/scaling_campaign/run.py "$SCALING_ROOT"
```

The full runner creates sixty campaigns and refuses existing campaign paths or
automatic retries.

## Step 7 — monitor from a second terminal

```sh
docker ps --filter label=com.docker.compose.project=mtscaling
cat "$SCALING_ROOT/campaign-status.json"
find "$SCALING_ROOT" -name driver.log -exec tail -n 3 {} \;
du -sh "$SCALING_ROOT"
```

## Step 8 — rerun regression tests

```sh
python3 campaigns/scaling_campaign/control.py tests-after "$SCALING_ROOT"
```

This confirms that the frozen N=16 behavior still passes after collection.

## Step 9 — analyze, plot and audit

```sh
python3 campaigns/scaling_campaign/test_analysis.py
python3 campaigns/scaling_campaign/analyze.py "$SCALING_ROOT"
python3 campaigns/scaling_campaign/plots.py "$SCALING_ROOT"
python3 campaigns/scaling_campaign/control.py audit "$SCALING_ROOT"
```

Plot generation needs matplotlib and numpy; use a separate virtual environment
and install `campaigns/scaling_campaign/requirements-plots.txt`.
The completed output records their exact versions. Everything else uses Python's
standard library on the host or the saved container tools. The fixtures are under
`artifacts/scaling/<result-directory-name>/batchN/{compact,mtc}/`. After structural validation,
fixture files are read-only and benchmark containers mount them read-only too.
Private keys remain in fixture storage, excluded by Git; outputs record hashes.

## Step 10 — inspect and preserve the result

```sh
cat "$SCALING_ROOT/report.md"
ls -lh "$SCALING_ROOT"/*.csv
git status --short
git rev-parse HEAD
```

Commit scaling changes and documentation separately from later network
experiments. Keep generated fixtures, private keys, raw results and Docker logs
under ignored `artifacts/`.

## Analysis and interpretation

`campaign-summary.csv` first takes within-campaign medians. `paired-comparisons.csv`
uses median round-paired differences; `bootstrap-comparisons.csv` resamples five
campaign effects at fixed N 10,000 times, with seed 20260910. It never resamples
pooled handshakes for final inference. Byte effects have no bootstrap intervals.
ECDSA observed median/min/max are retained. All outliers remain included.

Ascending N order can confound timing trends with host/time drift. Detail and
primary results must not be pooled. Plots show campaign medians and descriptive
serialized-size fits; no CPU regression is forced. Five campaigns give coarse
intervals and do not establish performance on other hosts.

The trust/H amortization is analytical bytes, not measured persistent reuse.
The primary stored-material model uses a Compact signed root versus the entire
MTC landmark file; a second model excludes the MTC authority base. Distribution
transport overhead, updates, failures and provisioning actions are unmeasured.
Setup/validation repeats per client process.

MTC-experimental retains richer X.509/MTC semantics and a CA plus local cosigner
model. Compact cold versus MTC standalone is an architectural comparison, not a
security-equivalent byte saving. Public transparency, full MTC PKIX support and
isolated MTC proof CPU are outside this validated implementation.

## Completed campaign

[Report and tables](../../artifacts/results/scaling-20260910T055410560403Z/report.md).
All sixty campaigns completed. Two primary campaigns, `primary-n256-c5` and
`primary-n1024-c1`, showed a marked wall/CPU slowdown even in the fixed RPK
baseline. They remain included. Byte findings are invariant in PQ; causal
interpretation of absolute timing scaling is provisional. MTC landmark vs X.509
handshake timing is uncertain at N=1024. The full report distinguishes these
limitations from passed authentication, regression and preservation checks.
