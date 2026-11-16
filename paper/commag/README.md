# IEEE Communications Magazine: Figures 4 and 5 and Table I

This public package contains per-connection data, summaries, figures, and
analysis scripts that reproduce **the values** in Figures 4 and 5 and Table I.
It also explains how to repeat the campaigns on Linux. Run all commands from
the MT repository root unless a command explicitly changes directory. No
private keys, Docker images, complete TLS traces, or machine-specific paths
from the raw Chromium CSV are included.

## Dataset map

| Result | Archived data | Measure and sample |
| --- | --- | --- |
| Figure 4, `s_client` | `data/figure_4/native.csv`, `summary.json` | Mean credential validation and `CertificateVerify` times; 100 measured connections per profile and arm, plus 5 warmups. P-384, ML-DSA-65, and SLH-DSA-192s. |
| Figure 5, Chromium | The `client=chromium` rows in `data/figures/authentication_samples.csv` and `authentication_statistics.csv` | The same two operations measured in Chromium; 100 connections per displayed profile and arm. P-384 and ML-DSA-65. Chromium did not measure SLH-DSA. |
| Table I | `data/table_i/native/` and `data/table_i/{ecdsa-p384,mldsa65,slhdsa192s}/` | Median bidirectional TLS bytes over 100 connections per arm. TLS 1.3, `X25519MLKEM768`, SNI `server.mtc.example.com`, X.509 D=3. |

A separate server repeat from November 16 is preserved under
[`data/repeat_20261116/`](data/repeat_20261116/README.md). Its figure values
and complete six-arm Table I have been recalculated. The repeat uses current
server credentials and keeps its figure and table blocks separate.

The figures come from **October 2026** measurement blocks, while the table
comes from local blocks run on **November 15, 2026**. Their timings are kept
separate and are not treated as paired observations. The archived Chromium
summary identifies image
`sha256:a7b1885e7927e01d82a78c55417ff853aca2b45a11c457bda08acdf5088e701d`;
the native Figure 4 summary did not record its image ID. All four X.509 arms
and the MTC arms in Table I record
`sha256:5a8b523dd976e28debc474f42b67b2a6a0f33013ae3b889e4c9562d3336e281e`.
For a repeat run, record the actual image ID as well as its Docker tag: a tag
can point to a different image after a rebuild.

`data/figures/authentication_samples.csv` and
`authentication_statistics.csv` are the archived anonymized per-connection
data and descriptive statistics for both figures. The original Chromium
`measurements.csv` and `summary.json` remain outside this public package
because they contain absolute machine paths. `scripts/prepare_authentication.py`
can process new raw campaigns into the same anonymized format.
`data/figure_4_5_values.csv` contains the 15 plotted heights, and
`data/table_i_values.csv` contains the 18 table cells, directional byte counts,
and percentages. The included `summary.json`, `config.json`, and
`authentication_checks.json` files provide provenance and checks.
`figures/archived/figure_4.*` and `figure_5.*` are PNG/PDF renderings saved
with the original analysis. Their numeric labels match the manuscript; their
palette and layout differ from the typeset version shown in the chat.

## 1. Check the archived data without contacting a server

```bash
cd /path/to/MT
python3 paper/commag/scripts/verify_data.py
```

The script requires 100 measurements per cell and checks the TLS group,
hostname, image ID, and directional agreement between the two ordinary X.509
references for Table I. It also checks that the figure means reproduce all
15 labels. It writes or updates both `*_values.csv` files.
To check the bytes of the archived data and figure files:

```bash
cd paper/commag
shasum -a 256 -c SHA256SUMS
cd ../..
```

To recompute the anonymized figure statistics from **new** native and Chromium
raw CSVs after running the campaigns below:

```bash
article=paper/commag
out="artifacts/results/commag-auth-analysis-$(date -u +%Y%m%dT%H%M%SZ)"
python3 "$article/scripts/prepare_authentication.py" \
  --native /path/to/native.csv \
  --chromium /path/to/measurements.csv \
  --out-dir "$out"
```

To draw Figures 4 and 5 from the archived statistics, install `matplotlib`
in the analysis environment and run:

```bash
article=paper/commag
plot_out="artifacts/results/commag-article-plots-$(date -u +%Y%m%dT%H%M%SZ)"
python3 "$article/scripts/plotter_tiempos.py" \
  "$article/data/figures/authentication_statistics.csv" \
  --figure auth --client s_client --level 3 --unit ms \
  --out-dir "$plot_out"
python3 "$article/scripts/plotter_tiempos.py" \
  "$article/data/figures/authentication_statistics.csv" \
  --figure auth --client chromium --level 3 --unit ms \
  --out-dir "$plot_out"
```

Each bar shows `auth_total_ns`: credential validation plus cryptographic
verification of the TLS `CertificateVerify` message, calculated **per
connection** before averaging. It does not show complete handshake time.
The plot places `CertificateVerify` below credential validation. The script
reproduces the values and components; its formatting may differ from the
final magazine layout. Generated plots do not replace the archived sources.

The compression runner's reporting script can recalculate a text report for
Table I without taking new measurements:

```bash
article=paper/commag/data/table_i
python3 campaigns/performance/x509_cert_compression/report_intermediate_elision.py \
  --study "ecdsa-p384=$article/ecdsa-p384" --archive "ecdsa-p384=$article/native" \
  --study "mldsa65=$article/mldsa65" --archive "mldsa65=$article/native" \
  --study "slhdsa192s=$article/slhdsa192s" --archive "slhdsa192s=$article/native"
```

## 2. Repeat Figures 4 and 5 on the server

Requirements: accessible Docker daemon, a built `mt-tls-mtc:local` image,
**instrumented** Chromium at
`/absolute/path/to/instrumented/chrome`, and the Chromium
runner's capture tools (`tshark` and either `dumpcap` or `tcpdump`). Run from
`/path/to/MT`. The new run uses `server.mtc.example.com` for both
clients. It generates new credentials, so the values may change. Record the
image ID before starting:

```bash
cd /path/to/MT
docker image inspect mt-tls-mtc:local --format '{{.Id}}'
```

### Figure 4: OpenSSL `s_client`

```bash
stamp=$(date -u +%Y%m%dT%H%M%SZ)
cfg=".mt-state/commag-auth-sclient-${stamp}.env"
out="artifacts/results/commag-auth-sclient-${stamp}"
xroot="artifacts/fixtures/commag-auth-x509-$stamp"
mroot="artifacts/mtc/commag-auth-mtc-$stamp"
vroot="artifacts/results/commag-auth-mtc-validation-$stamp"
image=mt-tls-mtc:local

python3 campaigns/scaling/cert_chain_scaling/generate_fixtures.py \
  --output "$xroot" --profile ecdsa-p384 --profile mldsa65 \
  --profile slhdsa192s --depth 3 \
  --server-hostname server.mtc.example.com --image "$image"
python3 campaigns/scaling/mtc_profile_scaling/workflow.py generate \
  --output "$mroot" --profile ecdsa-p384 --profile mldsa65 \
  --profile slhdsa192s --server-hostname server.mtc.example.com \
  --image "$image" --execute
python3 campaigns/scaling/mtc_profile_scaling/workflow.py validate \
  --fixtures "$mroot" --output "$vroot" \
  --profile ecdsa-p384 --profile mldsa65 --profile slhdsa192s \
  --server-hostname server.mtc.example.com --image "$image" --execute

bin/performance/mt-handshake-performance init "$cfg" x25519-mlkem768 3 100
sed -i -e 's/^SERVER_HOSTNAME=server$/SERVER_HOSTNAME=server.mtc.example.com/' \
  -e "s@^X509_CHAIN_FIXTURES=.*@X509_CHAIN_FIXTURES=$xroot@" \
  -e "s@^MTC_ROOT=.*@MTC_ROOT=$mroot@" \
  -e "s@^MTC_VALIDATION=.*@MTC_VALIDATION=$vroot/validation.json@" "$cfg"
IMAGE="$image" \
MT_HANDSHAKE_PROFILES=ecdsa-p384,mldsa65,slhdsa192s \
bin/performance/mt-handshake-performance run-native-single "$cfg" "$out"
printf 'CSV: %s/d3/native.csv\n' "$out"
```

The CSV contains five `warmup` rows and 100 `measured` rows per profile and
case (`x509-simple-d3`, `mtc-simple-landmark`, and
`mtc-simple-standalone`). For the bar heights, use
`credential_validation_total_ns` and `certificate_verify_crypto_ns` rather
than the broader `credential_verification_total_ms` and
`certificate_verify_ms` intervals.

### Figure 5: Chromium

The October Chromium X.509 matrix had certificates that expired on
November 14, 2026. Preparation may reuse that matrix based on its hashes
despite the expired certificates. A new worktree generates current credentials
and preserves earlier results. If a worktree for this repeat run already
exists, enter it without creating another one.

```bash
cd /path/to/MT
worktree="../MTC-openssl-auth-$(date -u +%Y%m%dT%H%M%SZ)"
git worktree add --detach "$worktree" HEAD
cd "$worktree"
CHROMIUM_BIN=/absolute/path/to/instrumented/chrome
test -x "$CHROMIUM_BIN"
for perfil in ecdsa-p384 mldsa65; do
  bin/browser_client/mt-chromium-tests browser-measurements run \
    --chromium "$CHROMIUM_BIN" --image mt-tls-mtc:local \
    --key-establishment x25519-mlkem768 \
    --profile "$perfil" --depth 3 --warmups 5 --pairs 100 || break
done
```

Each profile runs in a separate measurement block. The runner prints its
`artifacts/results/chromium-browser-measurements-*` directory, which contains
`measurements.csv`, `summary.json`, and per-connection evidence. Confirm 300
measured rows per profile (100 per case) and `overall_pass=true` in the
summary. Keep the two blocks separate; do not add their means or pair them
with `s_client` observations. The worktree shares the server's Docker images
but not the fixtures or `artifacts/` directory of the original checkout.

To produce a combined **figure-value report** from the native CSV and the two
separate Chromium blocks, run this command from a checkout containing the
`paper/commag` scripts. Replace the three source paths with the actual run
directories. The script checks each block and writes 15 anonymous bar values;
it never concatenates the raw Chromium files:

```bash
python3 paper/commag/scripts/summarize_new_figures.py \
  --native /path/to/native-run/d3/native.csv \
  --chromium /path/to/p384-run/measurements.csv \
  --chromium /path/to/mldsa65-run/measurements.csv \
  --output "artifacts/results/commag-figure-values-$(date -u +%Y%m%dT%H%M%SZ).csv"
```

## 3. Repeat Table I

Table I requires a different image, `mt-tls-mtc-cert-comp-pq:local`, with
zlib and auxiliary certificate support. It uses TLS 1.3,
`X25519MLKEM768`, SNI `server.mtc.example.com`, and the same D=3 X.509
credentials for all four X.509 arms within each profile. The native block
measures ordinary X.509, MTC Standalone, and MTC Landmark. The intermediate
elision runner measures ordinary and zlib-offered X.509 with the complete
chain and with the intermediate omitted. The two ordinary X.509 references
must agree in each direction before sharing a denominator.

If the image is missing, build it from `mt-tls-mtc:local`:

```bash
docker build -f campaigns/performance/x509_cert_compression/Dockerfile.zlib \
  -t mt-tls-mtc-cert-comp:local .
docker build -f campaigns/performance/x509_cert_compression/Dockerfile \
  -t mt-tls-mtc-cert-comp-pq:local .
docker image inspect mt-tls-mtc-cert-comp-pq:local --format '{{.Id}}'
```

Use **new paths** to preserve every earlier campaign. Run the following
block from the server checkout root:

```bash
stamp=$(date -u +%Y%m%dT%H%M%SZ)
xroot="artifacts/fixtures/commag-article-x509-$stamp"
mroot="artifacts/mtc/commag-article-mtc-$stamp"
vroot="artifacts/results/commag-article-mtc-validation-$stamp"
prefix="artifacts/results/commag-article-table-$stamp"
image=mt-tls-mtc-cert-comp-pq:local

python3 campaigns/scaling/cert_chain_scaling/generate_fixtures.py \
  --output "$xroot" --profile mldsa65 --profile slhdsa192s \
  --profile ecdsa-p384 --depth 3 \
  --server-hostname server.mtc.example.com --image "$image"
python3 campaigns/scaling/mtc_profile_scaling/workflow.py generate \
  --output "$mroot" --profile mldsa65 --profile slhdsa192s \
  --profile ecdsa-p384 --server-hostname server.mtc.example.com \
  --image "$image" --execute
python3 campaigns/scaling/mtc_profile_scaling/workflow.py validate \
  --fixtures "$mroot" --output "$vroot" \
  --profile mldsa65 --profile slhdsa192s --profile ecdsa-p384 \
  --server-hostname server.mtc.example.com --image "$image" --execute

for phase in pilot full; do
  template="campaigns/performance/x509_cert_compression/configs/browsername-native-$phase.env"
  config=".mt-state/commag-article-table-$phase-$stamp.env"
  sed -e "s@artifacts/fixtures/commag-browsername-x509-20261115a@$xroot@" \
      -e "s@artifacts/mtc/commag-browsername-n16-20261115a@$mroot@" \
      -e "s@artifacts/results/commag-browsername-mtc-validation-20261115a@$vroot@" \
      "$template" > "$config"
done

MT_HANDSHAKE_PROFILES=mldsa65,slhdsa192s,ecdsa-p384 \
MT_HANDSHAKE_NO_RX_CERT_COMP=1 MT_HANDSHAKE_TRACE_MESSAGES=1 \
IMAGE="$image" bin/performance/mt-handshake-performance run-native-single \
  ".mt-state/commag-article-table-pilot-$stamp.env" "$prefix-native-pilot"

for profile in mldsa65 slhdsa192s ecdsa-p384; do
  python3 campaigns/performance/x509_cert_compression/run.py \
    --intermediate-elision --x509-fixture "$xroot/$profile/depth-3" \
    --profile "$profile" --hostname server.mtc.example.com \
    --reference-native-csv "$prefix-native-pilot/d3/native.csv" \
    --output "$prefix-$profile-elision-pilot" --image "$image" \
    --warmups 0 --runs 1 --execute || break
done
```

Check all three pilot `summary.json` files for `pilot_pass=true`, matching
X.509 references, two transmitted certificates with the complete chain, and
one with the intermediate omitted. The `Omitted + zlib offered` arm records
the message actually sent; offering zlib does not require the server to send
`CompressedCertificate`.

If the pilots pass, run the full campaign:

```bash
MT_HANDSHAKE_PROFILES=mldsa65,slhdsa192s,ecdsa-p384 \
MT_HANDSHAKE_NO_RX_CERT_COMP=1 MT_HANDSHAKE_TRACE_MESSAGES=1 \
IMAGE="$image" bin/performance/mt-handshake-performance run-native-single \
  ".mt-state/commag-article-table-full-$stamp.env" "$prefix-native-full"

for profile in mldsa65 slhdsa192s ecdsa-p384; do
  python3 campaigns/performance/x509_cert_compression/run.py \
    --intermediate-elision --x509-fixture "$xroot/$profile/depth-3" \
    --profile "$profile" --hostname server.mtc.example.com \
    --pilot-summary "$prefix-$profile-elision-pilot/summary.json" \
    --output "$prefix-$profile-elision-full" --image "$image" \
    --warmups 5 --runs 100 --execute || break
done

python3 campaigns/performance/x509_cert_compression/report_intermediate_elision.py \
  --study "ecdsa-p384=$prefix-ecdsa-p384-elision-full" --archive "ecdsa-p384=$prefix-native-full/d3" \
  --study "mldsa65=$prefix-mldsa65-elision-full" --archive "mldsa65=$prefix-native-full/d3" \
  --study "slhdsa192s=$prefix-slhdsa192s-elision-full" --archive "slhdsa192s=$prefix-native-full/d3"
```

Keep `native.csv`, all three `samples.csv` files, their summaries and
configurations, the image ID, certificate hashes, and the pilot and full-run
logs. Each percentage in the table is
`100 × (bytes_X509_D3 − bytes_arm) / bytes_X509_D3`, using the **median
bidirectional byte count** for the same profile. Runner latencies come from
independent blocks and must not be compared as paired observations.

## 4. Adding future paper datasets

Put each new paper in its own `paper/<paper-id>/` directory. For a repeat of
this paper, keep the original files intact and add a run-specific subdirectory
under `paper/commag/data/`. Record the source campaign path, Git commit,
Docker image ID, Chromium build, hostname, TLS group, certificate hashes,
warmup and measured counts, and the exact columns used in each reported
statistic. Check the new run independently before replacing any manuscript
number. Do not mix timing observations from separate runners or campaigns.

Export per-connection Chromium data through `prepare_authentication.py` before
publication. Its anonymized samples and statistics retain the timing fields
needed for the figures; the raw browser CSV and its summary may contain
absolute machine paths and should remain outside this public directory.
