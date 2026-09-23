# Independent cryptographic-scaling entrypoints

Run from the repository root. No original campaign battery or historical fixtures
are prerequisites for the Paper-1 workflow.

```sh
# Prepare existing shared image dependencies, in order (manual Docker builds).
bin/base/mt-prepare run ALL

# First use only; then run the quick N=16 campaign when ready.
bin/cryptographic_scaling/mt-cert-scaling run ALL

# First use only: select Paper-1 ML-DSA-65 from the configured MTC16 root.
bin/base/mt-protocol-validation status
bin/base/mt-protocol-validation menu
```

The manual handshake comparator covers X.509 and MTC-experimental with both
server-only and mutual authentication. It records host-side execution time,
OpenSSL handshake bytes, independent packet captures, captured connection time
and wire bytes:

```sh
bin/performance/mt-handshake-performance init
bin/performance/mt-handshake-performance plan .mt-state/handshake-performance.env
```

Edit the generated fixture paths before using `run-native`, `run-pcap` or
`run-all`. The launcher never overwrites an output directory.

Stop on any failure. If a launcher is already initialized, use `status` rather
than initializing it again. `mt-cert-scaling run ALL` includes the authorized
manual functional TLS gate; **mt-prepare run ALL also runs this gate**. Protocol stages are
selected individually. A completed crossover is not required for protocol checks;
only the prepared images and existing N=16 MTC fixtures are needed. To prepare
just those fixtures, initialize cert-scaling and select stages50 and60 after image
setup; X.509 chain fixture generation and analysis can be done independently.

`mt-prepare` provides `list`, `show N`, `status`, `run N`, `run ALL`, `rebuild N`,
`rebuild ALL` and a menu. Stages 1–3 are base OpenSSL/PQ, MTC and packet-capture
tooling. Compact, its profiling image and its combined measurement image are not
part of this preparation. `run N` prepares missing prerequisites
through N, reusing existing images. `rebuild` is explicit; after source changes,
rebuild ALL to refresh descendants as well. Existing image presence does not
certify source freshness or scientific validity. Do not rebuild during an active
campaign. Logs and the setup lock live under `.mt-state/cryptographic-setup/`.

The launcher checks Docker/Compose, Python3 and matplotlib. If matplotlib is
missing, it provides the installation command for the selected Python environment;
it does not silently modify that environment. Docker must already be running.
No original campaign battery or packet capture is started. `run ALL` includes
N=16 generation and functional TLS validation; it does not run a performance matrix.

It uses the MTC/X.509 image chain under `docker/base/`. These prerequisites are
independent of historical campaigns and their results. Compact remains available
only under the historical source and Docker directories.
Image tags are shared with the lab, so explicit rebuilds affect subsequent users
of those tags. Scientific runs retain their image/source provenance gates.

For protocol validation, new `init` reads the saved cert-scaling MTC16 path and
sets PROFILE=mldsa65, FIX=MTC16/batch16/mtc/mldsa65 and
KEY=MTC16/population/mldsa65/0.key. It only records paths; fixtures must exist before
running. Existing protocol configurations without PROFILE retain legacy pq.
Use `new` for a fresh Paper-1 protocol campaign while preserving old state/results.
`init-legacy` is available explicitly for historical pq fixtures, with no automatic
reinterpretation or regeneration. PROFILE/FIX/KEY may be changed before evidence
exists. The profile is checked against the canonical issuer/cosigner registry.

## TLS performance workflow

`run ALL` runs fixture validation and the N=16 size-crossover stages. The former
TLS performance stages are disabled because their measurement image included
Compact instrumentation. They must not be used in the MTC/X.509-only battery
until a dedicated measurement runner is implemented.

| Stage | Action |
| --- | --- |
| 110 | Disabled MTC/X.509 matrix preview |
| 120 | Disabled TLS execution |
| 130 | Historical-result analysis only |
| 140 | Historical-result plots only |

Stages 110 and 120 fail closed with an explanatory error. Existing historical
measurement evidence remains readable by stages 130 and 140, but the launcher
will not create new Compact-derived measurements.

`TLS_ROOT` defaults to `artifacts/results/cert-chain-tls-$STAMP`, including for
older launcher configurations. Select another fresh location with
`mt-cert-scaling set TLS_ROOT artifacts/results/cert-chain-tls-NEW`.
The analysis writes `summary.csv`, `summary.json` and
`summary-algorithm_support.csv` under that root. Plots require the existing
N=16 crossover tables in `STATIC_ROOT` and Matplotlib. Existing output is
preserved; after a failure, inspect the log and use the individual remaining
stages or the documented runner resume procedure. The combined command does
not automatically resume or overwrite a previous TLS run.

## Initialize shared launcher paths

`mt-prepare run ALL` (or a successful `run N` / `rebuild`) initializes missing
cert-scaling configuration first, then protocol-validation configuration using
its N=16 path. Existing configurations, custom paths and results are preserved.
Do not run a separate launcher `init` afterward; inspect `status` instead.

If images were prepared before this change, configure the missing paths only:

```sh
bin/base/mt-prepare init
```

This command does not need Docker and does not generate fixtures. Run `mt-prepare run ALL` to also generate and validate N=16 fixtures automatically.
Existing fixture outputs are preserved; inspect status before repeating stages.

### Automatic N=16 prerequisites

`mt-prepare run ALL` prepares images and missing launcher configuration, then
runs certification stage 50 (N=16 generation) and stage 60 (functional TLS checks)
automatically when their outputs do not exist. No separate manual invocation of
those stages is needed. It checks the validation gate against fixture hashes,
current source hashes and the current MTC image before reporting success.
Existing incomplete, failed or stale evidence is preserved and reported as an
error; it is never overwritten. Existing custom protocol paths are preserved
and must match the prepared Paper-1 profile before setup reports readiness.

`run N` and `rebuild N` remain image-only preparation plus configuration, so the
certification image stage cannot recursively start fixture generation.
`init` only saves missing configuration. `run ALL` and `rebuild ALL` include
functional TLS validation, but no performance matrix or protocol capture.
