# Independent cryptographic-scaling entrypoints

Run from the repository root. No original campaign battery or historical fixtures
are prerequisites for the Paper-1 workflow.

```sh
# Prepare existing shared image dependencies, in order (manual Docker builds).
bin/cryptographic_scaling/mt-prepare run ALL

# First use only; then run the quick N=16 campaign when ready.
bin/cryptographic_scaling/mt-cert-scaling init
bin/cryptographic_scaling/mt-cert-scaling run ALL

# First use only: select Paper-1 ML-DSA-65 from the configured MTC16 root.
bin/cryptographic_scaling/mt-protocol-validation init
bin/cryptographic_scaling/mt-protocol-validation status
bin/cryptographic_scaling/mt-protocol-validation menu
```

Stop on any failure. If a launcher is already initialized, use `status` rather
than initializing it again. `mt-cert-scaling run ALL` includes the authorized
manual functional TLS gate; **mt-prepare does not run it**. Protocol stages are
selected individually. A completed crossover is not required for protocol checks;
only the prepared images and existing N=16 MTC fixtures are needed. To prepare
just those fixtures, initialize cert-scaling and select stages50 and60 after image
setup; X.509 chain fixture generation and analysis can be done independently.

`mt-prepare` provides `list`, `show N`, `status`, `run N`, `run ALL`, `rebuild N`,
`rebuild ALL` and a menu. Stages1–6 are base OpenSSL/PQ, Compact, profiling, MTC,
measurement and packet-capture tooling. `run N` prepares missing prerequisites
through N, reusing existing images. `rebuild` is explicit; after source changes,
rebuild ALL to refresh descendants as well. Existing image presence does not
certify source freshness or scientific validity. Do not rebuild during an active
campaign. Logs and the setup lock live under `.mt-state/cryptographic-setup/`.

The launcher checks Docker/Compose, Python3 and matplotlib. If matplotlib is
missing, it provides the installation command for the selected Python environment;
it does not silently modify that environment. Docker must already be running.
No network-impairment image, original regression battery, original fixtures,
benchmark, TLS connection or packet capture is started by this setup script.

It reuses the shared Dockerfiles currently located in `docker/original_campaigns/`.
Those recipes still contain historical instrumentation source dependencies;
this change removes **execution/state/data dependencies on earlier campaigns**,
not all code reuse. No recipes or algorithm versions are duplicated or changed.
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
