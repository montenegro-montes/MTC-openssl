# Offline experiment evidence reports

The HTML report is a derived presentation artifact. Existing JSON/JSONL/CSV
outputs remain the canonical scientific records. Rendering never runs a
measurement, alters fixtures/results, repairs missing values, pools captured
and uncaptured observations, or computes statistical inference.

## Usage and output policy

```bash
bin/artifacts/mt-report artifacts/integration-smoke/stage6c-native-correction
bin/artifacts/mt-report <results-directory> --output artifacts/reports/custom.html
```

Default output: `artifacts/reports/<source-name>-<source-path-hash>/report.html`.
Outputs inside the source directory and overwrites are rejected. Choose another
`--output` for a subsequent rendering. Open the single HTML file locally; no
server, Internet, CDN, fonts, JavaScript or third-party Python packages are
required. The report is usable with JavaScript disabled.

## Audited source map

| Producer | Canonical artifacts / schema differences |
|---|---|
| Controlled N=16 | Per-campaign `samples.csv`, `warmups.csv`, `metadata.json`, server metrics keyed by client random; root `campaign-status.json`, `all-samples.csv`, `all-warmups.csv`, `campaign-summary.csv`, `scenario-summary.csv`, `paired-comparisons.csv`, `bootstrap-comparisons.csv`; tests/preflight/preservation status and source/fixture SHA-256 inventories, measurement provenance and environments |
| Latency | Network fields added to samples/warmups; `validation.json` contains configured RTT and measured ping statistics; campaign/smoke status, existing summary/comparison CSV, environments and source/fixture hashes |
| Bandwidth | Similar CSV driver, but validation separates target rate/RTT from measured goodput/RTT; qdisc evidence and algorithm/condition-specific summary outputs |
| Packet loss | Separate `failures.csv` with warmup classification; measured-success samples, network validation, namespace `tcp-counters.json`; analysis status, retransmission/network CSV and campaign/paired/bootstrap summaries |
| Combined network | Profile records and `campaigns/<id>` hierarchy; failures, configured/validated network telemetry, campaign TCP counters, main/scenario/paired tables and optional isolated comparisons; no summing isolated effects |
| Stage-1 extractor | `summary.json.scenarios[]` contains packet-boundary timing and wire metrics; `connections.json` identifies scenarios/ports; `packets.csv` is a packet table, not observation statistics; PCAP hash and decryption flag in summary |
| Stage-4/6 integration | Per-observation `observation.json`, `capture-status.json`, `derived.json` with association/status and nested `metrics`; `pcap-metrics.jsonl` at campaign level. Analysis failure status remains separate from TLS success |
| Native profiling | `PROFILE_METRICS` in logs, server JSON, sample/component/summary CSV, metadata/environment/source hashes. Reports read machine-readable JSON/CSV, not reparsed TLS logs |
| Integration smokes | Native smoke `result.json.values` plus explicit smoke/scientific/comparability/PCAP flags; latency smoke has metadata, capture status and Stage-1 summary, without a complete campaign schema |
| Existing certificate-chain TLS results | `manifest.json`, environment/fixture hashes, cell-level observations and root summary CSV/JSON with recorded bootstrap intervals. Supported through the same table adapter |

Some historical original campaign results are absent from this checkout. The
map above was cross-checked against their existing writers/analyzers, not by
running them or assuming identical schemas.

## Architecture and interpretation

`adapters.py` reads JSON objects/lists, JSONL nested observation records and CSV
campaign tables. It preserves artifact identity. `render.py` is the single
escaped HTML renderer; `__main__.py` handles provenance and safe output. Adapter
labels are integration-smoke, campaign-csv, and json-records: the audit did not
require six duplicated campaign adapters.

The dashboard prominently marks integration smokes as **not scientific
performance data**. Missing scientific/comparability flags remain unavailable;
absence is not permission to treat a run as scientific. Capture SUCCESS alone
is not overall experiment SUCCESS. Validation/integrity failures remain visible.
Counts use aggregate CSVs where present, otherwise per-campaign CSVs, and never
count both. Existing summary/CI/effect tables are formatted as recorded.

Native TCP timing is connection entry to successful native return. Current
`s_client` uses `init_client` and may include resolver/address selection/socket
work; other supported sources may use `BIO_do_connect`. TLS timing remains
`SSL_CB_HANDSHAKE_START` to `SSL_CB_HANDSHAKE_DONE`. Full native timing is
original connect entry to that same TLS completion, measured directly.

PCAP timing is independently SYN to TCP established, ClientHello to client
Finished, and SYN to client Finished. Conceptual timelines allow intermediate
gaps and never depict full timing as an arithmetic sum. Diagnostic comparisons
require values in the same source record or unique explicit client-random
association; equality is not expected. BIO bytes and observed TCP/IP/frame
bytes remain separate. Violated byte hierarchy produces a warning.

## Integrity, security and limitations

The report records generator version, generation timestamp, source directory,
artifact inventory and SHA-256. Existing PCAP expected hashes are compared
read-only with available PCAPs. Missing PCAP/keylog/validation is unavailable,
not invented failure. Keylog contents and private keys are never read.
All metadata, JSON, paths and errors are HTML-escaped. There are no script
blocks or untrusted HTML insertions; a restrictive content policy is embedded.

Large tables preview the first 100 rows (150 for evidence fields), and raw
JSON details preview the first 100 artifacts with root metadata prioritized; full
canonical source files remain necessary for exhaustive audit. Packet CSVs are
hashed/inventoried but not rendered as a new packet parser. No extractor or
campaign analysis is invoked. Duplicate JSON/JSONL representations are labelled
by source and are not pooled. Older native metrics existing only in logs remain
unavailable. The renderer cannot certify scientific validity from incomplete
historical metadata. It does not independently validate TLS/keylog association
or recompute Stage-1 semantics; it shows recorded validation and checks hashes.

```bash
python3 -m unittest campaigns.common.reporting.test_reporting
bash -n bin/artifacts/mt-report
```
