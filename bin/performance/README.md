# Performance launchers

`mt-handshake-performance` measures the active X.509 and experimental MTC
handshakes. It provides native timing, packet-capture measurements, mutual
authentication cases and the nine-profile Trust Anchor Retry matrix. Simple and
mutual MTC measurements each include landmark and standalone credentials.
For mutual authentication, the client and server use the same one of the nine
signature profiles in each scenario. Dedicated client fixtures are prepared
automatically under `artifacts/validation/handshake-performance-mutual-v2/`.
The handshake report presents absolute results for every profile and case. Its
Native and PCAP tables include sample count, mean, sample standard deviation,
median and a 95% Student t confidence interval for the mean; it does not use a
baseline subtraction.

Run it from the repository root:

```bash
bin/performance/mt-handshake-performance
```

Creating a configuration asks for one key-establishment option:

1. `X25519` (OpenSSL group `X25519`)
2. `X25519+ML-KEM512` (OpenSSL group `x25519_mlkem512`)
3. `ML-KEM-512` (OpenSSL group `mlkem512`)

The selected value is stored as `KEM` in the configuration. Default result and
report directory names include its stable slug, and both JSON and HTML reports
record the display label and exact OpenSSL TLS group.

`init` creates the default configuration (or an explicitly named file). `new`
creates an independent timestamped configuration by default, so several KEM
configurations can coexist under `.mt-state/`.

Native and PCAP populations can be executed independently for simple or mutual
authentication. `run-single` and `run-mutual` execute Native followed by PCAP
only for their three authentication cases. `run-native-pcap` retains the full
six-case execution.

HTML renderers are centralized under `bin/renders/`.

### Performance KEM selection versus fixture provenance

The KEM chosen in the performance configuration controls the TLS group. Loading
`.mt-state/cert-scaling/paths.env` must not replace it with the KEM recorded for
fixture preparation. The runner now scopes those KEM assignments locally when
loading fixture paths. Newly written PCAP CSV rows include `key_establishment`
and `openssl_group`, matching native rows. These columns record configuration;
they are not an independent decoding of ServerHello key_share.

Historical run `handshake-performance-x25519-mlkem512-20260923T170822Z-800`
has an inconsistent directory label: its summary/configured-group logs report
X25519, and inspected OpenSSL client logs report `Server Temp Key: X25519`.
Do not use it as X25519+ML-KEM512 evidence or rewrite its artifacts. Old PCAP
CSVs lack the new columns. Existing performance configurations may already have
been rewritten to `KEM=x25519`; correcting the runner does not restore their
original selection. Review the intended KEM before any new run.
The correction was inspected only; no tests or measurements were executed.
