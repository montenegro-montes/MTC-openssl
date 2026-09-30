# Performance launchers

`mt-handshake-performance` measures the active X.509 and experimental MTC
handshakes. It provides native timing, packet-capture measurements, mutual
authentication cases and the nine-profile Trust Anchor Retry matrix. Simple and
mutual MTC measurements each include landmark and standalone credentials.
For mutual authentication, the client and server use the same one of the nine
signature profiles in each scenario. Dedicated client fixtures use the `MUTUAL_CLIENT_ROOT` configured for the
performance campaign. Fixture roots are supplied explicitly or derived by the
fixture-preparation workflow; the runner does not depend on a historical
fixture directory.
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

Historical artifacts may contain directory labels that do not match the
key-establishment group recorded by their configuration and OpenSSL logs.
Directory names must not be treated as protocol evidence. Existing artifacts
must not be rewritten; verify their recorded configuration before reuse.
