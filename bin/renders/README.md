# Base HTML renderers

HTML report generators used by the active launchers:

- `prepare.py`: preparation and fixture reports.
- `protocol-validation.py`: protocol matrix, mutual-authentication and retry reports.
- `handshake-performance.py`: native and PCAP handshake measurements.
- `handshake-retry-matrix.py`: nine-profile Trust Anchor Retry aggregation.
- `chromium.py`: Chromium functional-validation and paired browser-measurement
  summaries. It detects the JSON schema, keeps TLS validation separate from
  performance statistics, and links the recorded evidence without changing it.

These scripts render existing results. Campaign execution remains in the
corresponding `bin/base/mt-*` launcher.

## Chromium reports

Render a completed functional-validation summary:

```sh
python3 bin/renders/chromium.py \
  artifacts/results/chromium-browser-validation-RUN/summary.json \
  --output artifacts/results/chromium-browser-validation-RUN/report.html
```

Render a completed browser-measurement summary with descriptive statistics,
paired differences, selected charts, and links to its CSV/JSON evidence:

```sh
python3 bin/renders/chromium.py \
  artifacts/results/chromium-browser-measurements-RUN/summary.json \
  --output artifacts/results/chromium-browser-measurements-RUN/report.html
```

The input is never modified. The renderer refuses to overwrite an existing
report unless `--replace` is supplied.

`browser-measurements run` invokes this renderer automatically after its final
`summary.json` and CSV files have been written. The resulting report is saved
as `report.html` in the same campaign result directory. The commands above are
still useful for rendering older result directories manually.
