# Base HTML renderers

HTML report generators used by the active launchers:

- `prepare.py`: preparation and fixture reports.
- `protocol-validation.py`: protocol matrix, mutual-authentication and retry reports.
- `handshake-performance.py`: native and PCAP handshake measurements.
- `handshake-retry-matrix.py`: nine-profile Trust Anchor Retry aggregation.

These scripts render existing results. Campaign execution remains in the
corresponding `bin/base/mt-*` launcher.
