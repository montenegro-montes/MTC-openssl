# Browser clients

Browser-oriented MTC implementations and interoperability experiments.

- `chromium_mtc/`: Chromium Plants-06 integration, reproducibility metadata,
  patches, fixtures, and browser interoperability workflow.
- `boringssl_mtc_client/`: earlier BoringSSL-based client, wire probes,
  verifier experiments, and Trust Anchor ID validation utilities.

The Chromium workflow drivers are:

    bin/browser_client/mt-chromium-setup
    bin/browser_client/mt-chromium-tests

Use `mt-chromium-setup menu` for installation and credential preparation, or
`mt-chromium-tests menu` for validation and experiments.
