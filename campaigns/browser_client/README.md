# Browser clients

Browser-oriented MTC implementations and interoperability experiments.

- `chromium_mtc/`: Chromium Plants-06 integration, reproducibility metadata,
  patches, fixtures, and browser interoperability workflow.
- `boringssl_mtc_client/`: earlier BoringSSL-based client, wire probes,
  verifier experiments, and Trust Anchor ID validation utilities.

The Chromium workflow driver is:

    bin/browser_client/mt-chromium-mtc
