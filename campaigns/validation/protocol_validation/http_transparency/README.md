# HTTP transparency subvalidation

This optional validation covers the chain from an authenticated MCP2 snapshot
and HTTP subtree proofs through the RP updater and MTS1 publication. The
`http-positive` case then passes that MTS1 file to Chromium and requires a TLS
1.3 `VerifyMTC` success.

The implementation and Chromium harness remain in
`campaigns/browser_client/chromium_mtc/http_log_integration.py`. This directory
only supplies protocol-validation orchestration and the two fail-closed
negative cases; it imports the existing harness, updater, log service, and
snapshot checker instead of copying them. Stages 05-120 are unchanged and
Chromium is not a dependency of ordinary protocol validation.

Validated cases:

- `http-positive`: authenticated snapshot, valid subtree proofs, published
  MTS1, Chromium TLS 1.3 PASS.
- `invalid-subtree-proof`: corrupt the first-landmark subtree proof; Section
  7.4 fallback publishes a valid MTS1 containing zero trusted subtrees, so the
  corrupted subtree is not incorporated.
- `invalid-snapshot`: serve a corrupted copy and require native checker
  rejection with no trusted RP state.

The real positive E2E validation was: local persistent log -> HTTP snapshot and
subtree proofs -> authenticated checkpoint -> Section 7.4 RP validation ->
published MTS1 -> Chromium `--mtc-plants07-trusted-subtrees` -> TLS 1.3 MTC
PASS. Managed runs use an OS-selected loopback port by default; an explicit
`--log-port` remains supported and the selected base URL is recorded in HTTP
evidence.

Inspect without executing:

```sh
bin/base/mt-protocol-validation http-transparency plan
bin/base/mt-protocol-validation http-transparency show http-positive [OPTIONS]
```

Build the unversioned checker under `.mt-state/mtc/check_snapshot`:

```sh
bin/base/mt-protocol-validation http-transparency build-checker \
  --openssl-prefix "$(brew --prefix openssl@3)"
```

Run one case explicitly with `run CASE` and the options shown by `show`. The
positive accepts the existing Chromium harness CLI. Both negatives require
`--snapshot` and `--trusted-authority`; `invalid-subtree-proof` additionally
requires `--landmarks --log-number`, while `invalid-snapshot` requires managed
`--log-data`. A fresh output directory is required for every run.

Positive evidence remains under
`artifacts/results/chromium-http-log-mtc-*`. Negative evidence is written under
`artifacts/results/http-transparency-CASE-*` and includes `result.json`, RP
state, input hashes, the expected rejection or fallback outcome, and managed
log-service logs when used.

Chromium does **not** query the transparency log. It consumes the MTS1 file
created by the RP updater. Authenticated 8-to-16 checkpoint evolution through
`/proof/consistency` is intentionally deferred.

This is experimental local interoperability validation. It is not a public,
operational transparency-log service and does not establish broader deployment
or protocol-compliance claims.
