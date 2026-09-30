# Experimental MTC local log HTTP service

Operational access to the existing LocalLog and RFC 9162 primitives. This is
experimental, non-production software with no authentication or issuance
authorization. Entries are opaque bytes, not validated certificates. No CT API
compatibility, signing, gossip, TLS or certificate generation is provided.

All JSON state/proof responses explicitly include `unsigned: true`. `/checkpoint`
returns unsigned `tree_size` and `hash`, not an authenticated checkpoint.
Existing independently authenticated MCF1 snapshots remain the trust boundary.
Serving roots and proofs does not authenticate either root to a client.

## Docker (from repository root)

```sh
docker build -f docker/mtc_log/Dockerfile -t mtc-log:local .
docker volume create mtc-log-data
docker run --rm --name mtc-log -p 127.0.0.1:8080:8080 \
  -v mtc-log-data:/data mtc-log:local
```

The volume retains `state.json` and `log/NNNNNN.entry` across container restarts.
Reuse that volume to reopen the log. Do not remove it to restart the container.
Change the container port with `--port 8081` after the image name and adjust the
loopback port mapping accordingly. No OpenSSL or compiler is invoked/installed
by this Dockerfile; only the standard-library Python service runs.

## API examples

```sh
# Append an existing encoded entry unchanged. Response includes its zero-based index.
curl --fail -H 'Content-Type: application/octet-stream' \
  --data-binary @entry.bin http://127.0.0.1:8080/entries
curl --fail http://127.0.0.1:8080/checkpoint
curl --fail http://127.0.0.1:8080/entries/0 --output retrieved-entry.bin
# Requires at least 16 entries:
curl --fail 'http://127.0.0.1:8080/proof/inclusion/0?size=16'
curl --fail 'http://127.0.0.1:8080/proof/consistency?old=8&new=16'
```

Roots and proof hashes are lowercase hex. Inclusion replies contain `index`,
`tree_size`, `hash`, `proof`; consistency replies contain `old_size`, `new_size`,
`old_hash`, `new_hash`, `proof`. Proofs use a selected prefix of the current log.
POST requires Content-Length, accepts empty entries, and limits each entry to
1 MiB. Chunked request bodies are unsupported. Malformed/range requests return
400, unknown routes 404, unsupported methods 405, missing length 411 and oversized
entries 413. Inconsistent storage returns 500 without repair or traceback.

The server is synchronous. Each operation uses a locked, validated view; roots
are recomputed from disk. This is intended for small local experiments. Interrupted
appends may leave inconsistent storage which fails closed; there is no recovery
journal. Coordinated rewriting of entries and unsigned metadata requires an
independently retained authenticated snapshot to detect.
