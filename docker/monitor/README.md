# MTC Continuous Checkpoint Monitor

Experimental laboratory monitor for one authenticated view of an MTC issuance
log:

```text
MTC Log
  -> authenticated snapshot
  -> Checkpoint Monitor
  -> persistent accepted checkpoint
```

The monitor fetches `/snapshot`, authenticates it with the mounted trusted
authority and the existing native `check_snapshot` implementation, and requests
`/proof/consistency` only when the authenticated tree grows. It records only the
last accepted checkpoint under `/var/lib/mtc-monitor`.

The continuous process also exposes `GET /checkpoint` on
`0.0.0.0:8081` by default. It returns the validated, last accepted checkpoint
as JSON, or HTTP 404 before any checkpoint has been accepted. The endpoint is
read-only and is intended for exchanging monitor views over the deployment
network; `checkpoint.json` remains private persistent monitor state.

It detects rollback, a different root at the same tree size, an invalid
consistency proof, an unauthenticatable snapshot, corrupt local state, and Log
unavailability. A single monitor does **not** demonstrate the global absence of
split views, implement gossip, prove that isolated clients see the same view, or
prove global service availability.

The trusted authority is public verification configuration, not a signing key.
Set `MTC_MONITOR_TRUSTED_AUTHORITY` to an existing MCA2 `authority.bin` file; it
is mounted read-only. No External Cosigner material is used.

From `docker/`:

```sh
docker compose build monitor
MTC_MONITOR_TRUSTED_AUTHORITY=/absolute/path/to/authority.bin \
  docker compose up -d monitor
docker compose logs -f monitor
docker compose stop monitor
docker compose rm -f monitor
MTC_MONITOR_TRUSTED_AUTHORITY=/absolute/path/to/authority.bin \
  docker compose up -d monitor
```

Stopping and recreating the container preserves the independent
`mtc-monitor-state` volume. Do not use `docker compose down --volumes` when that
history must be retained.

The Compose default Log URL is `http://mtc-log:8080`. To use a remote Log:

```sh
MTC_MONITOR_LOG_URL=http://SERVER_A:8080 \
MTC_MONITOR_TRUSTED_AUTHORITY=/absolute/path/to/authority.bin \
  docker compose up -d monitor
```
