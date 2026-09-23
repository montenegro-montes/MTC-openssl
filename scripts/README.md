# Internal laboratory scripts

Use the commands in [`bin/historical_campaigns/`](../bin/historical_campaigns/) for routine operation. See the
[architecture guide](../docs/architecture.md) for the complete repository map.

| Directory | Files | Execution context |
|---|---|---|
| `fixtures/` | `generate-certs.sh`, `generate-merkle.sh` | Fixture generation, normally inside Docker with `/work` and `/opt` dependencies |
| `runtime/` | `client.sh`, `server.sh` | Initial laboratory TLS processes inside Docker |
| `runtime/` | `benchmark-initial.py` | Initial four-scenario client-process benchmark inside Docker |
| `lib/` | `scenario.sh` | Sourced configuration for client/server; not an entrypoint |

The base Dockerfile installs these files under `/opt/lab/`, preserving their
runtime names. Study-specific runners and analyses belong in `campaigns/`.

`maintenance/reset_lab.py` implements the destructive `mt-prepare reset-all`
action and remains available to the historical manager. It requires the literal
confirmation `RESET ALL`, uses Docker Compose
labels to select laboratory resources and deletes only the fixed local paths
`artifacts/` and `.mt-state/`. See [campaign management](../campaigns/README.md).
