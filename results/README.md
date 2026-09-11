# Published experiment snapshots

Each `campaign-snapshot-*` directory contains the compact, publication-oriented
outputs from one complete execution battery. Its name combines a UTC timestamp
and the first 12 characters of a SHA-256 digest over every archived file.

Snapshots retain reports, aggregate tables, comparisons, decisions, validation
status and reproducibility metadata. They deliberately exclude figures, raw
per-handshake observations, logs, packet captures, environment dumps, generated
credentials, private keys and cache files.

Create and verify a snapshot from the definitive campaign directories:

```sh
python3 scripts/archive-results.py
python3 scripts/archive-results.py --verify results/campaign-snapshot-<timestamp>-<hash>
```

For a new battery, pass its definitive directories explicitly. The campaign
manager does this automatically in its final `110.archive-results` step:

```sh
python3 scripts/archive-results.py \
  --campaign scaling=artifacts/results/scaling-<timestamp> \
  --campaign network-latency=artifacts/results/network-latency-<timestamp>
```

To create the verified snapshot and then reset generated artifacts for a clean
reconstruction run:

```sh
python3 scripts/archive-results.py --clean-artifacts
```

An already created snapshot can be used for the guarded cleanup without
creating a duplicate:

```sh
python3 scripts/archive-results.py \
  --verify results/campaign-snapshot-<timestamp>-<hash> \
  --clean-artifacts
```

The cleanup flag removes the complete local `artifacts/` tree only after every
selected file has been copied and its size and SHA-256 digest verified. Update
the definitive campaign registry in `scripts/archive-results.py` after a new
complete battery replaces the current one.
