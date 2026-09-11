# Experiment artifact publication policy

The complete local experiment record is generated below `artifacts/`, which is
ignored by Git. Before resetting that directory for a clean reconstruction,
create a verified publication snapshot under `results/` with:

```sh
python3 scripts/archive-results.py --clean-artifacts
```

Only deliberately selected publication outputs belong in Git, inside a
checksummed `results/campaign-snapshot-*` directory:

- generated reports and documented final tables;
- aggregated or paired-comparison CSV files;
- publication figures;
- experiment metadata and completion status;
- validation status and reproducibility hashes.

Do not publish private keys, generated credential fixtures, per-handshake logs,
raw `samples.csv`, detailed `components.csv`, per-connection server metrics,
Docker logs, environment dumps, temporary files, failed-run directories, or
duplicated source snapshots. Raw observations can be released separately only
after an explicit review of validity, privacy, size, and provenance.

Verify the snapshot and confirm that no `artifacts/` paths remain tracked before
committing or pushing selected results:

```sh
python3 scripts/check-published-artifacts.py
python3 scripts/archive-results.py --verify results/campaign-snapshot-<timestamp>-<hash>
```

`.gitignore` does not affect files already tracked. Use `git rm --cached` to
stop tracking an artifact while leaving its local file intact. Rewriting Git
history is a separate operation and is not required by this policy.
