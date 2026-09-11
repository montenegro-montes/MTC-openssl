# Experiment artifact publication policy

The complete local experiment record remains below `artifacts/`, which is
ignored by Git. Local raw evidence is preserved for audit and must not be moved,
renamed, or deleted merely to prepare a repository commit.

Only deliberately selected publication outputs may be force-added to Git:

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

Run this check before committing or pushing selected results:

```sh
python3 scripts/check-published-artifacts.py
```

`.gitignore` does not affect files already tracked. Use `git rm --cached` to
stop tracking an artifact while leaving its local file intact. Rewriting Git
history is a separate operation and is not required by this policy.
