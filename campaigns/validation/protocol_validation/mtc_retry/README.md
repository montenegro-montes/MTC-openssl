# MTC Trust Anchor Retry validation

This independent native runner validates direct authentication (`happy`) and
one bounded Trust Anchor ID retry (`retry`): an expected
`trust_anchor_mismatch` failure followed by a new authenticated connection.
It checks attempt counts, distinct connection IDs and absence of session reuse.
The runner does not define a separate terminal-error scenario.

`run.py` provides preflight and full modes, native timing observations and paired
happy/retry analysis. It remains separate from the parent directory's
single-connection PCAP/transcript workflow. Run manually from the repository
root using `campaigns/validation/protocol_validation/mtc_retry/run.py` and the
existing CLI arguments; this reorganization does not change fixture or result
locations. The native peer and existing fixtures remain prerequisites.

`rebuild_summary.py` imports the adjacent `run.py` to summarize existing
`observations.jsonl` data. Its entrypoint is now
`campaigns/validation/protocol_validation/mtc_retry/rebuild_summary.py`.

`run.py.before-paired-analysis` is a historical source backup, preserved byte
for byte. It retains its original path assumptions and is not a supported
entrypoint at this location. Implementation code remains under `src/mtc/`;
historical artifacts are not relocated or regenerated.
