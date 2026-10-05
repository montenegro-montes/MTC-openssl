# MTC checkpoint gossip

This component provides a small laboratory mechanism for comparing authenticated
checkpoint views obtained by independent MTC monitors.

It is intentionally separate from the continuous checkpoint monitor. The monitor
tracks the authenticated history observed by one observer; checkpoint gossip
compares views available to different observers.

## Comparison semantics

For checkpoints belonging to the same issuance log:

- Same tree size and same root hash: `CONSISTENT / PASS`.
- Same tree size and different root hashes: `SPLIT_VIEW / ALERT`.
- Different tree sizes: the older checkpoint is checked against the newer one
  using the Log consistency endpoint and the existing RFC 9162 consistency
  verification.
- Valid consistency proof: `CONSISTENT / PASS`.
- Invalid consistency proof: `INCONSISTENT / ALERT`.
- Unavailable Log while a consistency proof is required:
  `UNAVAILABLE / ERROR`.

Checkpoints belonging to different issuance logs are reported as
`DIFFERENT_LOG / INFO` and are not treated as split-view evidence.

A direct split view at the same tree size is detected without consulting the
Log: two authenticated checkpoints for the same issuance log and tree size with
different root hashes are contradictory evidence by themselves.

## CLI

Compare two monitor checkpoints over HTTP:

    PYTHONPATH=src/mtc python3 src/mtc/checkpoint_gossip.py \
      --first-url http://monitor-a:8081/checkpoint \
      --second-url http://monitor-b:8081/checkpoint \
      --log-url http://127.0.0.1:18080/

`--first` and `--second` remain available for offline file-based checks.

The Log URL is only required to establish consistency between checkpoints with
different tree sizes.

The command emits a JSON result. `PASS` and `INFO` return exit status 0;
`ALERT` and `ERROR` return a non-zero exit status.

## Laboratory validation

The implementation has been validated with two real views of the same persistent
MTC Log:

- N=8 root:
  `4e666e82828ddbddcd01bddafc2c458239da35438830cdb76bb5f54352c7449b`
- N=16 root:
  `5144e54dff7aad2884acc50174a420a69914af39221d528b4d686e26dd20b675`

The N=8 to N=16 comparison used the real Log consistency endpoint and the
existing RFC 9162 consistency verifier and produced `CONSISTENT / PASS`.

A same-size N=16 comparison with different root hashes produced
`SPLIT_VIEW / ALERT` without Log access.

## Scope

This is laboratory checkpoint gossip, not a public distributed gossip network.

It detects inconsistent or contradictory views when those views are made
available for comparison. It does not provide peer discovery, broadcast,
consensus, global auditing, or a guarantee that all hidden split views will be
discovered.
