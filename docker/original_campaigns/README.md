# Original campaign Docker infrastructure

This category contains the images and Compose definitions used by the original
validated campaign group. File contents and Compose project names retain their
original roles; their repository paths now mirror
`campaigns/original_campaigns/`.

It includes the base laboratory, Compact, profiling, MTC-experimental,
measurement, scaling, network-condition, and packet-capture definitions.
Commands should be run from the repository root using paths such as:

```sh
docker compose -f docker/original_campaigns/compose.yaml config
docker compose -f docker/original_campaigns/compose.scaling.yaml config
```

Use `scripts/manage-containers.sh` and `scripts/manage-campaigns.sh` for normal
operation because both managers now resolve these grouped paths.
