# Exploratory MTC scaling runner

This is the original host-side exploratory runner formerly at
`mtc/run_scaling.py`. It is distinct from the controlled scaling campaign and
the certificate-chain/proof-size study.

Prepare fixtures manually with `/opt/mtc/prepare_scaling.py` in the MTC image,
then run from the repository root:

```sh
python3 campaigns/original_campaigns/mtc_exploratory_scaling/run.py --fixtures /work/mtc/YOUR_FIXTURE_DIRECTORY
```

This command starts Docker services and performs TLS measurements. Outputs go
to a new `artifacts/results/mtc-scaling-*` directory. See the runner's arguments
for sizes and repetitions. The fixture builder remains in `src/mtc/` because
other scaling workflows also use it.
