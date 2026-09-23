# Paper-1 infrastructure review — 2026-09-12

## Files modified

Under `campaigns/scaling/cert_chain_scaling/`:
`inspect_environment.py`, `run.py`, `measure.py`, `analyze.py`, `plots.py`,
`size_analysis.py`, `generate_fixtures.py`, `fixture_builder.py`, `README.md`.

MTC loading: `src/mtc/tls.c`, `src/mtc/patch.py` and
`campaigns/historical_campaigns/controlled_n16_campaign/tests.sh`.

## Files created

Under the Paper-1 package: `capabilities.py`, `result_state.py`,
`test_support_resume.py`. Also `src/mtc/test_security.c`,
`docs/mtc-security-loading.md` and this report.

Local evidence (ignored by Git):
`artifacts/review/paper1-support-20260912/environment.json`,
`algorithm_support.csv`, `existing-cells.json` and `implementation-sha256.json`.

## TLS capability detection

Inspected image: `sha256:8f171c8dec57032a93427c52005f9df2852d7c161ea2398ad48bf48707487ddb`.
The actual image reports OpenSSL 3.4.7, liboqs 0.16.0 and oqs-provider
0.12.0-dev (provider commit `c174ed7050a32e720d40e59d79564b3646faf56a`).
This is the user's replacement stack, not the original 3.5.8 stack described
in the initial request. No Docker version selection was changed by this review.

All nine configured profiles advertise cryptographic and TLS signature support
in this image. That makes 36 eligible depth/profile cells per campaign index,
with zero unsupported cells in this image. Capability advertisement is not
handshake validation. The same parser correctly marks standardized SLH-DSA as
unsupported for a TLS list containing only legacy SPHINCS+ names.

The environment evidence records complete outputs and actual source/image
identities. X.509 sign/verify columns are unknown until same-image, hash-valid
fixture-builder evidence is supplied; they are not inferred from TLS listings.
Future fixture manifests include the image ID and generator/config hashes.

## Completed existing cells

The user confirmed resetting/deleting the previous campaign during this task.
The final filesystem inspection found no `observations.csv` files and no
Paper-1 chain fixture manifests. There are zero surviving completed TLS cells
to validate. This does not establish how many successful historical cells
existed before deletion.

## Missing eligible cells

The original campaign manifest is unavailable. Its campaign count, missing
cells and invalid/incomplete cells cannot be reconstructed accurately.
For a fresh full design on the currently inspected stack, all 36 cells per
campaign index require fixtures and future manual measurements.

## SLH-DSA static status

Retained in all nine-profile key/SPKI/certificate/signature and D=2..5 chain
analyses and standalone validation. MTC crossover retains its existing
P-256/ML-DSA-65 implementation limits. No SPHINCS+ substitution was introduced.
No chain fixtures were regenerated or old measurements rewritten.

## SLH-DSA TLS status

Detected dynamically. The current replacement image advertises the three
configured `slhdsasha2...s` schemes. They are eligible, not declared measured.
An image without these schemes records `SKIPPED_UNSUPPORTED_TLS`, not a
performance failure, timeout or zero-valued observation.

## Resume status

Implemented with immutable completion checks, filters, image/fixture/config
mismatch rejection, separate retry directories and per-attempt diagnostics and
provenance. The old deleted run cannot be resumed. The CLI refuses to fabricate
missing manifests. Resume dry-run was tested on synthetic completed cells
with Docker absent from PATH and all result bytes preserved.

## Validation status

18 Python unit tests passed (15 support/resume, one relative-path validator,
two static tests), along with Python/shell syntax and seven CLI help checks.
Four native offline MTC certificate-loading cases passed (classic/PQ ×
standalone/landmark) at security level 2, including negative policy assertions.
The MTC application patch was applied successfully to temporary copies of the
installed OpenSSL sources, confirming registration before certificate loading.
The agent did not rebuild images or execute TLS handshakes or measurement
campaigns. Subsequently, the user manually rebuilt and ran step
`07.measurement-image`, reporting:

```text
MTC TLS including malformed and signed invalid credentials: 70 PASS
ALL REGRESSION AND NEGATIVE TESTS PASS
COMPLETED 07.measurement-image
```

This is user-reported regression validation, not a Paper-1 performance result.

## Manual regression command (now completed)

The user has completed step 07 successfully. The command below is retained
as the reproduction command for that gate; it is not a pending action.
A valid old-run `--resume` command cannot be provided after the run was deleted.

```sh
bin/containers/mt-containers build mtc && bin/historical_campaigns/mt-campaigns retry 07.measurement-image
```
