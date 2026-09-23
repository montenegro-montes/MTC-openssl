# Mutual-authentication crossover

This is the canonical mutual-authentication crossover campaign. The earlier
single-profile implementation has been removed; the former v2 implementation
is now the main implementation.

The campaign measures all nine cryptographic profiles. For each profile it
records two X.509 mutual-authentication baselines (direct/direct and CA/CA) and
MTC mutual authentication at `N=1, 4, 16, 64, 256, 1024`. The final comparison
joins the mutual CA/CA crossover with the simple-authentication `D=2` crossover.
Direct/direct remains in the evidence as a separate baseline because it has no
exact counterpart in the simple `D=2` comparison.

Use `bin/cryptographic_scaling/mt-cert-scaling mutual-crossover`. The workflow
is opt-in and performs no generation, Docker build, TLS connection, or
measurement unless invoked with its internal `--execute` flag by the launcher.
It writes raw results, summarized crossover tables, the simple-versus-mutual
comparison, and an offline HTML report to separate new artifact directories.

The optional exact-boundary workflow is split into three further stages:

- `122.mutual-crossover-exact` models the client and server landmark
  certificates independently and sums their TLS Certificate-message sizes.
- `124.mutual-boundary-audit` generates and executes only `N-1` and `N` for
  exact boundaries within the native `N<=1024` limit.
- `125.mutual-crossover-html` combines the sampled intervals, exact boundaries,
  and empirical PASS/FAIL results in one English report.

The empirical condition is `MTC_total(N-1) < X509_total` and
`MTC_total(N) >= X509_total`, where each total includes both authentication
directions. These stages always use new output directories and do not modify the
sampled campaign fixtures.
