# Current network campaigns

- `latency`: deterministic RTT sensitivity.
- `bandwidth`: per-direction bandwidth caps at controlled RTT values.
- `loss`: controlled packet-loss sensitivity.
- `combined`: representative RTT, bandwidth and loss profiles.

Each campaign can run independently in `single` or `mutual` authentication
mode. Both modes cover the nine cryptographic profiles and compare X.509 with
MTC landmark and standalone authentication at N=16. Mutual mode uses symmetric
X.509/X.509 and MTC/MTC credentials. Results remain separated by campaign, authentication mode,
profile, network condition and scenario.
