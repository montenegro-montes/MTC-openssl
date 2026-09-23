# Network bandwidth campaign

Current X.509/MTC network experiment. This campaign was derived from the frozen
historical implementation but has no runtime dependency on `historical_campaigns`
and contains no Compact or RPK scenario.

Scenarios are X.509 ML-DSA-65, MTC landmark ML-DSA-65, and MTC standalone
ML-DSA-65. TLS 1.3, X25519, TLS_AES_256_GCM_SHA384, server-only authentication,
disabled tickets and no resumption remain fixed. Network impairment is the only
campaign variable.

Use `bin/network/mt-network`; it selects the validated N=16 fixtures, prepares a
new immutable output below `artifacts/results`, and prints or executes the
campaign command. Campaign execution is always explicit.
