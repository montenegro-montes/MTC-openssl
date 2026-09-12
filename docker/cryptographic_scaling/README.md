# Cryptographic scaling containers

Compose definitions used only by cryptographic-profile and representation-size
studies live here. They reuse the pinned laboratory images but remain separate
from the Compose projects for validated baseline and network campaigns.

| File | Purpose |
|---|---|
| `compose.cert-chain-scaling.yaml` | Ideal-network X.509 chain-depth measurements |

Run Compose through the corresponding campaign runner so all required fixture,
result, image, commit, and profile variables are set consistently.
