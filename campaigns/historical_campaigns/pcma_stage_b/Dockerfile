# Manual build only. Reuses the validated OpenSSL libraries, no OpenSSL rebuild.
FROM mt-tls-network:latency
COPY src/compact /opt/pcma-repo/src/compact
COPY src/integration /opt/pcma-repo/src/integration
COPY codigoOriginal/C/crypto /opt/pcma-repo/codigoOriginal/C/crypto
COPY campaigns/historical_campaigns/pcma /opt/pcma-repo/campaigns/historical_campaigns/pcma
COPY campaigns/historical_campaigns/pcma_stage_a2 /opt/pcma-repo/campaigns/historical_campaigns/pcma_stage_a2
COPY campaigns/historical_campaigns/pcma_stage_b /opt/pcma-repo/campaigns/historical_campaigns/pcma_stage_b
COPY campaigns/historical_campaigns/combined_network_campaign /opt/pcma-repo/campaigns/historical_campaigns/combined_network_campaign
RUN /opt/pcma-repo/campaigns/historical_campaigns/pcma_stage_b/build.sh /opt/openssl /opt/pcma-bin
RUN apt-get update && apt-get install -y --no-install-recommends tcpdump procps && rm -rf /var/lib/apt/lists/*
WORKDIR /work
