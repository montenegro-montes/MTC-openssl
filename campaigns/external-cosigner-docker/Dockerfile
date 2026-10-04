FROM python:3.14-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/openssl/bin \
    && ln -s /usr/bin/openssl /opt/openssl/bin/openssl

WORKDIR /app
COPY src/mtc/config_formats.py src/mtc/core.py src/mtc/cosigner.py src/mtc/cosigner_http_service.py src/mtc/crypto_profiles.py src/mtc/landmarks.py src/mtc/local_log.py src/mtc/prepare.py src/mtc/snapshots.py src/mtc/trust_anchor_ids.py src/mtc/trusted_subtrees.py ./
COPY campaigns/external-cosigner-docker/provision.sh ./

EXPOSE 8443

CMD ["python3", "cosigner_http_service.py"]
