FROM python:3.12-slim

WORKDIR /app

COPY src/mtc/rp_server.py \
     src/mtc/rp_state.py \
     src/mtc/rp_updater.py \
     src/mtc/core.py \
     src/mtc/landmarks.py \
     src/mtc/snapshots.py \
     src/mtc/local_log.py \
     src/mtc/prepare.py \
     src/mtc/config_formats.py \
     src/mtc/crypto_profiles.py \
     src/mtc/trust_anchor_ids.py \
     src/mtc/trusted_subtrees.py ./

ENV PYTHONDONTWRITEBYTECODE=1

VOLUME ["/var/lib/mtc-rp"]

ENTRYPOINT ["python3", "-B", "/app/rp_server.py"]

CMD ["--state", "/var/lib/mtc-rp", "--host", "0.0.0.0", "--port", "8082"]
