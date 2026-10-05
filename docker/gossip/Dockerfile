FROM python:3.12-slim

WORKDIR /app

COPY src/mtc/checkpoint_gossip.py src/mtc/rp_updater.py \
     src/mtc/core.py src/mtc/landmarks.py src/mtc/snapshots.py \
     src/mtc/local_log.py src/mtc/prepare.py src/mtc/config_formats.py \
     src/mtc/crypto_profiles.py src/mtc/trust_anchor_ids.py \
     src/mtc/rp_state.py src/mtc/rp_policy.py src/mtc/trusted_subtrees.py ./

ENV PYTHONDONTWRITEBYTECODE=1

ENTRYPOINT ["python3", "-B", "/app/checkpoint_gossip.py"]
