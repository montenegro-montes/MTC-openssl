FROM python:3.12-slim AS checker

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/mtc/check_snapshot.c src/mtc/mtc.c src/mtc/mtc.h ./
RUN cc -Wall -Wextra -Werror check_snapshot.c -lcrypto -o check_snapshot

FROM python:3.12-slim

WORKDIR /app
COPY --from=checker /build/check_snapshot /usr/local/bin/check_snapshot
COPY src/mtc/checkpoint_monitor.py src/mtc/rp_updater.py \
     src/mtc/rp_policy.py \
     src/mtc/core.py src/mtc/landmarks.py src/mtc/snapshots.py \
     src/mtc/local_log.py src/mtc/prepare.py src/mtc/config_formats.py \
     src/mtc/crypto_profiles.py src/mtc/trust_anchor_ids.py \
     src/mtc/rp_state.py src/mtc/trusted_subtrees.py ./
ENV PYTHONDONTWRITEBYTECODE=1
VOLUME ["/var/lib/mtc-monitor"]
ENTRYPOINT ["python3", "-B", "/app/checkpoint_monitor.py"]
