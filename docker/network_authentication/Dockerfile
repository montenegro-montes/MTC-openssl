# Build manually, from an existing immutable mutual-metrics image.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      iproute2 iputils-ping iperf3 procps \
 && rm -rf /var/lib/apt/lists/*
LABEL org.mt.experiment="network-authentication-v1"
WORKDIR /work
