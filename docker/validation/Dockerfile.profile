# Separate instrumentation image; the base MTC tag is never overwritten.
ARG MTC_BASE_IMAGE=mt-tls-mtc:local
FROM ${MTC_BASE_IMAGE}
COPY src/profiling/profile.c src/profiling/profile.h src/profiling/metrics.c src/profiling/patch_profile_metrics.py /opt/profile-metrics/
RUN python3 /opt/profile-metrics/patch_profile_metrics.py /opt/src/openssl-mtc \
 && cd /opt/src/openssl-mtc \
 && perl configdata.pm --reconfigure \
 && make -j2 \
 && make install_sw \
 && cp apps/openssl /opt/openssl-mtc/bin/openssl \
 && cp -a /opt/openssl/lib/. /opt/openssl-mtc/lib/ \
 && cp PROFILE_SHA256 /opt/openssl-mtc/ \
 && /opt/mtc/openssl.sh s_server -help 2>&1 | grep -q lab_metrics
RUN mkdir -p /opt/measurement && ln -s /opt/mtc/openssl.sh /opt/measurement/openssl.sh
WORKDIR /work
