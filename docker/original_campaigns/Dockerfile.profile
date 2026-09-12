FROM mt-tls-compact:local
COPY src/profiling/profile.c src/profiling/profile.h src/profiling/metrics.c src/profiling/patch.py src/profiling/openssl.sh /opt/profiling/
RUN cp -a /opt/src/openssl-compact /opt/src/openssl-profile && \
    python3 /opt/profiling/patch.py /opt/src/openssl-profile && \
    cd /opt/src/openssl-profile && ./Configure --prefix=/opt/openssl-profile --libdir=lib shared && \
    make -j2 && make install_sw && cp PROFILE_SHA256 /opt/openssl-profile/ && \
    chmod +x /opt/profiling/openssl.sh && /opt/profiling/openssl.sh version -a
COPY src/profiling /opt/profiling
RUN chmod +x /opt/profiling/openssl.sh
WORKDIR /work
