FROM debian:bookworm-slim
#ARG OPENSSL_VERSION=3.5.8
#ARG LIBOQS_VERSION=0.14.0
#ARG OQS_PROVIDER_VERSION=0.10.0
ARG OPENSSL_VERSION=3.4.7
ARG LIBOQS_VERSION=0.15.0
ARG OQS_PROVIDER_VERSION=0.11.0
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake ninja-build git ca-certificates perl python3 pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/src
RUN git clone --depth 1 --branch openssl-${OPENSSL_VERSION} https://github.com/openssl/openssl.git && \
    cd openssl && ./Configure --prefix=/opt/openssl --libdir=lib shared && \
    make -j2 && make install_sw && git rev-parse HEAD > /opt/openssl/SOURCE_COMMIT
ENV PATH="/opt/openssl/bin:${PATH}"
ENV LD_LIBRARY_PATH=/opt/openssl/lib:/opt/oqs/lib
RUN git clone --depth 1 --branch ${LIBOQS_VERSION} https://github.com/open-quantum-safe/liboqs.git && \
    cmake -S liboqs -B liboqs/build -GNinja -DCMAKE_INSTALL_PREFIX=/opt/oqs -DCMAKE_INSTALL_LIBDIR=lib -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_DIST_BUILD=ON -DOPENSSL_ROOT_DIR=/opt/openssl && \
    cmake --build liboqs/build -j2 && cmake --install liboqs/build && git -C liboqs rev-parse HEAD > /opt/oqs/SOURCE_COMMIT
RUN git clone --depth 1 --branch ${OQS_PROVIDER_VERSION} https://github.com/open-quantum-safe/oqs-provider.git && \
    cmake -S oqs-provider -B oqs-provider/build -GNinja -DOPENSSL_ROOT_DIR=/opt/openssl -Dliboqs_DIR=/opt/oqs/lib/cmake/liboqs -DCMAKE_BUILD_TYPE=Release && \
    cmake --build oqs-provider/build -j2 && cmake --install oqs-provider/build && git -C oqs-provider rev-parse HEAD > /opt/oqs/PROVIDER_COMMIT
COPY docker/original_campaigns/openssl.cnf /opt/openssl/ssl/openssl.cnf
ENV OPENSSL_CONF=/opt/openssl/ssl/openssl.cnf
ENV OPENSSL_MODULES=/opt/openssl/lib/ossl-modules
COPY codigoOriginal/C/crypto /opt/mt/crypto
COPY codigoOriginal/C/*tests.c /opt/mt/
RUN mkdir /opt/mt/bin && for test in merkle_tests mtc_tests merkle_mtc_tests; do \
    cc -Wall -Wextra -I/opt/openssl/include /opt/mt/$test.c /opt/mt/crypto/merkle.c /opt/mt/crypto/mtc.c -L/opt/openssl/lib -lcrypto -o /opt/mt/bin/$test; done
COPY src/integration /opt/mt/integration
RUN cc -Wall -Wextra -I/opt/openssl/include -I/opt/mt/crypto -I/opt/mt/integration \
    /opt/mt/integration/mt_bundle.c /opt/mt/integration/mt_wire.c /opt/mt/crypto/merkle.c /opt/mt/crypto/mtc.c \
    -L/opt/openssl/lib -lcrypto -o /opt/mt/bin/mt_bundle
RUN python3 /opt/mt/integration/patch_openssl.py /opt/src/openssl && \
    cd /opt/src/openssl && perl configdata.pm --reconfigure && make -j2 apps/openssl && \
    mkdir -p /opt/openssl-mt/bin && cp apps/openssl /opt/openssl-mt/bin/openssl && \
    cp MERKLE_PATCH_SHA256 /opt/openssl-mt/ && \
    /opt/openssl-mt/bin/openssl s_client -help 2>&1 | grep -q merkle_root
COPY tests /opt/mt/tests
RUN cc -Wall -Wextra -Werror -I/opt/openssl/include /opt/mt/tests/extension_server.c \
    -L/opt/openssl/lib -lssl -lcrypto -o /opt/mt/bin/mt_test_server && \
    cc -Wall -Wextra -g -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I/opt/openssl/include -I/opt/mt/crypto -I/opt/mt/integration \
    /opt/mt/tests/test_wire.c /opt/mt/integration/mt_wire.c /opt/mt/crypto/merkle.c \
    -L/opt/openssl/lib -lcrypto -o /opt/mt/bin/test_wire && /opt/mt/bin/test_wire
COPY scripts/runtime/client.sh scripts/runtime/server.sh scripts/runtime/benchmark-initial.py scripts/fixtures/generate-certs.sh scripts/fixtures/generate-merkle.sh scripts/lib/scenario.sh /opt/lab/
RUN mv /opt/lab/benchmark-initial.py /opt/lab/benchmark.py
RUN openssl list -providers && \
    openssl list -signature-algorithms | grep -Eiq 'mldsa44|ML-DSA' && \
    openssl list -tls-signature-algorithms | grep -q slhdsasha2128s
WORKDIR /work
CMD ["openssl", "version", "-a"]
