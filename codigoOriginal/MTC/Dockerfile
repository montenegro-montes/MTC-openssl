FROM ubuntu:24.04

# Arguments obtained from .env file through docker-compose.yaml args: parameter 
# (only available during the build process)
ARG OPENSSL_VERSION
ARG OPENSSL_DIR
ARG WORKDIR

# Set environment variables (available during both build and runtime)
ENV DEBIAN_FRONTEND=noninteractive
ENV OPENSSL_DIR=${OPENSSL_DIR}
ENV WORKDIR=${WORKDIR}

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    perl \
    wget \
    ca-certificates \
    git \
    cmake \
    ninja-build \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set up OpenSSL
WORKDIR /tmp
RUN wget https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz && \
    tar xzf openssl-${OPENSSL_VERSION}.tar.gz && \
    cd openssl-${OPENSSL_VERSION} && \
    ./Configure \
        --prefix=${OPENSSL_DIR} \
        --openssldir=${OPENSSL_DIR} \
        shared \
        linux-x86_64 && \
    make -j$(nproc) && \
    make install

# Clean up temporary files
RUN rm -rf /tmp/openssl-${OPENSSL_VERSION} /tmp/openssl-${OPENSSL_VERSION}.tar.gz

# Set environment variables for OpenSSL
ENV PATH="${OPENSSL_DIR}/bin:${PATH}"
ENV LD_LIBRARY_PATH="${OPENSSL_DIR}/lib64:${OPENSSL_DIR}/lib:${LD_LIBRARY_PATH}"

# Verify OpenSSL installation
RUN echo "OpenSSL version $(openssl version) installed at $(which openssl)"

# Set the working directory for the container
WORKDIR ${WORKDIR}

# Keep the container running for interactive use
CMD ["tail", "-f", "/dev/null"]
