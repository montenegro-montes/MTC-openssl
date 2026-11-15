FROM mt-tls-mtc-cert-comp:local
COPY campaigns/performance/x509_cert_compression/patch_provider_cert.py /opt/cert-comp/patch_provider_cert.py
COPY campaigns/performance/x509_cert_compression/patch_aux_untrusted.py /opt/cert-comp/patch_aux_untrusted.py

RUN python3 /opt/cert-comp/patch_provider_cert.py /opt/src/openssl-mtc/ssl/ssl_cert_comp.c \
    && python3 /opt/cert-comp/patch_aux_untrusted.py /opt/src/openssl-mtc/apps/s_client.c \
    && cd /opt/src/openssl-mtc \
    && make -j2 apps/openssl \
    && cp apps/openssl /opt/openssl-mtc/bin/openssl \
    && cp -a libssl.so* /opt/openssl-mtc/lib/ \
    && /opt/mtc/openssl.sh version
