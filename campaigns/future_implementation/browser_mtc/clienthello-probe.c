/* No sockets. Verification is deliberately fail-closed: not a TLS client yet. */
#include "mtc.c"
#include <openssl/bytestring.h>
#include <openssl/tls1.h>

#if TLSEXT_TYPE_trust_anchors != 0xca34
#error "This probe requires native provisional trust_anchors 0xca34"
#endif

static enum ssl_verify_result_t reject_peer(SSL *ssl, uint8_t *alert) {
    (void)ssl;
    *alert = SSL_AD_CERTIFICATE_UNKNOWN;
    return ssl_verify_invalid;
}

static int inspect(const unsigned char *data, size_t len,
                   const unsigned char *id, size_t idlen) {
    CBS record, payload, handshake, body, field, extensions;
    uint8_t type; uint16_t version, ext_type; unsigned found = 0;
    CBS_init(&record, data, len);
    if (!CBS_get_u8(&record, &type) || type != 22 ||
        !CBS_get_u16(&record, &version) ||
        !CBS_get_u16_length_prefixed(&record, &payload) || CBS_len(&record)) return 0;
    handshake = payload;
    if (!CBS_get_u8(&handshake, &type) || type != 1 ||
        !CBS_get_u24_length_prefixed(&handshake, &body) || CBS_len(&handshake) ||
        !CBS_skip(&body, 34) || /* legacy_version and random */
        !CBS_get_u8_length_prefixed(&body, &field) ||
        !CBS_get_u16_length_prefixed(&body, &field) ||
        !CBS_get_u8_length_prefixed(&body, &field) ||
        !CBS_get_u16_length_prefixed(&body, &extensions) || CBS_len(&body)) return 0;
    while (CBS_len(&extensions)) {
        if (!CBS_get_u16(&extensions, &ext_type) ||
            !CBS_get_u16_length_prefixed(&extensions, &field)) return 0;
        /* Reject the historical private codepoint; never negotiate it. */
        if (ext_type == 0xffa7) return 0;
        if (ext_type == MTC_EXT) {
            CBS list, actual;
            if (++found != 1 || !CBS_get_u16_length_prefixed(&field, &list) ||
                CBS_len(&field) || !CBS_get_u8_length_prefixed(&list, &actual) ||
                CBS_len(&list) || CBS_len(&actual) != idlen ||
                CRYPTO_memcmp(CBS_data(&actual), id, idlen)) return 0;
        }
    }
    return found == 1;
}

int main(int argc, char **argv) {
    int ok = 0; SSL_CTX *ctx = NULL; SSL *ssl = NULL;
    BIO *input = NULL, *output = NULL; MTCConfig *trust = NULL;
    unsigned char requested[256]; char *wire = NULL;
    if (argc != 2) { fprintf(stderr, "Usage: clienthello-probe authority.bin\n"); return 2; }
    trust = mtc_load(argv[1], 0);
    if (!trust || !trust->signal_len || trust->signal_len > 255) goto end;
    requested[0] = (unsigned char)trust->signal_len;
    memcpy(requested + 1, trust->signal, trust->signal_len);
    ctx = SSL_CTX_new(TLS_method());
    if (!ctx || !SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set1_requested_trust_anchors(ctx, requested, trust->signal_len + 1)) goto end;
    SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_PEER, reject_peer);
    ssl = SSL_new(ctx); input = BIO_new(BIO_s_mem()); output = BIO_new(BIO_s_mem());
    if (!ssl || !input || !output) goto end;
    BIO_set_mem_eof_return(input, -1);
    SSL_set_bio(ssl, input, output); input = output = NULL;
    int ret = SSL_connect(ssl);
    if (ret >= 0 || SSL_get_error(ssl, ret) != SSL_ERROR_WANT_READ) goto end;
    long len = BIO_get_mem_data(SSL_get_wbio(ssl), &wire);
    ok = len > 0 && inspect((const unsigned char *)wire, (size_t)len,
                           trust->signal, trust->signal_len);
end:
    BIO_free(input); BIO_free(output); SSL_free(ssl); SSL_CTX_free(ctx); mtc_free(trust);
    puts(ok ? "PASS: TLS 1.3 ClientHello contains one matching 0xca34 extension; no 0xffa7" : "FAIL: ClientHello probe");
    return ok ? 0 : 1;
}
