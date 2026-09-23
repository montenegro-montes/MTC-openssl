/* Direct-leaf laboratory client. No resumption or client auth. */
#include "mtc.c"
#include <openssl/pool.h>
#include <openssl/err.h>
#include <openssl/tls1.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>

#if TLSEXT_TYPE_trust_anchors != 0xca34
#error "Requires native provisional trust_anchors 0xca34"
#endif

typedef struct { MTCConfig *trust; const char *hostname; int verified; } Client;

static int available_matches(SSL *ssl, const MTCConfig *trust) {
    const uint8_t *data = NULL; size_t len = 0;
    SSL_get0_peer_available_trust_anchors(ssl, &data, &len);
    Slice list = {data, len}, id; int found = 0;
    if (!len) return 0;
    while (list.n) {
        if (!vector(&list, 1, &id) || !id.n) return 0;
        if (id.n == trust->signal_len &&
            !CRYPTO_memcmp(id.p, trust->signal, id.n)) found = 1;
    }
    return found;
}

static enum ssl_verify_result_t verify_peer(SSL *ssl, uint8_t *alert) {
    Client *client = SSL_get_app_data(ssl);
    X509 *leaf = NULL; X509_STORE *store = NULL; X509_STORE_CTX *check = NULL;
    const char *reason = "negotiation"; int ok = 0;
    *alert = SSL_AD_BAD_CERTIFICATE;
    if (!client || !SSL_peer_matched_trust_anchor(ssl) ||
        !available_matches(ssl, client->trust)) goto end;
    reason = "chain";
    const STACK_OF(CRYPTO_BUFFER) *chain = SSL_get0_peer_certificates(ssl);
    if (!chain || sk_CRYPTO_BUFFER_num(chain) != 1) goto end;
    const CRYPTO_BUFFER *buffer = sk_CRYPTO_BUFFER_value(chain, 0);
    const unsigned char *begin = CRYPTO_BUFFER_data(buffer), *cursor = begin;
    size_t len = CRYPTO_BUFFER_len(buffer);
    if (len > MTC_MAX) goto end;
    leaf = d2i_X509(NULL, &cursor, (long)len);
    if (!leaf || cursor != begin + len) goto end;
    reason = "proof";
    if (!mtc_verify(leaf, client->trust)) goto end;
    reason = "hostname";
    if (X509_check_host(leaf, client->hostname, strlen(client->hostname),
                       X509_CHECK_FLAG_NEVER_CHECK_SUBJECT, NULL) != 1) goto end;
    reason = "validity";
    if (X509_cmp_current_time(X509_get0_notBefore(leaf)) >= 0 ||
        X509_cmp_current_time(X509_get0_notAfter(leaf)) <= 0) goto end;
    reason = "purpose";
    if (X509_check_purpose(leaf, X509_PURPOSE_SSL_SERVER, 0) != 1) goto end;
    /* Only after authenticating this exact leaf with MTC, use it as a local
       trust anchor to apply native leaf constraints. Not general PKIX. */
    reason = "leaf-policy";
    store = X509_STORE_new(); check = X509_STORE_CTX_new();
    if (!store || !check || !X509_STORE_add_cert(store, leaf) ||
        !X509_STORE_CTX_init(check, store, leaf, NULL)) goto end;
    X509_VERIFY_PARAM *param = X509_STORE_CTX_get0_param(check);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
    if (!X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_PARTIAL_CHAIN) ||
        !X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_SSL_SERVER) ||
        !X509_VERIFY_PARAM_set1_host(param, client->hostname, strlen(client->hostname)) ||
        X509_verify_cert(check) != 1) goto end;
    client->verified = 1; ok = 1;
end:
    if (!ok) fprintf(stderr, "MTC_REJECT: %s\n", reason);
    X509_STORE_CTX_free(check); X509_STORE_free(store); X509_free(leaf);
    return ok ? ssl_verify_ok : ssl_verify_invalid;
}

int main(int argc, char **argv) {
    int result = 1, fd = -1; SSL_CTX *ctx = NULL; SSL *ssl = NULL;
    Client client = {0}; unsigned char requested[256];
    int landmark = 0;
    if (argc == 4 && !strcmp(argv[3], "landmark")) landmark = 1;
    else if (argc != 3 && !(argc == 4 && !strcmp(argv[3], "standalone"))) {
        fprintf(stderr, "Usage: tls-client TRUST_BIN DNS_NAME [standalone|landmark]\n"); return 2;
    }
    signal(SIGPIPE, SIG_IGN); alarm(20);
    client.hostname = argv[2]; client.trust = mtc_load(argv[1], landmark);
    if (!client.trust || client.trust->request_signal_len > 255) goto end;
    requested[0] = (unsigned char)client.trust->request_signal_len;
    memcpy(requested + 1, client.trust->request_signal, client.trust->request_signal_len);
    ctx = SSL_CTX_new(TLS_method());
    /* BoringSSL's default verification list omits P-521 and ML-DSA even
       though this revision implements them. Scope this explicit policy to
       the six laboratory profiles; CertificateVerify remains mandatory. */
    const uint16_t signature_algorithms[] = {
        SSL_SIGN_ECDSA_SECP256R1_SHA256, SSL_SIGN_ECDSA_SECP384R1_SHA384,
        SSL_SIGN_ECDSA_SECP521R1_SHA512,
        SSL_SIGN_ML_DSA_44, SSL_SIGN_ML_DSA_65, SSL_SIGN_ML_DSA_87
    };
    if (!ctx || !SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_verify_algorithm_prefs(ctx, signature_algorithms,
            sizeof(signature_algorithms) / sizeof(signature_algorithms[0])) ||
        !SSL_CTX_set1_requested_trust_anchors(ctx, requested, client.trust->request_signal_len + 1)) goto end;
    SSL_CTX_set_custom_verify(ctx, SSL_VERIFY_PEER, verify_peer);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    ssl = SSL_new(ctx);
    if (!ssl || !SSL_set_app_data(ssl, &client) ||
        !SSL_set_tlsext_host_name(ssl, client.hostname)) goto end;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0}; address.sin_family = AF_INET;
    address.sin_port = htons(4433);
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) goto end;
    if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        !SSL_set_fd(ssl, fd)) { perror("transport"); goto end; }
    if (SSL_connect(ssl) != 1 || !client.verified || SSL_session_reused(ssl)) goto end;
    printf("TLS_OK: %s %s; MTC %s; hostname=%s\n",
           SSL_get_version(ssl), SSL_get_cipher(ssl), landmark ? "landmark" : "standalone", client.hostname);
    SSL_shutdown(ssl); result = 0;
end:
    if (result) ERR_print_errors_fp(stderr);
    SSL_free(ssl); SSL_CTX_free(ctx); if (fd >= 0) close(fd);
    mtc_free(client.trust); alarm(0); return result;
}
