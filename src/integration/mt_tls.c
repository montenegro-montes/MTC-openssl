#include "mt_tls.h"
#include "mt_wire.h"
#include "apps.h"
#include "s_apps.h"
#include <string.h>
/* Private-use experiment identifier; not an assigned/interoperable protocol. */
#define MT_EXTENSION 0xffa5
#define MT_CONTEXT (SSL_EXT_TLS_ONLY | SSL_EXT_TLS1_3_ONLY | SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_CERTIFICATE)
typedef struct {
    int server;
    MTRoot root;
    unsigned char wire[MT_MAX_WIRE];
    size_t len;
} MTConfig;
static int ctx_index = -1, ssl_index = -1;
static const unsigned char offer[] = {1};
static char marker;
static void config_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                        int idx, long argl, void *argp)
{
    (void)parent; (void)ad; (void)idx; (void)argl; (void)argp;
    OPENSSL_free(ptr);
}
static int add(SSL *ssl, unsigned int type, unsigned int context,
               const unsigned char **out, size_t *len, X509 *x,
               size_t chainidx, int *alert, void *arg)
{
    MTConfig *config = arg;
    (void)type; (void)x;
    if (!config->server && context == SSL_EXT_CLIENT_HELLO) {
        /* Reset state for each new ClientHello, including HelloRetryRequest. */
        if (!SSL_set_ex_data(ssl, ssl_index, NULL)) { *alert = SSL_AD_INTERNAL_ERROR; return -1; }
        *out = offer; *len = sizeof(offer); return 1;
    }
    if (config->server && context == SSL_EXT_TLS1_3_CERTIFICATE && chainidx == 0
        && SSL_get_ex_data(ssl, ssl_index) == &marker) {
        *out = config->wire; *len = config->len; return 1;
    }
    return 0;
}
static int parse(SSL *ssl, unsigned int type, unsigned int context,
                 const unsigned char *in, size_t len, X509 *x,
                 size_t chainidx, int *alert, void *arg)
{
    MTConfig *config = arg;
    MTProof proof;
    unsigned char *der = NULL;
    int derlen, ok;
    (void)type;
    *alert = SSL_AD_DECODE_ERROR;
    if (config->server && context == SSL_EXT_CLIENT_HELLO) {
        if (len != sizeof(offer) || memcmp(in, offer, sizeof(offer))) return 0;
        return SSL_set_ex_data(ssl, ssl_index, &marker);
    }
    if (config->server || context != SSL_EXT_TLS1_3_CERTIFICATE || chainidx != 0
        || x == NULL || SSL_get_ex_data(ssl, ssl_index) != NULL
        || !mt_proof_decode(in, len, &proof)) {
        BIO_printf(bio_err, "Merkle verification FAILED: malformed proof\n");
        return 0;
    }
    derlen = i2d_X509(x, &der);
    ok = derlen > 0 && mt_proof_verify(der, (size_t)derlen, &proof, &config->root);
    OPENSSL_free(der);
    if (!ok) {
        BIO_printf(bio_err, "Merkle verification FAILED: certificate/root/proof mismatch\n");
        *alert = SSL_AD_BAD_CERTIFICATE; return 0;
    }
    if (!SSL_set_ex_data(ssl, ssl_index, &marker)) { *alert = SSL_AD_INTERNAL_ERROR; return 0; }
    return 1;
}
static int verify(int preverify_ok, X509_STORE_CTX *store)
{
    SSL *ssl = X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
    /* Never let s_client's permissive diagnostic callback override X.509 errors. */
    if (!preverify_ok) { (void)verify_callback(preverify_ok, store); return 0; }
    if (X509_STORE_CTX_get_error_depth(store) == 0) {
        if (!ssl || SSL_get_ex_data(ssl, ssl_index) != &marker) {
            X509_STORE_CTX_set_error(store, X509_V_ERR_APPLICATION_VERIFICATION);
            BIO_printf(bio_err, "Merkle verification FAILED: missing proof\n");
            return 0;
        }
        BIO_printf(bio_err, "Merkle verification: OK (X.509 also required)\n");
    }
    return verify_callback(preverify_ok, store);
}
static int configure(SSL_CTX *ctx, const char *path, int server)
{
    MTConfig *config = NULL;
    MTProof proof;
    if (ctx_index < 0) ctx_index = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, config_free);
    if (ssl_index < 0) ssl_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
    if (ctx_index < 0 || ssl_index < 0 || SSL_CTX_get_ex_data(ctx, ctx_index)) goto error;
    if (!server) {
        X509_VERIFY_PARAM *param = SSL_CTX_get0_param(ctx);
        char *ip = X509_VERIFY_PARAM_get1_ip_asc(param);
        int has_identity = X509_VERIFY_PARAM_get0_host(param, 0) != NULL || ip != NULL;
        OPENSSL_free(ip);
        if (!has_identity) {
            BIO_printf(bio_err, "Merkle mode requires -verify_hostname or -verify_ip\n");
            goto error;
        }
    }
    config = OPENSSL_zalloc(sizeof(*config));
    if (!config) goto error;
    config->server = server;
    if (!mt_read_file(path, config->wire, sizeof(config->wire), &config->len)) goto error;
    if (server) {
        if (!mt_proof_decode(config->wire, config->len, &proof)) goto error;
    } else if (!mt_root_decode(config->wire, config->len, &config->root)) goto error;
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)
        || !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)) goto error;
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    if (server && !SSL_CTX_set_num_tickets(ctx, 0)) goto error;
    if (!SSL_CTX_set_ex_data(ctx, ctx_index, config)) goto error;
    if (!SSL_CTX_add_custom_ext(ctx, MT_EXTENSION, MT_CONTEXT, add, NULL, config, parse, config)) {
        /* ctx now owns config, including on registration failure. */
        BIO_printf(bio_err, "Merkle extension registration FAILED\n");
        return 0;
    }
    if (!server) SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify);
    return 1;
error:
    OPENSSL_free(config);
    BIO_printf(bio_err, "Merkle configuration FAILED: invalid file or TLS context\n");
    return 0;
}
int mt_client_configure(SSL_CTX *ctx, const char *root_file)
{
    return configure(ctx, root_file, 0);
}
int mt_server_configure(SSL_CTX *ctx, const char *proof_file)
{
    return configure(ctx, proof_file, 1);
}
