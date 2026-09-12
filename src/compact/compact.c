#include "compact.h"
#include "mt_wire.h"
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#define EXT 0xffa6u
#define CONTEXT (SSL_EXT_TLS_ONLY | SSL_EXT_TLS1_3_ONLY | SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS)
#define MAX_PAYLOAD 8192u
#define ROOT_HEADER 88u
#define MAX_CREDENTIAL 308u

typedef struct {
    int server, warm;
    EVP_PKEY *authority;
    unsigned char authority_id[32];
    uint64_t authority_nb, authority_na;
    MTRoot root;
    uint64_t root_nb, root_na;
    char hostname[254];
    unsigned char bundle[MAX_PAYLOAD], signed_root[MAX_PAYLOAD];
    size_t bundle_len, signed_len;
} Config;
typedef struct {
    int offered, received, warm;
    unsigned char credential[MAX_CREDENTIAL];
    size_t credential_len;
    MTProof proof;
    MTRoot root;
    uint64_t root_nb, root_na;
} State;
static int ci = -1, si = -1;
static uint16_t u16(const unsigned char *p) { return ((uint16_t)p[0] << 8) | p[1]; }
static uint32_t u32(const unsigned char *p) { return ((uint32_t)u16(p) << 16) | u16(p + 2); }
static uint64_t u64(const unsigned char *p) { return ((uint64_t)u32(p) << 32) | u32(p + 4); }
static void put16(unsigned char *p, size_t n) { p[0] = (unsigned char)(n >> 8); p[1] = (unsigned char)n; }
static double now_ms(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000.0 + t.tv_nsec / 1e6; }
static int valid_time(uint64_t nb, uint64_t na) { time_t t = time(NULL); return t >= 0 && nb <= (uint64_t)t && (uint64_t)t <= na && nb < na; }
static int hash_key(EVP_PKEY *key, unsigned char out[32])
{
    unsigned char *der = NULL; unsigned int size = 0;
    int n = i2d_PUBKEY(key, &der);
    int ok = n > 0 && EVP_Digest(der, (size_t)n, out, &size, EVP_sha256(), NULL) && size == 32;
    OPENSSL_free(der); return ok;
}
static const char *signature_digest(EVP_PKEY *key)
{
    return EVP_PKEY_is_a(key, "EC") ? "SHA256" : NULL;
}
static int supported_key(EVP_PKEY *key)
{
    return key && (EVP_PKEY_is_a(key, "mldsa65")
                  ||  EVP_PKEY_is_a(key, "ML-DSA-65"))
                  || (EVP_PKEY_is_a(key, "EC") && EVP_PKEY_get_bits(key) == 256));
}
static uint64_t asn1_epoch(const ASN1_TIME *value)
{
    struct tm tm = {0}; time_t t;
    if (!ASN1_TIME_to_tm(value, &tm)) return 0;
    t = timegm(&tm); return t < 0 ? 0 : (uint64_t)t;
}
static int dns_name(const unsigned char *p, size_t n)
{
    size_t label = 0;
    if (!n || n > 253) return 0;
    for (size_t i = 0; i < n; i++) {
        if (p[i] == '.') {
            if (!label || p[i - 1] == '-') return 0;
            label = 0;
        } else {
            if (!((p[i] >= 'a' && p[i] <= 'z') || (p[i] >= '0' && p[i] <= '9') || p[i] == '-')) return 0;
            if ((!label && p[i] == '-') || ++label > 63) return 0;
        }
    }
    return label && p[n - 1] != '-';
}
static int root_decode(Config *c, const unsigned char *p, size_t n,
                       MTRoot *root, uint64_t *nb, uint64_t *na, int verify)
{
    EVP_MD_CTX *md = NULL; int ok = 0;
    if (n < ROOT_HEADER + 2 || memcmp(p, "MTR2", 4)
        || u16(p + ROOT_HEADER) != n - ROOT_HEADER - 2) return 0;
    root->leaves = u32(p + 4); memcpy(root->root.bytes, p + 8, 32);
    *nb = u64(p + 40); *na = u64(p + 48);
    if (!root->leaves || root->leaves > MT_MAX_LEAVES || !valid_time(*nb, *na)) return 0;
    if (!verify) return 1;
    if (!c->authority || CRYPTO_memcmp(p + 56, c->authority_id, 32)
        || *nb < c->authority_nb || *na > c->authority_na) return 0;
    md = EVP_MD_CTX_new();
    ok = md && EVP_DigestVerifyInit_ex(md, NULL, signature_digest(c->authority), NULL, NULL, c->authority, NULL)
         && EVP_DigestVerify(md, p + ROOT_HEADER + 2, n - ROOT_HEADER - 2, p, ROOT_HEADER) == 1;
    EVP_MD_CTX_free(md); return ok;
}
static int bundle_decode(const unsigned char *p, size_t n, State *s,
                         const unsigned char **root, size_t *root_len)
{
    size_t credlen, prooflen, offset;
    if (n < 10 || n > MAX_PAYLOAD || memcmp(p, "MCB2", 4)) return 0;
    credlen = u16(p + 4);
    if (credlen < 56 || credlen > MAX_CREDENTIAL || n < 6 + credlen + 4) return 0;
    offset = 6 + credlen; prooflen = u16(p + offset); offset += 2;
    if (prooflen > n - offset - 2 || !mt_proof_decode(p + offset, prooflen, &s->proof)) return 0;
    offset += prooflen; *root_len = u16(p + offset); offset += 2;
    if (*root_len != n - offset) return 0;
    memcpy(s->credential, p + 6, credlen); s->credential_len = credlen;
    *root = p + offset;
    return 1;
}
static int credential_verify(Config *c, State *s, EVP_PKEY *key)
{
    const unsigned char *p = s->credential;
    size_t n = s->credential_len, name_len;
    unsigned char digest[32]; uint64_t nb, na;
    if (n < 56 || memcmp(p, "MTC2", 4)) return 0;
    name_len = u16(p + 4);
    if (n != 55 + name_len || !dns_name(p + 6, name_len)
        || strlen(c->hostname) != name_len || memcmp(p + 6, c->hostname, name_len)) return 0;
    nb = u64(p + 6 + name_len); na = u64(p + 14 + name_len);
    if (!valid_time(nb, na) || !valid_time(s->root_nb, s->root_na)
        || !valid_time(c->authority_nb, c->authority_na)
        || s->root_nb < nb || s->root_na > na || p[n - 1] != 1
        || !supported_key(key) || !hash_key(key, digest)
        || CRYPTO_memcmp(p + 22 + name_len, digest, 32)) return 0;
    return mt_proof_verify(p, n, &s->proof, &s->root);
}
static void config_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    Config *c = ptr; (void)parent; (void)ad; (void)idx; (void)argl; (void)argp;
    if (c) { EVP_PKEY_free(c->authority); OPENSSL_free(c); }
}
static void state_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
    (void)parent; (void)ad; (void)idx; (void)argl; (void)argp; OPENSSL_free(ptr);
}
static State *state(SSL *ssl)
{
    State *s = SSL_get_ex_data(ssl, si);
    if (!s) {
        s = OPENSSL_zalloc(sizeof(*s));
        if (s && !SSL_set_ex_data(ssl, si, s)) { OPENSSL_free(s); s = NULL; }
    }
    return s;
}
static int add(SSL *ssl, unsigned int type, unsigned int context,
               const unsigned char **out, size_t *len, X509 *x, size_t index,
               int *alert, void *arg)
{
    Config *c = arg; State *s = state(ssl); unsigned char *p;
    (void)type; (void)x; (void)index; *alert = SSL_AD_INTERNAL_ERROR;
    if (!s) return -1;
    if (!c->server && context == SSL_EXT_CLIENT_HELLO) {
        memset(s, 0, sizeof(*s)); s->warm = c->warm;
        *len = c->warm ? 34 : 2; p = OPENSSL_malloc(*len);
        if (!p) return -1;
        p[0] = 2; p[1] = c->warm ? 0 : 1;
        if (c->warm) memcpy(p + 2, c->root.root.bytes, 32);
        *out = p; return 1;
    }
    if (c->server && context == SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS && s->offered) {
        *len = c->bundle_len + (s->warm ? 0 : c->signed_len);
        if (*len > MAX_PAYLOAD || !(p = OPENSSL_malloc(*len))) return -1;
        memcpy(p, c->bundle, c->bundle_len);
        if (!s->warm) {
            put16(p + c->bundle_len - 2, c->signed_len);
            memcpy(p + c->bundle_len, c->signed_root, c->signed_len);
        }
        *out = p; return 1;
    }
    return 0;
}
static void free_ext(SSL *ssl, unsigned int type, unsigned int context, const unsigned char *p, void *arg)
{
    (void)ssl; (void)type; (void)context; (void)arg; OPENSSL_free((void *)p);
}
static int parse(SSL *ssl, unsigned int type, unsigned int context,
                 const unsigned char *p, size_t n, X509 *x, size_t index, int *alert, void *arg)
{
    Config *c = arg; State *s = state(ssl); const unsigned char *root; size_t rootlen;
    (void)type; (void)x; (void)index; *alert = SSL_AD_BAD_CERTIFICATE;
    if (!s) return 0;
    if (c->server && context == SSL_EXT_CLIENT_HELLO) {
        if (n < 2 || p[0] != 2 || p[1] > 1 || n != (p[1] ? 2u : 34u)) goto fail;
        s->warm = p[1] == 0;
        if (s->warm && CRYPTO_memcmp(p + 2, c->root.root.bytes, 32)) goto fail;
        s->offered = 1; return 1;
    }
    if (c->server || context != SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS || s->received
        || !bundle_decode(p, n, s, &root, &rootlen)) goto fail;
    if (c->warm) {
        if (rootlen) goto fail;
        s->root = c->root; s->root_nb = c->root_nb; s->root_na = c->root_na;
    } else if (!root_decode(c, root, rootlen, &s->root, &s->root_nb, &s->root_na, 1)) goto fail;
    s->received = 1; return 1;
fail:
    fprintf(stderr, "Compact verification FAILED: extension/root\n"); return 0;
}
static int verify(X509_STORE_CTX *store, void *arg)
{
    Config *c = arg;
    SSL *ssl = X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
    State *s = ssl ? SSL_get_ex_data(ssl, si) : NULL;
    EVP_PKEY *key = X509_STORE_CTX_get0_rpk(store);
    if (!ssl || !s || !s->received || SSL_get_negotiated_server_cert_type(ssl) != TLSEXT_cert_type_rpk
        || !key || !credential_verify(c, s, key)) {
        X509_STORE_CTX_set_error(store, X509_V_ERR_APPLICATION_VERIFICATION);
        fprintf(stderr, "Compact verification FAILED: credential/identity/key/proof\n"); return 0;
    }
    X509_STORE_CTX_set_error(store, X509_V_OK);
    fprintf(stderr, "Compact verification: OK (RPK + authenticated Merkle credential)\n");
    return 1;
}
static int install(SSL_CTX *ctx, Config *c)
{
    const unsigned char rpk[] = {TLSEXT_cert_type_rpk};
    if (ci < 0) ci = SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, config_free);
    if (si < 0) si = SSL_get_ex_new_index(0, NULL, NULL, NULL, state_free);
    if (ci < 0 || si < 0 || SSL_CTX_get_ex_data(ctx, ci)
        || !SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)
        || !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)
        || !SSL_CTX_set1_server_cert_type(ctx, rpk, sizeof(rpk))) goto fail;
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    if (!SSL_CTX_set_num_tickets(ctx, 0)) goto fail;
    if (!SSL_CTX_add_custom_ext(ctx, EXT, CONTEXT, add, free_ext, c, parse, c)) goto fail;
    if (!SSL_CTX_set_ex_data(ctx, ci, c)) goto fail;
    if (!c->server) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_cert_verify_callback(ctx, verify, c);
    }
    return 1;
fail:
    config_free(NULL, c, NULL, 0, 0, NULL); return 0;
}
int compact_client(SSL_CTX *ctx, const char *authority, const char *cached_root)
{
    double start = now_ms(); BIO *bio = NULL; X509 *ca = NULL;
    Config *c = OPENSSL_zalloc(sizeof(*c));
    const char *host = X509_VERIFY_PARAM_get0_host(SSL_CTX_get0_param(ctx), 0);
    if (!c || !authority || !host || strlen(host) > 253 || X509_VERIFY_PARAM_get0_host(SSL_CTX_get0_param(ctx), 1)) goto fail;
    for (size_t i = 0; host[i]; i++) c->hostname[i] = host[i] >= 'A' && host[i] <= 'Z' ? host[i] + 32 : host[i];
    if (!dns_name((unsigned char *)c->hostname, strlen(c->hostname))) goto fail;
    bio = BIO_new_file(authority, "r");
    if (!bio || !(ca = PEM_read_bio_X509(bio, NULL, NULL, NULL)) || X509_check_ca(ca) <= 0) goto fail;
    c->authority = X509_get_pubkey(ca);
    c->authority_nb = asn1_epoch(X509_get0_notBefore(ca)); c->authority_na = asn1_epoch(X509_get0_notAfter(ca));
    if (!supported_key(c->authority) || !hash_key(c->authority, c->authority_id)
        || !valid_time(c->authority_nb, c->authority_na)) goto fail;
    c->warm = cached_root != NULL;
    if (c->warm && (!mt_read_file(cached_root, c->signed_root, sizeof(c->signed_root), &c->signed_len)
        || !root_decode(c, c->signed_root, c->signed_len, &c->root, &c->root_nb, &c->root_na, 1))) goto fail;
    X509_free(ca); BIO_free(bio);
    if (!install(ctx, c)) return 0;
    fprintf(stderr, "COMPACT_SETUP {\"cached_root\":%s,\"setup_ms\":%.6f}\n", cached_root ? "true" : "false", now_ms() - start);
    return 1;
fail:
    fprintf(stderr, "Compact configuration FAILED: authority/root/hostname\n");
    X509_free(ca); BIO_free(bio); config_free(NULL, c, NULL, 0, 0, NULL); return 0;
}
int compact_server(SSL_CTX *ctx, const char *bundle, const char *signed_root)
{
    Config *c = OPENSSL_zalloc(sizeof(*c)); State state_value = {0};
    const unsigned char *root; size_t rootlen;
    if (!c) return 0;
    c->server = 1;
    if (!bundle || !signed_root || !mt_read_file(bundle, c->bundle, sizeof(c->bundle), &c->bundle_len)
        || !bundle_decode(c->bundle, c->bundle_len, &state_value, &root, &rootlen) || rootlen
        || !mt_read_file(signed_root, c->signed_root, sizeof(c->signed_root), &c->signed_len)
        || c->bundle_len + c->signed_len > MAX_PAYLOAD
        || !root_decode(c, c->signed_root, c->signed_len, &c->root, &c->root_nb, &c->root_na, 0)
        || !mt_proof_verify(state_value.credential, state_value.credential_len, &state_value.proof, &c->root)) {
        fprintf(stderr, "Compact server configuration FAILED\n");
        config_free(NULL, c, NULL, 0, 0, NULL); return 0;
    }
    return install(ctx, c);
}
