/* Probe OpenSSL's post-ClientHello certificate suitability for MTC leaves.
 * In-memory TLS only: no sockets, application data, or fixture changes. */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

typedef int (*SecurityCallback)(const SSL *, const SSL_CTX *, int, int, int,
                                void *, void *);
static SecurityCallback previous_security;
static int proof_gate_count;

/* Match the existing server MTC exception; delegate every other decision. */
static int proof_algorithm(const X509_ALGOR *algorithm)
{
    const ASN1_OBJECT *object = NULL;
    char oid[80];
    if (!algorithm)
        return 0;
    X509_ALGOR_get0(&object, NULL, NULL, algorithm);
    return object && OBJ_obj2txt(oid, sizeof(oid), object, 1) > 0
        && strcmp(oid, "1.3.6.1.5.5.7.6.67") == 0;
}

static int mtc_probe_security(const SSL *ssl, const SSL_CTX *ctx, int op,
                              int bits, int nid, void *other, void *ex)
{
    if (op == SSL_SECOP_CA_MD && other) {
        const X509_ALGOR *signature = NULL;
        X509 *certificate = other;
        X509_get0_signature(NULL, &signature, certificate);
        if (proof_algorithm(signature)
            && proof_algorithm(X509_get0_tbs_sigalg(certificate))) {
            proof_gate_count++;
            return 1;
        }
    }
    return previous_security
        ? previous_security(ssl, ctx, op, bits, nid, other, ex) : 0;
}

typedef struct {
    X509 *cert[2];
    EVP_PKEY *key[2];
    int callback_seen;
    int ee_seen;
    int ee_before_callback;
    int valid[2];
} Probe;

static int choose_certificate(SSL *ssl, void *arg)
{
    Probe *probe = arg;
    int selected = -1;
    probe->callback_seen++;
    for (int i = 0; i < 2; i++) {
        int flags = SSL_check_chain(ssl, probe->cert[i], probe->key[i], NULL);
        probe->valid[i] = (flags & CERT_PKEY_VALID) != 0;
        printf("candidate_%d flags=0x%x cert_pkey_valid=%d\n",
               i, flags, probe->valid[i]);
        if (selected < 0 && probe->valid[i])
            selected = i;
    }
    fflush(stdout);
    return selected >= 0
        && SSL_use_cert_and_key(ssl, probe->cert[selected], probe->key[selected],
                                NULL, 1) == 1;
}

static void observe_message(int write_p, int version, int content_type,
                            const void *data, size_t length, SSL *ssl,
                            void *arg)
{
    Probe *probe = arg;
    const unsigned char *bytes = data;
    (void)version;
    (void)ssl;
    if (write_p && content_type == 22 && length && bytes[0] == 8) {
        probe->ee_seen++;
        if (!probe->callback_seen)
            probe->ee_before_callback = 1;
    }
}

static X509 *read_cert(const char *path)
{
    BIO *bio = BIO_new_file(path, "r");
    X509 *cert = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
    BIO_free(bio);
    return cert;
}

static EVP_PKEY *read_key(const char *path)
{
    BIO *bio = BIO_new_file(path, "r");
    EVP_PKEY *key = bio ? PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)
                        : NULL;
    BIO_free(bio);
    return key;
}

int main(int argc, char **argv)
{
    Probe probe = {0};
    SSL_CTX *server_ctx = NULL, *client_ctx = NULL;
    SSL *server = NULL, *client = NULL;
    BIO *server_bio = NULL, *client_bio = NULL;
    int server_done = 0, client_done = 0, ok = 0;

    if (argc != 4 && argc != 6) {
        fprintf(stderr, "usage: %s cert0.pem cert1.pem key0.pem [key1.pem client-groups]\n",
                argv[0]);
        return 2;
    }
    probe.cert[0] = read_cert(argv[1]);
    probe.cert[1] = read_cert(argv[2]);
    probe.key[0] = read_key(argv[3]);
    probe.key[1] = argc == 6 ? read_key(argv[4]) : probe.key[0];
    server_ctx = SSL_CTX_new(TLS_server_method());
    client_ctx = SSL_CTX_new(TLS_client_method());
    if (!probe.cert[0] || !probe.cert[1] || !probe.key[0] || !probe.key[1]
        || !server_ctx || !client_ctx
        || !X509_check_private_key(probe.cert[0], probe.key[0])
        || !X509_check_private_key(probe.cert[1], probe.key[1])
        || !SSL_CTX_set_min_proto_version(server_ctx, TLS1_3_VERSION)
        || !SSL_CTX_set_min_proto_version(client_ctx, TLS1_3_VERSION)
        || !SSL_CTX_set_max_proto_version(server_ctx, TLS1_3_VERSION)
        || !SSL_CTX_set_max_proto_version(client_ctx, TLS1_3_VERSION)
        || (argc == 6 && !SSL_CTX_set1_groups_list(client_ctx, argv[5])))
        goto end;

    previous_security = SSL_CTX_get_security_callback(server_ctx);
    SSL_CTX_set_security_callback(server_ctx, mtc_probe_security);
    SSL_CTX_set_cert_cb(server_ctx, choose_certificate, &probe);
    SSL_CTX_set_msg_callback(server_ctx, observe_message);
    SSL_CTX_set_msg_callback_arg(server_ctx, &probe);
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, NULL);
    server = SSL_new(server_ctx);
    client = SSL_new(client_ctx);
    if (!server || !client
        || !BIO_new_bio_pair(&server_bio, 0, &client_bio, 0))
        goto end;
    SSL_set_bio(server, server_bio, server_bio);
    SSL_set_bio(client, client_bio, client_bio);
    server_bio = client_bio = NULL;
    SSL_set_accept_state(server);
    SSL_set_connect_state(client);

    for (int step = 0; step < 100 && (!server_done || !client_done); step++) {
        SSL *peers[2] = {client, server};
        int *done[2] = {&client_done, &server_done};
        for (int i = 0; i < 2; i++) {
            int result, error;
            if (*done[i])
                continue;
            result = SSL_do_handshake(peers[i]);
            if (result == 1) {
                *done[i] = 1;
                continue;
            }
            error = SSL_get_error(peers[i], result);
            if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                goto end;
        }
    }
    ok = server_done && client_done && probe.callback_seen == 1
        && probe.ee_seen == 1 && !probe.ee_before_callback
        && probe.valid[0] && probe.valid[1] == (argc == 4)
        && proof_gate_count > 0;
end:
    printf("callback_seen=%d ee_seen=%d ee_before_callback=%d "
           "proof_gate_count=%d "
           "server_done=%d client_done=%d\n",
           probe.callback_seen, probe.ee_seen, probe.ee_before_callback,
           proof_gate_count, server_done, client_done);
    puts(ok ? (argc == 4 ? "PASS: both MTC candidates eligible before EE"
                         : "PASS: only candidate 0 eligible before EE")
            : "FAIL: inspect candidate flags or callback order");
    if (!ok)
        ERR_print_errors_fp(stderr);
    BIO_free(server_bio);
    BIO_free(client_bio);
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    X509_free(probe.cert[0]);
    X509_free(probe.cert[1]);
    if (probe.key[1] != probe.key[0])
        EVP_PKEY_free(probe.key[1]);
    EVP_PKEY_free(probe.key[0]);
    return ok ? 0 : 1;
}
