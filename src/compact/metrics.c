#include "compact.h"
#include <stdio.h>
#include <time.h>
#include <stdint.h>
typedef struct {
    int active;
    double wall, cpu;
    uint64_t read0, written0, hs_read, hs_written, certificate, certverify, extensions;
} Metrics;
static int index_value = -1;
static void (*previous_info)(const SSL *, int, int);
static double millis(clockid_t clock) { struct timespec t; clock_gettime(clock, &t); return t.tv_sec * 1000.0 + t.tv_nsec / 1e6; }
static void cleanup(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{ (void)parent; (void)ad; (void)idx; (void)argl; (void)argp; OPENSSL_free(ptr); }
static Metrics *get(const SSL *ssl)
{
    Metrics *m = SSL_get_ex_data(ssl, index_value);
    if (!m) {
        m = OPENSSL_zalloc(sizeof(*m));
        if (m && !SSL_set_ex_data((SSL *)ssl, index_value, m)) { OPENSSL_free(m); return NULL; }
    }
    return m;
}
static void info(const SSL *ssl, int where, int ret)
{
    Metrics *m = get(ssl);
    if (m && (where & SSL_CB_HANDSHAKE_START) && !m->active) {
        m->active = 1; m->wall = millis(CLOCK_MONOTONIC); m->cpu = millis(CLOCK_PROCESS_CPUTIME_ID);
        m->read0 = BIO_number_read(SSL_get_rbio(ssl)); m->written0 = BIO_number_written(SSL_get_wbio(ssl));
    }
    if (m && (where & SSL_CB_HANDSHAKE_DONE) && m->active) {
        double wall = millis(CLOCK_MONOTONIC) - m->wall, cpu = millis(CLOCK_PROCESS_CPUTIME_ID) - m->cpu;
        fprintf(stderr, "LAB_METRICS {\"handshake_wall_ms\":%.6f,\"handshake_client_cpu_ms\":%.6f,"
                "\"transport_read_bytes\":%llu,\"transport_written_bytes\":%llu,"
                "\"handshake_read_bytes\":%llu,\"handshake_written_bytes\":%llu,"
                "\"certificate_message_bytes\":%llu,\"certificate_verify_message_bytes\":%llu,\"encrypted_extensions_bytes\":%llu,"
                "\"reused\":%d,\"server_cert_type\":%d}\n",
                wall, cpu, (unsigned long long)(BIO_number_read(SSL_get_rbio(ssl)) - m->read0),
                (unsigned long long)(BIO_number_written(SSL_get_wbio(ssl)) - m->written0),
                (unsigned long long)m->hs_read, (unsigned long long)m->hs_written,
                (unsigned long long)m->certificate, (unsigned long long)m->certverify,
                (unsigned long long)m->extensions, SSL_session_reused(ssl), SSL_get_negotiated_server_cert_type(ssl));
        m->active = 0;
    }
    if (previous_info) previous_info(ssl, where, ret);
}
static void message(int write, int version, int type, const void *buf, size_t len, SSL *ssl, void *arg)
{
    Metrics *m = get(ssl); const unsigned char *p = buf;
    (void)version; (void)arg;
    if (!m || type != SSL3_RT_HANDSHAKE || !len) return;
    if (write) m->hs_written += len;
    else {
        m->hs_read += len;
        if (p[0] == SSL3_MT_CERTIFICATE) m->certificate += len;
        if (p[0] == SSL3_MT_CERTIFICATE_VERIFY) m->certverify += len;
        if (p[0] == SSL3_MT_ENCRYPTED_EXTENSIONS) m->extensions += len;
    }
}
int lab_metrics_enable(SSL_CTX *ctx)
{
    if (index_value < 0) index_value = SSL_get_ex_new_index(0, NULL, NULL, NULL, cleanup);
    if (index_value < 0) return 0;
    previous_info = SSL_CTX_get_info_callback(ctx);
    SSL_CTX_set_info_callback(ctx, info); SSL_CTX_set_msg_callback(ctx, message); return 1;
}
