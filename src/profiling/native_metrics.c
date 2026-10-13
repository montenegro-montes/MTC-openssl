#include "native_metrics.h"
#include "../ssl/native_components.h"
#include <openssl/crypto.h>
#include <stdio.h>
#include <time.h>

typedef struct {
    int connect_attempted, connect_ok, handshake_started;
    double connect_start, connect_wall, handshake_start;
} NativeMetrics;

static int metrics_index = -1;
static void (*previous_info)(const SSL *, int, int);

static double monotonic_ms(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1.0;
    return value.tv_sec * 1000.0 + value.tv_nsec / 1e6;
}

static void free_metrics(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                         int idx, long argl, void *argp)
{
    (void)parent; (void)ad; (void)idx; (void)argl; (void)argp;
    OPENSSL_free(ptr);
}

static NativeMetrics *metrics(const SSL *ssl)
{
    NativeMetrics *value = SSL_get_ex_data(ssl, metrics_index);
    if (value == NULL) {
        value = OPENSSL_zalloc(sizeof(*value));
        if (value != NULL && !SSL_set_ex_data((SSL *)ssl, metrics_index, value)) {
            OPENSSL_free(value);
            return NULL;
        }
    }
    return value;
}

void mtc_native_connect_start(SSL *ssl)
{
    NativeMetrics *value = metrics_index >= 0 ? metrics(ssl) : NULL;
    if (value != NULL) {
        value->connect_attempted = 1;
        value->connect_ok = value->handshake_started = 0;
        value->connect_start = monotonic_ms();
    }
}

void mtc_native_connect_done(SSL *ssl, int success)
{
    NativeMetrics *value = metrics_index >= 0 ? metrics(ssl) : NULL;
    if (value != NULL && value->connect_attempted && success) {
        value->connect_wall = monotonic_ms() - value->connect_start;
        value->connect_ok = 1;
    }
}

static void info_callback(const SSL *ssl, int where, int ret)
{
    NativeMetrics *value = metrics(ssl);
    if (value != NULL && (where & SSL_CB_HANDSHAKE_START)) {
        mtc_native_components_reset((SSL *)ssl);
        value->handshake_start = monotonic_ms();
        value->handshake_started = 1;
    }
    if (value != NULL && (where & SSL_CB_HANDSHAKE_DONE)
            && value->handshake_started) {
        double finished = monotonic_ms();
        double component_ms[MTC_NATIVE_COMPONENT_COUNT] = {0};
        double authentication_ms = 0;
        unsigned long component_calls[MTC_NATIVE_COMPONENT_COUNT] = {0};
        int components_ok = mtc_native_components_snapshot((SSL *)ssl,
                component_ms, component_calls, MTC_NATIVE_COMPONENT_COUNT);
        int authentication_ok = mtc_native_authentication_snapshot(
                (SSL *)ssl, &authentication_ms);
        fprintf(stdout, "NATIVE_METRICS {\"tcp_connect_wall_ms_native\":");
        if (value->connect_ok) fprintf(stdout, "%.6f", value->connect_wall);
        else fputs("null", stdout);
        fprintf(stdout, ",\"handshake_wall_ms\":%.6f,",
                finished - value->handshake_start);
        fputs("\"connection_establishment_wall_ms_native\":", stdout);
        if (value->connect_ok) fprintf(stdout, "%.6f", finished - value->connect_start);
        else fputs("null", stdout);
        if (components_ok && component_calls[MTC_NATIVE_X509_VERIFY] > 0)
            fprintf(stdout, ",\"x509_verification_ms\":%.6f,"
                    "\"credential_verification_total_ms\":%.6f",
                    component_ms[MTC_NATIVE_X509_VERIFY],
                    component_ms[MTC_NATIVE_X509_VERIFY]);
        else fputs(",\"x509_verification_ms\":null,"
                   "\"credential_verification_total_ms\":null", stdout);
        if (components_ok && component_calls[MTC_NATIVE_CERTIFICATE_VERIFY] > 0)
            fprintf(stdout, ",\"certificate_verify_ms\":%.6f",
                    component_ms[MTC_NATIVE_CERTIFICATE_VERIFY]);
        else fputs(",\"certificate_verify_ms\":null", stdout);
        if (authentication_ok)
            fprintf(stdout,
                    ",\"client_authentication_verification_total_ms\":%.6f",
                    authentication_ms);
        else fputs(",\"client_authentication_verification_total_ms\":null",
                   stdout);
        fputs("}\n", stdout);
        fflush(stdout);
        value->handshake_started = 0;
    }
    if (previous_info != NULL) previous_info(ssl, where, ret);
}

int mtc_native_metrics_enable(SSL_CTX *ctx)
{
    if (metrics_index < 0)
        metrics_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, free_metrics);
    if (metrics_index < 0) return 0;
    previous_info = SSL_CTX_get_info_callback(ctx);
    SSL_CTX_set_info_callback(ctx, info_callback);
    return 1;
}
