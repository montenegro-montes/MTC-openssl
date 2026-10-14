#include "native_components.h"
#include <openssl/crypto.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

typedef struct {
    int active[MTC_NATIVE_COMPONENT_COUNT];
    double start[MTC_NATIVE_COMPONENT_COUNT];
    double elapsed[MTC_NATIVE_COMPONENT_COUNT];
    unsigned long calls[MTC_NATIVE_COMPONENT_COUNT];
    int authentication_active;
    unsigned int authentication_regions;
    double authentication_start, authentication_elapsed;
    int credential_validation_active;
    int credential_validation_complete;
    int credential_validation_overflow;
    struct timespec credential_validation_start;
    uint64_t credential_validation_ns;
    int crypto_active[MTC_NATIVE_CRYPTO_COMPONENT_COUNT];
    struct timespec crypto_start[MTC_NATIVE_CRYPTO_COMPONENT_COUNT];
    uint64_t crypto_elapsed_ns[MTC_NATIVE_CRYPTO_COMPONENT_COUNT];
    uint64_t crypto_calls[MTC_NATIVE_CRYPTO_COMPONENT_COUNT];
    int crypto_overflow[MTC_NATIVE_CRYPTO_COMPONENT_COUNT];
    int x509_measurement_active;
    int x509_measurement_complete;
} NativeComponents;

static int component_index = -1;
static CRYPTO_ONCE component_once = CRYPTO_ONCE_STATIC_INIT;

static double monotonic_ms(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1.0;
    return value.tv_sec * 1000.0 + value.tv_nsec / 1e6;
}

static int elapsed_monotonic_ns(const struct timespec *start,
                                uint64_t *elapsed)
{
    struct timespec end;
    uint64_t seconds, nanoseconds;
    if (start == NULL || elapsed == NULL
            || clock_gettime(CLOCK_MONOTONIC, &end) != 0
            || end.tv_sec < start->tv_sec)
        return 0;
    seconds = (uint64_t)(end.tv_sec - start->tv_sec);
    if (end.tv_nsec < start->tv_nsec) {
        if (seconds == 0) return 0;
        seconds--;
        nanoseconds = 1000000000ULL + (uint64_t)end.tv_nsec
                      - (uint64_t)start->tv_nsec;
    } else {
        nanoseconds = (uint64_t)(end.tv_nsec - start->tv_nsec);
    }
    if (seconds > UINT64_MAX / 1000000000ULL) return 0;
    *elapsed = seconds * 1000000000ULL + nanoseconds;
    return 1;
}

static void free_components(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                            int idx, long argl, void *argp)
{
    (void)parent; (void)ad; (void)idx; (void)argl; (void)argp;
    OPENSSL_free(ptr);
}

static void init_components(void)
{
    component_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, free_components);
}

static NativeComponents *components(SSL *ssl)
{
    NativeComponents *value;
    if (!CRYPTO_THREAD_run_once(&component_once, init_components)
            || component_index < 0) return NULL;
    value = SSL_get_ex_data(ssl, component_index);
    if (value == NULL) {
        value = OPENSSL_zalloc(sizeof(*value));
        if (value != NULL && !SSL_set_ex_data(ssl, component_index, value)) {
            OPENSSL_free(value);
            return NULL;
        }
    }
    return value;
}

int mtc_native_components_reset(SSL *ssl)
{
    NativeComponents *value = components(ssl);
    if (value == NULL) return 0;
    memset(value, 0, sizeof(*value));
    return 1;
}

void mtc_native_component_begin(SSL *ssl, int component)
{
    NativeComponents *value = components(ssl);
    if (value == NULL || component < 0 || component >= MTC_NATIVE_COMPONENT_COUNT
            || value->active[component]) return;
    value->start[component] = monotonic_ms();
    value->active[component] = 1;
}

void mtc_native_component_end(SSL *ssl, int component)
{
    NativeComponents *value = components(ssl);
    if (value == NULL || component < 0 || component >= MTC_NATIVE_COMPONENT_COUNT
            || !value->active[component]) return;
    value->elapsed[component] += monotonic_ms() - value->start[component];
    value->calls[component]++;
    value->active[component] = 0;
}

void mtc_native_authentication_begin(SSL *ssl)
{
    NativeComponents *value = components(ssl);
    if (value == NULL || value->authentication_active) return;
    value->authentication_start = monotonic_ms();
    value->authentication_active = 1;
}

void mtc_native_authentication_end(SSL *ssl)
{
    NativeComponents *value = components(ssl);
    if (value == NULL || !value->authentication_active) return;
    value->authentication_elapsed += monotonic_ms()
                                     - value->authentication_start;
    value->authentication_regions++;
    value->authentication_active = 0;
}

void mtc_native_credential_validation_begin(SSL *ssl)
{
    NativeComponents *value = components(ssl);
    if (value == NULL || value->credential_validation_overflow) return;
    if (value->credential_validation_active
            || value->credential_validation_complete) {
        value->credential_validation_overflow = 1;
        return;
    }
    if (clock_gettime(CLOCK_MONOTONIC,
                      &value->credential_validation_start) != 0) {
        value->credential_validation_overflow = 1;
        return;
    }
    value->credential_validation_active = 1;
}

void mtc_native_credential_validation_end(SSL *ssl)
{
    NativeComponents *value = components(ssl);
    uint64_t elapsed;
    if (value == NULL || !value->credential_validation_active) return;
    value->credential_validation_active = 0;
    if (!elapsed_monotonic_ns(&value->credential_validation_start, &elapsed)) {
        value->credential_validation_overflow = 1;
        return;
    }
    value->credential_validation_ns = elapsed;
    value->credential_validation_complete = 1;
}

int mtc_native_components_snapshot(SSL *ssl, double *milliseconds,
                                   unsigned long *calls, size_t count)
{
    NativeComponents *value = components(ssl);
    if (value == NULL || count != MTC_NATIVE_COMPONENT_COUNT) return 0;
    for (size_t i = 0; i < count; i++) {
        if (value->active[i]) return 0;
        milliseconds[i] = value->elapsed[i];
        calls[i] = value->calls[i];
    }
    return 1;
}

int mtc_native_authentication_snapshot(SSL *ssl, double *milliseconds)
{
    NativeComponents *value = components(ssl);
    if (value == NULL || value->authentication_active
            || value->authentication_regions != 2) return 0;
    *milliseconds = value->authentication_elapsed;
    return 1;
}

int mtc_native_credential_validation_snapshot(SSL *ssl,
                                              uint64_t *nanoseconds)
{
    NativeComponents *value = components(ssl);
    if (value == NULL || nanoseconds == NULL
            || value->credential_validation_active
            || !value->credential_validation_complete
            || value->credential_validation_overflow)
        return 0;
    *nanoseconds = value->credential_validation_ns;
    return 1;
}

void mtc_native_crypto_begin(SSL *ssl, int component)
{
    NativeComponents *value = components(ssl);
    if (value == NULL || component < 0
            || component >= MTC_NATIVE_CRYPTO_COMPONENT_COUNT
            || value->crypto_active[component]
            || value->crypto_overflow[component])
        return;
    if (clock_gettime(CLOCK_MONOTONIC, &value->crypto_start[component]) == 0)
        value->crypto_active[component] = 1;
    else
        value->crypto_overflow[component] = 1;
}

void mtc_native_crypto_end(SSL *ssl, int component)
{
    NativeComponents *value = components(ssl);
    uint64_t elapsed;
    if (value == NULL || component < 0
            || component >= MTC_NATIVE_CRYPTO_COMPONENT_COUNT
            || !value->crypto_active[component])
        return;
    value->crypto_active[component] = 0;
    if (!elapsed_monotonic_ns(&value->crypto_start[component], &elapsed)
            || value->crypto_calls[component] == UINT64_MAX
            || elapsed > UINT64_MAX - value->crypto_elapsed_ns[component]) {
        value->crypto_overflow[component] = 1;
        return;
    }
    value->crypto_elapsed_ns[component] += elapsed;
    value->crypto_calls[component]++;
}

int mtc_native_crypto_snapshot(SSL *ssl, uint64_t *nanoseconds,
                               uint64_t *calls, size_t count)
{
    NativeComponents *value = components(ssl);
    if (value == NULL || count != MTC_NATIVE_CRYPTO_COMPONENT_COUNT)
        return 0;
    for (size_t i = 0; i < count; i++) {
        if (value->crypto_active[i] || value->crypto_overflow[i]) return 0;
        nanoseconds[i] = value->crypto_elapsed_ns[i];
        calls[i] = value->crypto_calls[i];
    }
    return 1;
}

int mtc_native_certificate_verify_crypto_snapshot(SSL *ssl,
                                                  uint64_t *nanoseconds,
                                                  uint64_t *calls)
{
    NativeComponents *value = components(ssl);
    int component = MTC_NATIVE_CERTIFICATE_VERIFY_CRYPTO;
    if (value == NULL || nanoseconds == NULL || calls == NULL
            || value->crypto_active[component]
            || value->crypto_overflow[component])
        return 0;
    *nanoseconds = value->crypto_elapsed_ns[component];
    *calls = value->crypto_calls[component];
    return 1;
}

void mtc_native_x509_measurement_begin(SSL *ssl)
{
    NativeComponents *value = components(ssl);
    if (value == NULL) return;
    value->x509_measurement_active = 1;
    value->x509_measurement_complete = 0;
}

void mtc_native_x509_measurement_end(SSL *ssl)
{
    NativeComponents *value = components(ssl);
    if (value == NULL || !value->x509_measurement_active) return;
    value->x509_measurement_active = 0;
    value->x509_measurement_complete = 1;
}

void mtc_native_x509_signature_begin(void *ssl)
{
    mtc_native_crypto_begin(ssl, MTC_NATIVE_X509_SIGNATURE_CRYPTO);
}

void mtc_native_x509_signature_end(void *ssl)
{
    mtc_native_crypto_end(ssl, MTC_NATIVE_X509_SIGNATURE_CRYPTO);
}

int mtc_native_x509_signature_snapshot(SSL *ssl, uint64_t *nanoseconds,
                                       uint64_t *calls)
{
    NativeComponents *value = components(ssl);
    int component = MTC_NATIVE_X509_SIGNATURE_CRYPTO;
    if (value == NULL || nanoseconds == NULL || calls == NULL
            || value->x509_measurement_active
            || !value->x509_measurement_complete
            || value->crypto_active[component]
            || value->crypto_overflow[component])
        return 0;
    *nanoseconds = value->crypto_elapsed_ns[component];
    *calls = value->crypto_calls[component];
    return 1;
}
