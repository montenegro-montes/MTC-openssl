#include "native_components.h"
#include <openssl/crypto.h>
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
} NativeComponents;

static int component_index = -1;
static CRYPTO_ONCE component_once = CRYPTO_ONCE_STATIC_INIT;

static double monotonic_ms(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1.0;
    return value.tv_sec * 1000.0 + value.tv_nsec / 1e6;
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
