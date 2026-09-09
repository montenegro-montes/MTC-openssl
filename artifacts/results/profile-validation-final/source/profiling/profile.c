#include "profile.h"
#include <time.h>
#include <string.h>
#define STACK_MAX 8
typedef struct {
    int enabled, error, depth[PROFILE_COUNT];
    double wall[PROFILE_COUNT], cpu[PROFILE_COUNT];
    double wall_start[PROFILE_COUNT][STACK_MAX], cpu_start[PROFILE_COUNT][STACK_MAX];
    unsigned long calls[PROFILE_COUNT];
} Profile;
static int index_value = -1;
static CRYPTO_ONCE once = CRYPTO_ONCE_STATIC_INIT;
static double tick(clockid_t clock)
{
    struct timespec t;
    if (clock_gettime(clock, &t)) return -1;
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}
static void cleanup(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long l, void *arg)
{ (void)parent; (void)ad; (void)idx; (void)l; (void)arg; OPENSSL_free(ptr); }
static void init(void) { index_value = SSL_get_ex_new_index(0, NULL, NULL, NULL, cleanup); }
int SSL_profile_reset(SSL *ssl, int enabled)
{
    Profile *p;
    if (!CRYPTO_THREAD_run_once(&once, init) || index_value < 0) return 0;
    p = SSL_get_ex_data(ssl, index_value);
    if (!p) {
        p = OPENSSL_zalloc(sizeof(*p));
        if (!p || !SSL_set_ex_data(ssl, index_value, p)) { OPENSSL_free(p); return 0; }
    }
    memset(p, 0, sizeof(*p)); p->enabled = enabled; return 1;
}
void SSL_profile_begin(SSL *ssl, int id)
{
    Profile *p; int d;
    if (!ssl || index_value < 0 || !(p = SSL_get_ex_data(ssl, index_value)) || !p->enabled) return;
    if (id < 0 || id >= PROFILE_COUNT || (d = p->depth[id]) >= STACK_MAX) { p->error = 1; return; }
    p->wall_start[id][d] = tick(CLOCK_MONOTONIC);
    p->cpu_start[id][d] = tick(CLOCK_PROCESS_CPUTIME_ID);
    p->depth[id]++;
}
void SSL_profile_end(SSL *ssl, int id)
{
    Profile *p; int d;
    if (!ssl || index_value < 0 || !(p = SSL_get_ex_data(ssl, index_value)) || !p->enabled) return;
    if (id < 0 || id >= PROFILE_COUNT || p->depth[id] <= 0) { p->error = 1; return; }
    d = --p->depth[id];
    p->cpu[id] += tick(CLOCK_PROCESS_CPUTIME_ID) - p->cpu_start[id][d];
    p->wall[id] += tick(CLOCK_MONOTONIC) - p->wall_start[id][d];
    p->calls[id]++;
}
int SSL_profile_snapshot(SSL *ssl, double *wall, double *cpu, unsigned long *calls, size_t count)
{
    Profile *p;
    if (index_value < 0 || count != PROFILE_COUNT || !(p = SSL_get_ex_data(ssl, index_value)) || p->error) return 0;
    for (int i = 0; i < PROFILE_COUNT; i++) if (p->depth[i]) return 0;
    memcpy(wall,p->wall,sizeof(p->wall)); memcpy(cpu,p->cpu,sizeof(p->cpu)); memcpy(calls,p->calls,sizeof(p->calls));
    return 1;
}
