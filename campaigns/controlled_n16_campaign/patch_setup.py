"""Measurement-only wrappers; preserve return values and protocol implementation."""
from pathlib import Path
import sys,hashlib
root=Path(sys.argv[1]);p=root/'apps/s_client.c';s=p.read_text()
def once(a,b):
    global s
    if s.count(a)!=1:raise ValueError('Unexpected source anchor: '+a)
    s=s.replace(a,b,1)
wrapper=r'''
#include <time.h>
static double measurement_clock(clockid_t id)
{
    struct timespec t;
    if (clock_gettime(id, &t) != 0) return -1;
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}
static void measurement_setup_emit(const char *scheme, double wall, double cpu)
{
    double end_wall = measurement_clock(CLOCK_MONOTONIC);
    double end_cpu = measurement_clock(CLOCK_PROCESS_CPUTIME_ID);
    fprintf(stderr, "MEASUREMENT_SETUP {\"scheme\":\"%s\",\"setup_wall_ms\":%.6f,\"setup_cpu_ms\":%.6f}\n",
            scheme, end_wall - wall, end_cpu - cpu);
}
static int measurement_compact_client(SSL_CTX *ctx, const char *authority, const char *cached_root)
{
    double wall = measurement_clock(CLOCK_MONOTONIC);
    double cpu = measurement_clock(CLOCK_PROCESS_CPUTIME_ID);
    int result = compact_client(ctx, authority, cached_root);
    if (result) measurement_setup_emit("compact", wall, cpu);
    return result;
}
static int measurement_mtc_client(SSL_CTX *ctx, const char *path, int landmark)
{
    double wall = measurement_clock(CLOCK_MONOTONIC);
    double cpu = measurement_clock(CLOCK_PROCESS_CPUTIME_ID);
    int result = mtc_client(ctx, path, landmark);
    if (result) measurement_setup_emit("MTC-experimental", wall, cpu);
    return result;
}
'''
once('#include "mtc.h"','#include "mtc.h"\n'+wrapper)
once('!compact_client(ctx, compact_a, compact_b)','!measurement_compact_client(ctx, compact_a, compact_b)')
once('!mtc_client(ctx,mtc_file,mtc_landmark_mode)','!measurement_mtc_client(ctx,mtc_file,mtc_landmark_mode)')
p.write_text(s)
(root/'CONTROLLED_MEASUREMENT_SHA256').write_text(hashlib.sha256(Path(__file__).read_bytes()).hexdigest()+'\n')
