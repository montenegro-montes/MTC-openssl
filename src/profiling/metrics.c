#include "compact.h"
#include "ssl/profile.h"
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
    int active, detail, error;
    double wall, cpu;
    int connect_attempted, connect_ok, establishment_done;
    double connect_start, connect_wall, establishment_wall;
    uint64_t read0, written0, hs_read, hs_written, certificate, cv, extensions;
} Metrics;
static int index_value = -1;
static void (*previous_info)(const SSL *, int, int);
static const char *names[PROFILE_COUNT] = {
    "certificate_parse", "rpk_parse", "peer_auth", "certificate_verify_verify", "certificate_verify_sign",
    "compact_payload_parse", "root_auth", "root_signature", "credential_total", "identity_validity",
    "key_binding", "spki_encode", "spki_hash", "merkle_proof", "phase1_proof", "certificate_build"
};
static double tick(clockid_t clock) { struct timespec t; clock_gettime(clock,&t); return t.tv_sec*1000.0+t.tv_nsec/1e6; }
static void cleanup(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long l, void *arg)
{
    Metrics *m = ptr;
    (void)parent; (void)ad; (void)idx; (void)l; (void)arg;
    if (m && m->connect_attempted) {
        fputs("NATIVE_CONNECTION_METRICS {", stderr);
        if (m->connect_ok) fprintf(stderr, "\"tcp_connect_wall_ms_native\":%.6f,", m->connect_wall);
        else fputs("\"tcp_connect_wall_ms_native\":null,", stderr);
        if (m->establishment_done) fprintf(stderr, "\"connection_establishment_wall_ms_native\":%.6f}\n", m->establishment_wall);
        else fputs("\"connection_establishment_wall_ms_native\":null}\n", stderr);
    }
    OPENSSL_free(ptr);
}
static Metrics *get(const SSL *ssl)
{
    Metrics *m = SSL_get_ex_data(ssl,index_value);
    if (!m) {
        m = OPENSSL_zalloc(sizeof(*m));
        if (m && !SSL_set_ex_data((SSL *)ssl,index_value,m)) { OPENSSL_free(m); return NULL; }
    }
    return m;
}
void lab_metrics_connect_start(SSL *ssl)
{
    Metrics *m = index_value >= 0 ? get(ssl) : NULL;
    if (m) {
        m->connect_attempted = 1;
        m->connect_ok = m->establishment_done = 0;
        m->connect_start = tick(CLOCK_MONOTONIC);
    }
}
void lab_metrics_connect_done(SSL *ssl, int success)
{
    Metrics *m = index_value >= 0 ? get(ssl) : NULL;
    if (m && m->connect_attempted && success) {
        m->connect_wall = tick(CLOCK_MONOTONIC) - m->connect_start;
        m->connect_ok = 1;
    }
}
int lab_metrics_connect(SSL *ssl, BIO *bio)
{
    int result;
    lab_metrics_connect_start(ssl);
    result = BIO_do_connect(bio);
    lab_metrics_connect_done(ssl, result > 0);
    return result;
}
static void emit(FILE *out, const char *id, const SSL *ssl, Metrics *m, double wall, double cpu,
                 const double *part_wall, const double *part_cpu, const unsigned long *calls, int valid)
{
    double tcp_connect_wall_ms, connection_establishment_wall_ms;
    tcp_connect_wall_ms = m->connect_ok ? m->connect_wall : -1.0;
    connection_establishment_wall_ms = m->establishment_done ? m->establishment_wall : -1.0;
    fprintf(out, "{\"client_random\":\"%s\",\"side\":\"%s\",\"detail\":%d,\"profile_valid\":%d,"
            "\"handshake_wall_ms\":%.6f,\"handshake_cpu_ms\":%.6f,"
            "\"transport_read_bytes\":%llu,\"transport_written_bytes\":%llu,"
            "\"handshake_read_bytes\":%llu,\"handshake_written_bytes\":%llu,"
            "\"certificate_message_bytes\":%llu,\"certificate_verify_message_bytes\":%llu,\"encrypted_extensions_bytes\":%llu,"
            "\"reused\":%d,\"server_cert_type\":%d,",
            id,SSL_is_server(ssl)?"server":"client",m->detail,valid,
            wall,cpu,(unsigned long long)(BIO_number_read(SSL_get_rbio(ssl))-m->read0),
            (unsigned long long)(BIO_number_written(SSL_get_wbio(ssl))-m->written0),
            (unsigned long long)m->hs_read,(unsigned long long)m->hs_written,
            (unsigned long long)m->certificate,(unsigned long long)m->cv,(unsigned long long)m->extensions,
            SSL_session_reused(ssl),SSL_get_negotiated_server_cert_type(ssl));
    if (tcp_connect_wall_ms >= 0.0 && connection_establishment_wall_ms >= 0.0)
        fprintf(out, "\"tcp_connect_wall_ms_native\":%.6f,\"connection_establishment_wall_ms_native\":%.6f,",
                tcp_connect_wall_ms, connection_establishment_wall_ms);
    else
        fputs("\"tcp_connect_wall_ms_native\":null,\"connection_establishment_wall_ms_native\":null,", out);
    fputs("\"components\":{", out);
    for (int i=0;i<PROFILE_COUNT;i++)
        fprintf(out,"%s\"%s\":{\"wall_ms\":%.6f,\"cpu_ms\":%.6f,\"calls\":%lu}",
                i?",":"",names[i],part_wall[i],part_cpu[i],calls[i]);
    fputs("}}\n",out);
}
static void info(const SSL *ssl, int where, int ret)
{
    Metrics *m=get(ssl);
    if (m && (where & SSL_CB_HANDSHAKE_START) && !m->active) {
        const char *detail=getenv("PROFILE_DETAIL");
        /* Preserve the per-SSL connect timestamp across handshake initialization. */
        m->hs_read=m->hs_written=m->certificate=m->cv=m->extensions=0;
        m->detail=detail && strcmp(detail,"1")==0;
        m->error=!SSL_profile_reset((SSL *)ssl,m->detail);
        m->active=1; m->read0=BIO_number_read(SSL_get_rbio(ssl)); m->written0=BIO_number_written(SSL_get_wbio(ssl));
        m->wall=tick(CLOCK_MONOTONIC); m->cpu=tick(CLOCK_PROCESS_CPUTIME_ID);
    }
    if (m && (where & SSL_CB_HANDSHAKE_DONE) && m->active) {
        double handshake_done=tick(CLOCK_MONOTONIC);
        double wall=handshake_done-m->wall, cpu=tick(CLOCK_PROCESS_CPUTIME_ID)-m->cpu;
        if (m->connect_ok) {
            m->establishment_wall=handshake_done-m->connect_start;
            m->establishment_done=1;
        }
        double pw[PROFILE_COUNT]={0}, pc[PROFILE_COUNT]={0}; unsigned long calls[PROFILE_COUNT]={0};
        unsigned char random[32]; char id[65];
        int valid=!m->error && SSL_profile_snapshot((SSL *)ssl,pw,pc,calls,PROFILE_COUNT);
        if (SSL_get_client_random(ssl,random,sizeof(random))!=sizeof(random)) valid=0;
        for(size_t i=0;i<sizeof(random);i++) snprintf(id+2*i,3,"%02x",random[i]);
        fputs("PROFILE_METRICS ",stderr); emit(stderr,id,ssl,m,wall,cpu,pw,pc,calls,valid);
        if (SSL_is_server(ssl)) {
            const char *directory=getenv("PROFILE_METRICS_DIR");
            if (directory) {
                char path[4096]; int n=snprintf(path,sizeof(path),"%s/%s.json",directory,id);
                FILE *out = n>0 && (size_t)n<sizeof(path) ? fopen(path,"wx") : NULL;
                if (out) { emit(out,id,ssl,m,wall,cpu,pw,pc,calls,valid); fclose(out); }
                else fputs("PROFILE_WRITE_FAILED\n",stderr);
            }
        }
        m->active=0;
    }
    if (previous_info) previous_info(ssl,where,ret);
}
static void message(int write, int version, int type, const void *buf, size_t len, SSL *ssl, void *arg)
{
    Metrics *m=get(ssl); const unsigned char *p=buf; (void)version; (void)arg;
    if (!m || type!=SSL3_RT_HANDSHAKE || !len) return;
    if (write) m->hs_written+=len; else m->hs_read+=len;
    /* Count the server's messages at both endpoints, for a consistency check. */
    if ((write && SSL_is_server(ssl)) || (!write && !SSL_is_server(ssl))) {
        if (p[0]==SSL3_MT_CERTIFICATE) m->certificate+=len;
        if (p[0]==SSL3_MT_CERTIFICATE_VERIFY) m->cv+=len;
        if (p[0]==SSL3_MT_ENCRYPTED_EXTENSIONS) m->extensions+=len;
    }
}
int lab_metrics_enable(SSL_CTX *ctx)
{
    if (index_value<0) index_value=SSL_get_ex_new_index(0,NULL,NULL,NULL,cleanup);
    if(index_value<0) return 0;
    previous_info=SSL_CTX_get_info_callback(ctx);
    SSL_CTX_set_info_callback(ctx,info); SSL_CTX_set_msg_callback(ctx,message); return 1;
}
