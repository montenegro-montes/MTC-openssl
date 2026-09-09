"""Add profiling in a separate source/library copy. All replacements fail on drift."""
from pathlib import Path
import hashlib
import re
import shutil
import sys
source=Path(sys.argv[1]); here=Path(__file__).resolve().parent

def once(s,old,new):
    if s.count(old)!=1: raise SystemExit(f'Expected one anchor: {old!r}')
    return s.replace(old,new,1)

def function(s,name):
    # Match a definition, never a declaration; mask comments/literals for brace counting.
    pattern=rf'^(?:static )?(?:int|MSG_PROCESS_RETURN|CON_FUNC_RETURN) {name}\([^;{{]*\)\s*\{{'
    match=re.search(pattern,s,re.M)
    if not match: raise SystemExit('Function not found: '+name)
    brace=s.index('{',match.start())
    masked=re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',lambda m:' '*len(m.group()),s,flags=re.S)
    depth=1; end=brace+1
    while depth:
        if masked[end]=='{': depth+=1
        if masked[end]=='}': depth-=1
        end+=1
    return match.start(),brace,end

def wrap(s,name,args,ssl,category):
    start,brace,end=function(s,name)
    signature=s[start:brace].strip()
    kind=signature.removeprefix('static ').split(' ',1)[0]
    impl=signature.replace(name+'(',name+'_profile_impl(',1)
    if not impl.startswith('static '): impl='static '+impl
    body=s[brace:end]
    wrapper=f'''\n{signature}
{{
    {kind} result;
    SSL_profile_begin({ssl}, {category});
    result = {name}_profile_impl({args});
    SSL_profile_end({ssl}, {category});
    return result;
}}'''
    return s[:start]+impl+'\n'+body+wrapper+s[end:]

for name in ['profile.c','profile.h']: shutil.copyfile(here/name,source/'ssl'/name)
p=source/'ssl/build.info';p.write_text(p.read_text()+'\nSOURCE[../libssl]=profile.c\n')
p=source/'util/libssl.num';s=p.read_text();number=max(int(line.split()[1]) for line in s.splitlines() if line.strip() and not line.startswith('#'))
for i,name in enumerate(['SSL_profile_reset','SSL_profile_begin','SSL_profile_end','SSL_profile_snapshot'],1):
    s+=f'{name:40} {number+i}\t3_5_0\tEXIST::FUNCTION:\n'
p.write_text(s)
for filename,definitions in {
    'ssl/ssl_cert.c':[('ssl_verify_internal','s, sk, rpk','s','P_PEER_AUTH')],
    'ssl/statem/statem_srvr.c':[('tls_construct_server_certificate','s, pkt','s','P_CERT_BUILD')],
    'ssl/statem/statem_clnt.c':[('tls_process_server_certificate','s, pkt','s','P_CERT_PARSE')],
    'ssl/statem/statem_lib.c':[('tls_process_rpk','sc, pkt, peer_rpk','sc','P_RPK_PARSE'),
                               ('tls_process_cert_verify','s, pkt','s','P_CV_VERIFY'),
                               ('tls_construct_cert_verify','s, pkt','s','P_CV_SIGN')]
}.items():
    p=source/filename;s=p.read_text();s='#include "'+('../' if '/statem/' in filename else '')+'profile.h"\n'+s
    for name,args,ssl,category in definitions: s=wrap(s,name,args,f'SSL_CONNECTION_GET_SSL({ssl})',category)
    p.write_text(s)

# Compact subcomponents. Preserve all checks and their short-circuit order.
p=source/'apps/compact.c';s=p.read_text();s='#include "ssl/profile.h"\n'+s
s=once(s,'    int offered, received, warm;','    int offered, received, warm;\n    SSL *ssl;')
s=once(s,'    return s;\n}\nstatic int add(', '    if (s) s->ssl = ssl;\n    return s;\n}\nstatic int add(')
s=once(s,'static int hash_key(EVP_PKEY *key, unsigned char out[32])','static int hash_key(EVP_PKEY *key, unsigned char out[32], SSL *ssl)')
s=once(s,'    int n = i2d_PUBKEY(key, &der);','    int n, ok;\n    SSL_profile_begin(ssl, P_KEY_ENCODE);\n    n = i2d_PUBKEY(key, &der);\n    SSL_profile_end(ssl, P_KEY_ENCODE);\n    SSL_profile_begin(ssl, P_KEY_HASH);')
s=once(s,'    int ok = n > 0 && EVP_Digest', '    ok = n > 0 && EVP_Digest')
s=once(s,'    OPENSSL_free(der); return ok;', '    SSL_profile_end(ssl, P_KEY_HASH);\n    OPENSSL_free(der); return ok;')
s=once(s,'hash_key(c->authority, c->authority_id)','hash_key(c->authority, c->authority_id, NULL)')
s=once(s,'uint64_t *nb, uint64_t *na, int verify)', 'uint64_t *nb, uint64_t *na, int verify, SSL *ssl)')
s=once(s,'&s->root_nb, &s->root_na, 1)', '&s->root_nb, &s->root_na, 1, ssl)')
s=once(s,'&c->root_nb, &c->root_na, 1)', '&c->root_nb, &c->root_na, 1, NULL)')
s=once(s,'&c->root_nb, &c->root_na, 0)', '&c->root_nb, &c->root_na, 0, NULL)')
s=once(s,'    md = EVP_MD_CTX_new();', '''    struct timespec profile_cpu;
    double signature_wall = 0, signature_cpu = 0;
    if (!ssl) {
        signature_wall = now_ms();
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &profile_cpu);
        signature_cpu = profile_cpu.tv_sec * 1000.0 + profile_cpu.tv_nsec / 1e6;
    }
    SSL_profile_begin(ssl, P_ROOT_SIGNATURE);
    md = EVP_MD_CTX_new();''')
s=once(s,'    EVP_MD_CTX_free(md); return ok;', '''    EVP_MD_CTX_free(md);
    SSL_profile_end(ssl, P_ROOT_SIGNATURE);
    if (!ssl) {
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &profile_cpu);
        fprintf(stderr, "ROOT_SIGNATURE_SETUP {\\"wall_ms\\":%.6f,\\"cpu_ms\\":%.6f}\\n",
                now_ms() - signature_wall,
                profile_cpu.tv_sec * 1000.0 + profile_cpu.tv_nsec / 1e6 - signature_cpu);
    }
    return ok;''')
start,brace,end=function(s,'credential_verify')
s=s[:start]+'''static int profile_policy(Config *c, State *s)
{
    const unsigned char *p = s->credential;
    size_t n = s->credential_len, name_len;
    uint64_t nb, na;
    if (n < 56 || memcmp(p, "MTC2", 4)) return 0;
    name_len = u16(p + 4);
    if (n != 55 + name_len || !dns_name(p + 6, name_len)
        || strlen(c->hostname) != name_len || memcmp(p + 6, c->hostname, name_len)) return 0;
    nb = u64(p + 6 + name_len); na = u64(p + 14 + name_len);
    if (!valid_time(nb, na) || !valid_time(s->root_nb, s->root_na)
        || !valid_time(c->authority_nb, c->authority_na)
        || s->root_nb < nb || s->root_na > na || p[n - 1] != 1) return 0;
    return 1;
}
static int profile_binding(State *s, EVP_PKEY *key)
{
    unsigned char digest[32]; size_t name_len = u16(s->credential + 4);
    return supported_key(key) && hash_key(key, digest, s->ssl)
           && !CRYPTO_memcmp(s->credential + 22 + name_len, digest, 32);
}
static int profile_proof(State *s)
{
    return mt_proof_verify(s->credential, s->credential_len, &s->proof, &s->root);
}
static int credential_verify(Config *c, State *s, EVP_PKEY *key)
{
    return profile_policy(c, s) && profile_binding(s, key) && profile_proof(s);
}'''+s[end:]
for name,args,ssl,category in [('profile_policy','c, s','s->ssl','P_POLICY'),
    ('profile_binding','s, key','s->ssl','P_KEY_BINDING'),('profile_proof','s','s->ssl','P_PROOF'),
    ('credential_verify','c, s, key','s->ssl','P_CREDENTIAL'),('root_decode','c, p, n, root, nb, na, verify, ssl','ssl','P_ROOT_AUTH'),
    ('bundle_decode','p, n, s, root, root_len','s->ssl','P_COMPACT_PARSE')]: s=wrap(s,name,args,ssl,category)
p.write_text(s)
p=source/'apps/mt_tls.c';s=p.read_text();s='#include "ssl/profile.h"\n'+s
s=once(s,'    derlen = i2d_X509(x, &der);','    SSL_profile_begin(ssl, P_PHASE1_PROOF);\n    derlen = i2d_X509(x, &der);')
s=once(s,'    OPENSSL_free(der);','    OPENSSL_free(der);\n    SSL_profile_end(ssl, P_PHASE1_PROOF);');p.write_text(s)
shutil.copyfile(here/'metrics.c',source/'apps/metrics.c')
for app in ['s_client','s_server']:
    p=source/'apps'/f'{app}.c';s=p.read_text()
    s=once(s,'    OPT_COMMON,','    OPT_COMMON,\n    OPT_PROFILE_RPK_ONLY,')
    extra='    {"profile_rpk_only", OPT_PROFILE_RPK_ONLY, \'-\', "Diagnostic RPK-only negotiation"},\n'
    s=once(s,'#include "compact.h"','#include "compact.h"\nstatic int profile_rpk_only = 0;\nstatic const unsigned char profile_rpk_type[] = { TLSEXT_cert_type_rpk };')
    s=once(s,'        case OPT_HELP:', '        case OPT_PROFILE_RPK_ONLY:\n            profile_rpk_only = 1; enable_server_rpk = 1; mt_incompatible = 1; break;\n        case OPT_HELP:')
    if app=='s_server':
        s=once(s,'    OPT_COMMON,','    OPT_COMMON,\n    OPT_PROFILE_METRICS,')
        s=once(s,'static int profile_rpk_only = 0;','static int profile_rpk_only = 0, profile_metrics = 0;')
        extra+='    {"lab_metrics", OPT_PROFILE_METRICS, \'-\', "Emit endpoint and component metrics"},\n'
        s=once(s,'        case OPT_HELP:', '        case OPT_PROFILE_METRICS: profile_metrics = 1; break;\n        case OPT_HELP:')
        s=once(s,'    SSL_CTX_set_verify(ctx, s_server_verify, verify_callback);','    if (profile_metrics && !lab_metrics_enable(ctx)) goto end;\n    SSL_CTX_set_verify(ctx, s_server_verify, verify_callback);')
        old='SSL_CTX_set1_server_cert_type(ctx, cert_type_rpk, sizeof(cert_type_rpk))'
        new='SSL_CTX_set1_server_cert_type(ctx, profile_rpk_only ? profile_rpk_type : cert_type_rpk, profile_rpk_only ? sizeof(profile_rpk_type) : sizeof(cert_type_rpk))'
    else:
        guard = """
static int profile_verify_callback(int ok, X509_STORE_CTX *store)
{
    if (profile_rpk_only && X509_STORE_CTX_get0_cert(store) != NULL) {
        X509_STORE_CTX_set_error(store, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }
    return verify_callback(ok, store);
}
"""
        s=once(s, 'static int profile_rpk_only = 0;', 'static int profile_rpk_only = 0;'+guard)
        s=once(s, 'SSL_CTX_set_verify(ctx, verify, verify_callback);', 'SSL_CTX_set_verify(ctx, verify, profile_verify_callback);')
        old='SSL_set1_server_cert_type(con, cert_type_rpk, sizeof(cert_type_rpk))'
        new='SSL_set1_server_cert_type(con, profile_rpk_only ? profile_rpk_type : cert_type_rpk, profile_rpk_only ? sizeof(profile_rpk_type) : sizeof(cert_type_rpk))'
    s=once(s,old,new)
    s=once(s,'    { "help", OPT_HELP,',extra+'    { "help", OPT_HELP,')
    p.write_text(s)
h=hashlib.sha256()
for p in sorted(here.iterdir()):
    if p.is_file():h.update(p.name.encode()+b'\0'+p.read_bytes())
(source/'PROFILE_SHA256').write_text(h.hexdigest()+'\n')
