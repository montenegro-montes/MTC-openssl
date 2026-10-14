"""Add minimal TCP/TLS timing to the active MTC s_client."""
from pathlib import Path
import hashlib, shutil, sys

source=Path(sys.argv[1]); here=Path(__file__).resolve().parent
def once(text, old, new):
    if text.count(old)!=1: raise SystemExit(f'Expected one native-metrics anchor: {old!r}')
    return text.replace(old,new,1)

for name in ('native_metrics.c','native_metrics.h'):
    shutil.copyfile(here/name,source/'apps'/name)
build=source/'apps/build.info'; build.write_text(build.read_text()+'\nSOURCE[openssl]=native_metrics.c\n')
for name in ('native_components.c','native_components.h'):
    shutil.copyfile(here/name,source/'ssl'/name)
build=source/'ssl/build.info'; build.write_text(build.read_text()+'\nSOURCE[../libssl]=native_components.c\n')
shutil.copyfile(here/'native_x509_timing.h',
                source/'include/crypto/native_x509_timing.h')
exports=source/'util/libssl.num'; export_text=exports.read_text()
number=max(int(line.split()[1]) for line in export_text.splitlines()
           if line.strip() and not line.startswith('#'))
for offset,name in enumerate(('mtc_native_components_reset',
                              'mtc_native_component_begin',
                              'mtc_native_component_end',
                              'mtc_native_authentication_begin',
                              'mtc_native_authentication_end',
                              'mtc_native_credential_validation_begin',
                              'mtc_native_credential_validation_end',
                              'mtc_native_components_snapshot',
                              'mtc_native_authentication_snapshot',
                              'mtc_native_credential_validation_snapshot',
                              'mtc_native_crypto_begin',
                              'mtc_native_crypto_end',
                              'mtc_native_crypto_snapshot',
                              'mtc_native_certificate_verify_crypto_snapshot',
                              'mtc_native_x509_signature_snapshot'),1):
    export_text+=f'{name:40} {number+offset}\t3_4_0\tEXIST::FUNCTION:\n'
exports.write_text(export_text)

def patch_asn1_verifier():
    p=source/'crypto/asn1/a_verify.c'; text=p.read_text()
    text=once(text, '#include "crypto/rsa.h"',
              '#include "crypto/rsa.h"\n'
              '#include "crypto/native_x509_timing.h"')
    text=once(text,
              'int ASN1_item_verify(const ASN1_ITEM *it, const X509_ALGOR *alg,',
              'static int asn1_item_verify_ctx_with_timing(\n'
              '    const ASN1_ITEM *it, const X509_ALGOR *alg,\n'
              '    const ASN1_BIT_STRING *signature, const void *data,\n'
              '    EVP_MD_CTX *ctx, const OSSL_MTC_X509_TIMING *timing);\n\n'
              'int ASN1_item_verify(const ASN1_ITEM *it, const X509_ALGOR *alg,')
    old=('int ASN1_item_verify_ctx(const ASN1_ITEM *it, const X509_ALGOR *alg,\n'
         '    const ASN1_BIT_STRING *signature, const void *data,\n'
         '    EVP_MD_CTX *ctx)\n'
         '{')
    new=(old+'\n'
         '    return asn1_item_verify_ctx_with_timing(it, alg, signature,\n'
         '        data, ctx, NULL);\n'
         '}\n\n'
         'static int asn1_item_verify_ctx_with_timing(\n'
         '    const ASN1_ITEM *it, const X509_ALGOR *alg,\n'
         '    const ASN1_BIT_STRING *signature, const void *data,\n'
         '    EVP_MD_CTX *ctx, const OSSL_MTC_X509_TIMING *timing)\n'
         '{')
    text=once(text, old, new)
    old=('    ret = EVP_DigestVerify(ctx, signature->data, '
         '(size_t)signature->length,\n'
         '        buf_in, inl);')
    new=('    if (timing != NULL && timing->begin != NULL)\n'
         '        timing->begin(timing->arg);\n'
         '    ret = EVP_DigestVerify(ctx, signature->data,\n'
         '        (size_t)signature->length, buf_in, inl);\n'
         '    if (timing != NULL && timing->end != NULL)\n'
         '        timing->end(timing->arg);')
    text=once(text, old, new)
    anchor=('int ASN1_item_verify_ctx(const ASN1_ITEM *it, '
            'const X509_ALGOR *alg,\n'
            '    const ASN1_BIT_STRING *signature, const void *data,\n'
            '    EVP_MD_CTX *ctx)')
    timed=('int ossl_asn1_item_verify_ex_with_timing(\n'
           '    const ASN1_ITEM *it, const X509_ALGOR *alg,\n'
           '    const ASN1_BIT_STRING *signature, const void *data,\n'
           '    const ASN1_OCTET_STRING *id, EVP_PKEY *pkey,\n'
           '    OSSL_LIB_CTX *libctx, const char *propq,\n'
           '    const OSSL_MTC_X509_TIMING *timing)\n'
           '{\n'
           '    EVP_MD_CTX *ctx;\n'
           '    int rv = -1;\n\n'
           '    if ((ctx = evp_md_ctx_new_ex(pkey, id, libctx, propq)) '
           '!= NULL) {\n'
           '        rv = asn1_item_verify_ctx_with_timing(it, alg, signature,\n'
           '            data, ctx, timing);\n'
           '        EVP_PKEY_CTX_free(EVP_MD_CTX_get_pkey_ctx(ctx));\n'
           '        EVP_MD_CTX_free(ctx);\n'
           '    }\n'
           '    return rv;\n'
           '}\n\n')
    text=once(text, anchor, timed+anchor)
    p.write_text(text)

patch_asn1_verifier()

# The source image is pinned to OpenSSL 3.4.7. These anchors deliberately
# fail closed if its X.509 verification internals drift in another release.
p=source/'include/crypto/x509.h'; text=p.read_text()
text=once(text, '#include "crypto/types.h"',
          '#include "crypto/types.h"\n'
          '#include "crypto/native_x509_timing.h"')
text=once(text, '    char *propq;\n};\n\n/* PKCS#8 private key info structure */',
          '    char *propq;\n'
          '    OSSL_MTC_X509_TIMING mtc_signature_timing;\n'
          '};\n\n/* PKCS#8 private key info structure */')
p.write_text(text)

exports=source/'util/libcrypto.num'; export_text=exports.read_text()
number=max(int(line.split()[1]) for line in export_text.splitlines()
           if line.strip() and not line.startswith('#'))
export_text+=(f'{"ossl_x509_store_ctx_set_signature_timing":40} '
             f'{number+1}\t3_4_0\tEXIST::FUNCTION:\n')
exports.write_text(export_text)

p=source/'crypto/x509/x_all.c'; text=p.read_text()
text=once(text, '#include "crypto/rsa.h"',
          '#include "crypto/rsa.h"\n'
          '#include "crypto/native_x509_timing.h"')
anchor='int X509_REQ_verify_ex(X509_REQ *a, EVP_PKEY *r, OSSL_LIB_CTX *libctx,'
timed=('int ossl_x509_verify_with_timing(\n'
       '    X509 *a, EVP_PKEY *r, const OSSL_MTC_X509_TIMING *timing)\n'
       '{\n'
       '    if (X509_ALGOR_cmp(&a->sig_alg, &a->cert_info.signature) != 0)\n'
       '        return 0;\n\n'
       '    return ossl_asn1_item_verify_ex_with_timing(\n'
       '        ASN1_ITEM_rptr(X509_CINF), &a->sig_alg, &a->signature,\n'
       '        &a->cert_info, a->distinguishing_id, r, a->libctx, a->propq,\n'
       '        timing);\n'
       '}\n\n')
text=once(text, anchor, timed+anchor)
p.write_text(text)

p=source/'crypto/x509/x509_vfy.c'; text=p.read_text()
old=('void *X509_STORE_CTX_get_ex_data(const X509_STORE_CTX *ctx, int idx)\n'
     '{\n'
     '    return CRYPTO_get_ex_data(&ctx->ex_data, idx);\n'
     '}')
new=(old+'\n\n'
     'void ossl_x509_store_ctx_set_signature_timing(\n'
     '    X509_STORE_CTX *ctx, const OSSL_MTC_X509_TIMING *timing)\n'
     '{\n'
     '    if (ctx == NULL)\n'
     '        return;\n'
     '    if (timing == NULL)\n'
     '        memset(&ctx->mtc_signature_timing, 0,\n'
     '            sizeof(ctx->mtc_signature_timing));\n'
     '    else\n'
     '        ctx->mtc_signature_timing = *timing;\n'
     '}')
text=once(text, old, new)
text=once(text, 'CB_FAIL_IF(X509_verify(xs, pkey) <= 0,',
          'CB_FAIL_IF(ossl_x509_verify_with_timing(\n'
          '                    xs, pkey, &ctx->mtc_signature_timing) <= 0,')
text=once(text,
          '    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509_STORE_CTX, ctx, '
          '&(ctx->ex_data));\n'
          '    memset(&ctx->ex_data, 0, sizeof(ctx->ex_data));',
          '    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_X509_STORE_CTX, ctx, '
          '&(ctx->ex_data));\n'
          '    memset(&ctx->ex_data, 0, sizeof(ctx->ex_data));\n'
          '    memset(&ctx->mtc_signature_timing, 0,\n'
          '        sizeof(ctx->mtc_signature_timing));')
p.write_text(text)

def function(text,name):
    import re
    match=re.search(r'^(?:static )?(?:int|MSG_PROCESS_RETURN) '+name+r'\([^;{]*\)\s*\{',text,re.M)
    if not match: raise SystemExit('Native component function not found: '+name)
    brace=text.index('{',match.start())
    masked=re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',lambda m:' '*len(m.group()),text,flags=re.S)
    depth=1; end=brace+1
    while depth:
        if masked[end]=='{': depth+=1
        if masked[end]=='}': depth-=1
        end+=1
    return match.start(),brace,end

def wrap(text,name,args,ssl,component,authentication_begin=False,
         authentication_end=False,credential_validation=False):
    start,brace,end=function(text,name); signature=text[start:brace].strip()
    kind=signature.removeprefix('static ').split(' ',1)[0]
    implementation=signature.replace(name+'(',name+'_native_impl(',1)
    if not implementation.startswith('static '): implementation='static '+implementation
    body=text[brace:end]
    auth_begin=(f'    mtc_native_authentication_begin({ssl});\n'
                if authentication_begin else '')
    auth_end=(f'    mtc_native_authentication_end({ssl});\n'
              if authentication_end else '')
    credential_begin=(f'    mtc_native_credential_validation_begin({ssl});\n'
                      if credential_validation else '')
    credential_end=(f'    mtc_native_credential_validation_end({ssl});\n'
                    if credential_validation else '')
    wrapper=(f'\n{signature}\n{{\n    {kind} result;\n'
             f'{auth_begin}'
             f'{credential_begin}'
             f'    mtc_native_component_begin({ssl}, {component});\n'
             f'    result = {name}_native_impl({args});\n'
             f'    mtc_native_component_end({ssl}, {component});\n'
             f'{credential_end}'
             f'{auth_end}    return result;\n}}')
    return text[:start]+implementation+'\n'+body+wrapper+text[end:]

for filename,name,args,ssl,component,auth_begin,auth_end,credential in (
    ('ssl/ssl_cert.c','ssl_verify_internal','s, sk, rpk','s',
     'MTC_NATIVE_X509_VERIFY',True,True,True),
    ('ssl/statem/statem_lib.c','tls_process_cert_verify','s, pkt','s',
     'MTC_NATIVE_CERTIFICATE_VERIFY',True,True,False)):
    target=source/filename; wrapped=target.read_text()
    prefix='../' if '/statem/' in filename else ''
    wrapped='#include "'+prefix+'native_components.h"\n'+wrapped
    target.write_text(wrap(wrapped,name,args,'SSL_CONNECTION_GET_SSL('+ssl+')',
                           component,auth_begin,auth_end,credential))

# Install borrowed callbacks only for the built-in verifier. A configured
# app_verify_callback remains unmeasured rather than being misattributed.
p=source/'ssl/ssl_cert.c'; text=p.read_text()
text=once(text, '#include "native_components.h"',
          '#include "native_components.h"\n'
          '#include "crypto/native_x509_timing.h"')
old=('    } else {\n'
     '        i = X509_verify_cert(ctx);\n'
     '        /* We treat an error in the same way as a failure to verify */')
new=('    } else {\n'
     '        OSSL_MTC_X509_TIMING timing = {\n'
     '            mtc_native_x509_signature_begin,\n'
     '            mtc_native_x509_signature_end,\n'
     '            SSL_CONNECTION_GET_SSL(s)\n'
     '        };\n\n'
     '        mtc_native_x509_measurement_begin(SSL_CONNECTION_GET_SSL(s));\n'
     '        ossl_x509_store_ctx_set_signature_timing(ctx, &timing);\n'
     '        i = X509_verify_cert(ctx);\n'
     '        ossl_x509_store_ctx_set_signature_timing(ctx, NULL);\n'
     '        mtc_native_x509_measurement_end(SSL_CONNECTION_GET_SSL(s));\n'
     '        /* We treat an error in the same way as a failure to verify */')
text=once(text, old, new)
p.write_text(text)

# Keep the historical whole-function wrapper above, and add one independent
# v2 interval around the effective TLS CertificateVerify primitive. The exact
# anchor is deliberately version-specific so a source drift fails closed.
p=source/'ssl/statem/statem_lib.c'; text=p.read_text()
text=once(text,
          '    j = EVP_DigestVerify(mctx, data, len, hdata, hdatalen);',
          '    mtc_native_crypto_begin(SSL_CONNECTION_GET_SSL(s),\n'
          '                            MTC_NATIVE_CERTIFICATE_VERIFY_CRYPTO);\n'
          '    j = EVP_DigestVerify(mctx, data, len, hdata, hdatalen);\n'
          '    mtc_native_crypto_end(SSL_CONNECTION_GET_SSL(s),\n'
          '                          MTC_NATIVE_CERTIFICATE_VERIFY_CRYPTO);')
p.write_text(text)
p=source/'apps/s_client.c'; text=p.read_text()
text=once(text,'#include "s_apps.h"','#include "s_apps.h"\n#include "native_metrics.h"')
text=once(text,'    OPT_COMMON,','    OPT_COMMON,\n    OPT_NATIVE_METRICS,')
text=once(text,'    { "help", OPT_HELP,','    {"lab_metrics", OPT_NATIVE_METRICS, \'-\', "Emit native TCP and TLS timing"},\n    { "help", OPT_HELP,')
text=once(text,'        case OPT_HELP:','        case OPT_NATIVE_METRICS: native_metrics = 1; break;\n        case OPT_HELP:')
text=once(text,'static int mtc_landmark_mode=0;','static int mtc_landmark_mode=0;\nstatic int native_metrics = 0;')
text=once(text,'SSL_CTX_set_verify(ctx, verify, verify_callback);','if (native_metrics && !mtc_native_metrics_enable(ctx)) goto end;\n    SSL_CTX_set_verify(ctx, verify, verify_callback);')
if 'BIO_do_connect(sbio)' in text:
    raise SystemExit('BIO_do_connect layout requires an explicit native-metrics patch')
text=once(text,'    if (init_client(&sock, host, port, bindhost, bindport, socket_family,','    mtc_native_connect_start(con);\n    if (init_client(&sock, host, port, bindhost, bindport, socket_family,')
text=once(text,'        BIO_printf(bio_err, "connect:errno=%d\\n", get_last_socket_error());','        mtc_native_connect_done(con, 0);\n        BIO_printf(bio_err, "connect:errno=%d\\n", get_last_socket_error());')
text=once(text,'    BIO_printf(bio_c_out, "CONNECTED(%08X)\\n", sock);','    mtc_native_connect_done(con, 1);\n    BIO_printf(bio_c_out, "CONNECTED(%08X)\\n", sock);')
p.write_text(text)
digest=hashlib.sha256()
for name in ('native_metrics.c','native_metrics.h','native_components.c',
             'native_components.h','native_x509_timing.h',
             'patch_native_metrics.py'):
    digest.update(name.encode()+b'\0'+(here/name).read_bytes())
(source/'NATIVE_METRICS_SHA256').write_text(digest.hexdigest()+'\n')
