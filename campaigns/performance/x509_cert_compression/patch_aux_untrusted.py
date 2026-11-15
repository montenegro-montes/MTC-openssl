"""Add a narrowly scoped untrusted issuer option to the experimental s_client."""

from pathlib import Path
import sys


path = Path(sys.argv[1])
source = path.read_text()


def once(old, new):
    global source
    if source.count(old) != 1:
        raise SystemExit(f"s_client source drift: {old!r}")
    source = source.replace(old, new, 1)


once('#include "s_apps.h"', '#include "s_apps.h"\n#include <openssl/pem.h>')
once('static int mtc_landmark_mode=0;', '''static int mtc_landmark_mode=0;
static const char *verify_untrusted_file = NULL;
static X509 *verify_untrusted_cert = NULL;
static int verify_untrusted_trace = 0;

static int load_verify_untrusted(void)
{
    BIO *input = BIO_new_file(verify_untrusted_file, "r");
    X509 *extra;
    if (input == NULL)
        return 0;
    verify_untrusted_cert = PEM_read_bio_X509(input, NULL, NULL, NULL);
    extra = PEM_read_bio_X509(input, NULL, NULL, NULL);
    BIO_free(input);
    ERR_clear_error(); /* A missing second PEM normally sets PEM_R_NO_START_LINE. */
    if (extra != NULL || verify_untrusted_cert == NULL) {
        X509_free(extra);
        return 0;
    }
    return 1;
}

/* Called before X509_verify_cert, unlike the per-certificate verify callback. */
static int verify_with_untrusted(X509_STORE_CTX *store, void *arg)
{
    X509 *aux = arg;
    STACK_OF(X509) *original = X509_STORE_CTX_get0_untrusted(store);
    STACK_OF(X509) *combined = sk_X509_new_null();
    STACK_OF(X509) *chain;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    int i, ok = 0;
    if (combined == NULL)
        return 0;
    for (i = 0; original != NULL && i < sk_X509_num(original); ++i)
        if (!sk_X509_push(combined, sk_X509_value(original, i)))
            goto done;
    if (!sk_X509_push(combined, aux))
        goto done;
    X509_STORE_CTX_set0_untrusted(store, combined);
    ok = X509_verify_cert(store);
    chain = X509_STORE_CTX_get0_chain(store);
    if (ok != 1 || X509_STORE_CTX_get_error(store) != X509_V_OK
        || chain == NULL || sk_X509_num(chain) != 3
        || X509_cmp(sk_X509_value(chain, 1), aux) != 0) {
        X509_STORE_CTX_set_error(store, X509_V_ERR_APPLICATION_VERIFICATION);
        ok = 0;
    } else if (verify_untrusted_trace) {
        for (i = 0; i < 3; ++i) {
            unsigned int j;
            if (!X509_digest(sk_X509_value(chain, i), EVP_sha256(),
                             digest, &digest_len)) {
                ok = 0;
                break;
            }
            BIO_printf(bio_err, "AUX_VERIFY_CHAIN %d ", i);
            for (j = 0; j < digest_len; ++j)
                BIO_printf(bio_err, "%02x", digest[j]);
            BIO_printf(bio_err, "\\n");
        }
    }
    X509_STORE_CTX_set0_untrusted(store, original);
done:
    sk_X509_free(combined);
    return ok;
}
''')
once('    OPT_MTC_CONFIG,', '    OPT_VERIFY_UNTRUSTED, OPT_VERIFY_UNTRUSTED_TRACE,\n    OPT_MTC_CONFIG,')
once('    { "help", OPT_HELP,',
     '    {"verify_untrusted", OPT_VERIFY_UNTRUSTED, \'s\', '
     '"PEM intermediate for peer chain construction, not a trust anchor"},\n'
     '    {"verify_untrusted_trace", OPT_VERIFY_UNTRUSTED_TRACE, \'-\', '
     '"Log the verified chain SHA-256 hashes"},\n'
     '    { "help", OPT_HELP,')
once('        case OPT_HELP:',
     '        case OPT_VERIFY_UNTRUSTED: verify_untrusted_file = opt_arg(); break;\n'
     '        case OPT_VERIFY_UNTRUSTED_TRACE: verify_untrusted_trace = 1; break;\n'
     '        case OPT_HELP:')
once('    SSL_CTX_set_verify(ctx, verify, verify_callback);', '''    SSL_CTX_set_verify(ctx, verify, verify_callback);
    if (verify_untrusted_file != NULL) {
        if (mtc_file || mtc_ca || mtc_ca_root || !load_verify_untrusted()) {
            BIO_printf(bio_err, "Invalid -verify_untrusted input\\n");
            goto end;
        }
        SSL_CTX_set_cert_verify_callback(ctx, verify_with_untrusted,
                                         verify_untrusted_cert);
    }''')
path.write_text(source)
