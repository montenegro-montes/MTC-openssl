"""Raise the OpenSSL s_client certificate-list limit for controlled experiments.

OpenSSL defaults to a 100 KiB maximum received certificate list.
Large post-quantum chains, particularly SLH-DSA-256s at higher chain
depths, can legitimately exceed that value.

The experimental limit is applied uniformly to every s_client built
from this OpenSSL source tree.
"""

from pathlib import Path
import sys


EXPERIMENT_MAX_CERT_LIST = 512 * 1024


def replace_once(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"Expected exactly one patch anchor, found {count}: {old!r}"
        )
    return text.replace(old, new, 1)


if len(sys.argv) != 2:
    raise SystemExit(
        "usage: patch_max_cert_list.py <openssl-source-directory>"
    )

source = Path(sys.argv[1])
path = source / "apps" / "s_client.c"

if not path.is_file():
    raise SystemExit(f"OpenSSL s_client source not found: {path}")

text = path.read_text()

text = replace_once(
    text,
    '#include "s_apps.h"\n',
    '#include "s_apps.h"\n'
    '\n'
    '/* Controlled experiment: permit large PQ certificate chains. */\n'
    '#define EXPERIMENT_MAX_CERT_LIST (512 * 1024)\n',
)

old = """    ctx = SSL_CTX_new_ex(app_get0_libctx(), app_get0_propq(), meth);
    if (ctx == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    SSL_CTX_clear_mode(ctx, SSL_MODE_AUTO_RETRY);
"""

new = """    ctx = SSL_CTX_new_ex(app_get0_libctx(), app_get0_propq(), meth);
    if (ctx == NULL) {
        ERR_print_errors(bio_err);
        goto end;
    }

    /*
     * Apply the same receive limit to every experimental scenario.
     * OpenSSL's default 100 KiB certificate-list limit is too small
     * for some deep post-quantum certificate chains.
     */
    SSL_CTX_set_max_cert_list(ctx, EXPERIMENT_MAX_CERT_LIST);

    SSL_CTX_clear_mode(ctx, SSL_MODE_AUTO_RETRY);
"""

text = replace_once(text, old, new)

path.write_text(text)

(source / "EXPERIMENT_MAX_CERT_LIST_BYTES").write_text(
    f"{EXPERIMENT_MAX_CERT_LIST}\n"
)

print(
    f"Patched {path}: "
    f"EXPERIMENT_MAX_CERT_LIST={EXPERIMENT_MAX_CERT_LIST} bytes"
)