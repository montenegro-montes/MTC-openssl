#!/usr/bin/env python3

from pathlib import Path
import hashlib
import sys


def once(text, old, new):
    if text.count(old) != 1:
        raise SystemExit(
            f"Expected exactly one anchor, found {text.count(old)}:\n{old}"
        )
    return text.replace(old, new, 1)


if len(sys.argv) != 2:
    raise SystemExit(
        "usage: patch_mutual_metrics.py /path/to/apps/metrics.c"
    )

path = Path(sys.argv[1])

if not path.is_file():
    raise SystemExit(f"missing metrics source: {path}")

original = path.read_text()

text = original


# ------------------------------------------------------------
# 1. Extend per-connection state.
#
# Legacy:
#   certificate -> server Certificate
#   cv          -> server CertificateVerify
#
# New fields explicitly distinguish both authentication sides.
# ------------------------------------------------------------

text = once(
    text,
    "    uint64_t read0, written0, hs_read, hs_written, certificate, cv, extensions;\n",
    """    uint64_t read0, written0, hs_read, hs_written, certificate, cv, extensions;
    uint64_t server_certificate, client_certificate;
    uint64_t server_cv, client_cv;
"""
)


# ------------------------------------------------------------
# 2. Extend PROFILE_METRICS JSON.
# ------------------------------------------------------------

text = once(
    text,
    '''            "\\"certificate_message_bytes\\":%llu,\\"certificate_verify_message_bytes\\":%llu,\\"encrypted_extensions_bytes\\":%llu,"
''',
    '''            "\\"certificate_message_bytes\\":%llu,\\"certificate_verify_message_bytes\\":%llu,\\"encrypted_extensions_bytes\\":%llu,"
            "\\"server_certificate_message_bytes\\":%llu,\\"client_certificate_message_bytes\\":%llu,"
            "\\"server_certificate_verify_message_bytes\\":%llu,\\"client_certificate_verify_message_bytes\\":%llu,"
'''
)

text = once(
    text,
    '''            (unsigned long long)m->certificate,(unsigned long long)m->cv,(unsigned long long)m->extensions,
            SSL_session_reused(ssl),SSL_get_negotiated_server_cert_type(ssl));
''',
    '''            (unsigned long long)m->certificate,(unsigned long long)m->cv,(unsigned long long)m->extensions,
            (unsigned long long)m->server_certificate,(unsigned long long)m->client_certificate,
            (unsigned long long)m->server_cv,(unsigned long long)m->client_cv,
            SSL_session_reused(ssl),SSL_get_negotiated_server_cert_type(ssl));
'''
)


# ------------------------------------------------------------
# 3. Reset all counters at handshake start.
# ------------------------------------------------------------

text = once(
    text,
    '''        m->hs_read=m->hs_written=m->certificate=m->cv=m->extensions=0;
''',
    '''        m->hs_read=m->hs_written=m->certificate=m->cv=m->extensions=0;
        m->server_certificate=m->client_certificate=0;
        m->server_cv=m->client_cv=0;
'''
)


# ------------------------------------------------------------
# 4. Count Certificate / CertificateVerify by authentication
#    direction.
#
# Keep legacy certificate/cv semantics unchanged:
# they still represent the server's messages.
# ------------------------------------------------------------

text = once(
    text,
    '''    /* Count the server's messages at both endpoints, for a consistency check. */
    if ((write && SSL_is_server(ssl)) || (!write && !SSL_is_server(ssl))) {
        if (p[0]==SSL3_MT_CERTIFICATE) m->certificate+=len;
        if (p[0]==SSL3_MT_CERTIFICATE_VERIFY) m->cv+=len;
        if (p[0]==SSL3_MT_ENCRYPTED_EXTENSIONS) m->extensions+=len;
    }
''',
    '''    /*
     * Count both authentication directions at both endpoints.
     *
     * Legacy certificate/cv retain their original meaning:
     * server Certificate and server CertificateVerify.
     */
    {
        int server_message =
            (write && SSL_is_server(ssl))
            || (!write && !SSL_is_server(ssl));

        int client_message =
            (write && !SSL_is_server(ssl))
            || (!write && SSL_is_server(ssl));

        if (server_message) {
            if (p[0]==SSL3_MT_CERTIFICATE) {
                m->certificate+=len;
                m->server_certificate+=len;
            }

            if (p[0]==SSL3_MT_CERTIFICATE_VERIFY) {
                m->cv+=len;
                m->server_cv+=len;
            }

            if (p[0]==SSL3_MT_ENCRYPTED_EXTENSIONS)
                m->extensions+=len;
        }

        if (client_message) {
            if (p[0]==SSL3_MT_CERTIFICATE)
                m->client_certificate+=len;

            if (p[0]==SSL3_MT_CERTIFICATE_VERIFY)
                m->client_cv+=len;
        }
    }
'''
)


path.write_text(text)

print("patched:", path)
print("original_sha256:", hashlib.sha256(original.encode()).hexdigest())
print("patched_sha256: ", hashlib.sha256(text.encode()).hexdigest())
