"""Apply bounded app-only edits to OpenSSL 3.5.8; fail on source drift."""
from pathlib import Path
import sys
import hashlib
import shutil

source = Path(sys.argv[1])
here = Path(__file__).resolve().parent

def replace_once(text, old, new):
    if text.count(old) != 1:
        raise SystemExit(f'Expected exactly one patch anchor: {old!r}')
    return text.replace(old, new, 1)

for app, option in [('s_client', 'root'), ('s_server', 'proof')]:
    path = source / 'apps' / f'{app}.c'
    text = path.read_text()
    text = replace_once(text, '#include "s_apps.h"', '#include "s_apps.h"\n#include "mt_tls.h"\nstatic const char *mt_file = NULL;\nstatic int mt_incompatible = 0;')
    text = replace_once(text, '    OPT_COMMON,', '    OPT_COMMON,\n    OPT_MERKLE,')
    text = replace_once(text, '    { "help", OPT_HELP,', f'    {{ "merkle_{option}", OPT_MERKLE, \'<\', "Experimental TLS 1.3 Merkle {option} file" }},\n    {{ "help", OPT_HELP,')
    text = replace_once(text, '        case OPT_HELP:', '        case OPT_MERKLE:\n            mt_file = opt_arg();\n            break;\n        case OPT_HELP:')
    incompatible = ['PSK', 'PSK_SESS', 'EARLY_DATA', 'ENABLE_SERVER_RPK', 'DTLS', 'DTLS1', 'DTLS1_2', 'TLS1', 'TLS1_1', 'TLS1_2']
    if app == 's_client':
        incompatible += ['SESS_IN', 'RECONNECT', 'ADV', 'QUIC', 'DANE_TLSA_DOMAIN', 'DANE_TLSA_RRDATA', 'DANE_EE_NO_NAME']
    for name in incompatible:
        anchor = f'        case OPT_{name}:'
        text = replace_once(text, anchor, anchor + '\n            mt_incompatible = 1;')
    if app == 's_client':
        code = '''    if (mt_file != NULL) {
        if (mt_incompatible) {
            BIO_printf(bio_err, "Merkle mode requires full TLS 1.3 X.509 handshake; incompatible option\\n");
            goto end;
        }
        verify_args.return_error = 1;
        if (!mt_client_configure(ctx, mt_file))
            goto end;
    }

'''
        text = replace_once(text, '    con = SSL_new(ctx);', code + '    con = SSL_new(ctx);')
    else:
        code = '''    if (mt_file != NULL) {
        if (mt_incompatible || ctx2 != NULL) {
            BIO_printf(bio_err, "Merkle mode requires TLS 1.3 X.509 and a single certificate context\\n");
            goto end;
        }
        if (!mt_server_configure(ctx, mt_file))
            goto end;
    }

'''
        text = replace_once(text, '    SSL_CTX_set_verify(ctx, s_server_verify, verify_callback);', code + '    SSL_CTX_set_verify(ctx, s_server_verify, verify_callback);')
    path.write_text(text)

build = source / 'apps/build.info'
text = build.read_text()
if 'mt_tls.c' in text:
    raise SystemExit('Already patched')
build.write_text(text + '\nSOURCE[openssl]=mt_tls.c mt_wire.c mt_merkle.c\n')
for name in ['mt_tls.c', 'mt_tls.h', 'mt_wire.c', 'mt_wire.h']:
    shutil.copyfile(here / name, source / 'apps' / name)
for src, dst in [('merkle.c', 'mt_merkle.c'), ('merkle.h', 'merkle.h')]:
    shutil.copyfile('/opt/mt/crypto/' + src, source / 'apps' / dst)
# Fingerprint the patch inputs, alongside the unchanged upstream source commit.
hash_value = hashlib.sha256()
for path in sorted(here.glob('*')):
    if path.is_file():
        hash_value.update(path.name.encode() + b'\0' + path.read_bytes())
for path in sorted(Path('/opt/mt/crypto').glob('merkle.*')):
    hash_value.update(path.name.encode() + b'\0' + path.read_bytes())
(source / 'MERKLE_PATCH_SHA256').write_text(hash_value.hexdigest() + '\n')
