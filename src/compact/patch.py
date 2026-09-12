from pathlib import Path
import shutil
import sys
import hashlib
source = Path(sys.argv[1]); here = Path(__file__).resolve().parent

def change(s, old, new):
    if s.count(old) != 1:
        raise SystemExit(f'Unexpected OpenSSL source at {old!r}')
    return s.replace(old, new, 1)

for app in ['s_client', 's_server']:
    p = source / 'apps' / (app + '.c'); s = p.read_text()
    s = change(s, '#include "mt_tls.h"', '#include "mt_tls.h"\n#include "compact.h"\nstatic const char *compact_a = NULL, *compact_b = NULL;\nstatic int compact_mode = 0;')
    enum = '    OPT_COMPACT_A, OPT_COMPACT_B,' + (' OPT_COMPACT_COLD, OPT_LAB_METRICS,' if app == 's_client' else '') + '\n'
    s = change(s, '    OPT_COMMON,', '    OPT_COMMON,\n' + enum)
    names = ['compact_authority', 'compact_root'] if app == 's_client' else ['compact_bundle', 'compact_signed_root']
    opts = ''.join(f'    {{"{name}", OPT_COMPACT_{letter}, \'<\', "Compact Merkle {name} file"}},\n' for name, letter in zip(names, ['A','B']))
    if app == 's_client':
        opts += '    {"compact_cold", OPT_COMPACT_COLD, \'-\', "Receive and verify signed root in handshake"},\n    {"lab_metrics", OPT_LAB_METRICS, \'-\', "Emit handshake metrics (not compatible with -msg/-trace)"},\n'
        s = change(s, 'static int compact_mode = 0;', 'static int compact_mode = 0, metrics_mode = 0;')
    s = change(s, '    { "help", OPT_HELP,', opts + '    { "help", OPT_HELP,')
    cases = '        case OPT_COMPACT_A: compact_a = opt_arg(); break;\n        case OPT_COMPACT_B: compact_b = opt_arg(); break;\n'
    if app == 's_client':
        cases += '        case OPT_COMPACT_COLD: compact_mode = 1; break;\n        case OPT_LAB_METRICS: metrics_mode = 1; break;\n'
        code = '''    if (compact_a || compact_b || compact_mode) {
        if (!compact_a || (compact_mode && compact_b) || (!compact_mode && !compact_b)
            || mt_file || mt_incompatible) {
            BIO_printf(bio_err, "Compact mode incompatible options or missing authority/root\\n"); goto end;
        }
        if (!compact_client(ctx, compact_a, compact_b)) goto end;
        enable_server_rpk = 1;
    }
    if (metrics_mode && c_msg) {
        BIO_printf(bio_err, "-lab_metrics cannot be combined with -msg or -trace\\n"); goto end;
    }
    if (metrics_mode && !lab_metrics_enable(ctx)) goto end;

'''
        s = change(s, '    con = SSL_new(ctx);', code + '    con = SSL_new(ctx);')
    else:
        s = s.replace('static int compact_mode = 0;', '')
        code = '''    if (compact_a || compact_b) {
        if (!compact_a || !compact_b || mt_file || mt_incompatible || ctx2) {
            BIO_printf(bio_err, "Compact mode incompatible options or missing bundle/root\\n"); goto end;
        }
        if (!compact_server(ctx, compact_a, compact_b)) goto end;
    }

'''
        s = change(s, '    SSL_CTX_set_verify(ctx, s_server_verify, verify_callback);', code + '    SSL_CTX_set_verify(ctx, s_server_verify, verify_callback);')
    s = change(s, '        case OPT_HELP:', cases + '        case OPT_HELP:')
    p.write_text(s)
for name in ['compact.c', 'compact.h', 'metrics.c']:
    shutil.copyfile(here / name, source / 'apps' / name)
p = source / 'apps/build.info'; p.write_text(p.read_text() + '\nSOURCE[openssl]=compact.c metrics.c\n')
h = hashlib.sha256()
for p in sorted(here.glob('*')):
    if p.is_file(): h.update(p.name.encode() + b'\0' + p.read_bytes())
(source / 'COMPACT_SHA256').write_text(h.hexdigest() + '\n')
