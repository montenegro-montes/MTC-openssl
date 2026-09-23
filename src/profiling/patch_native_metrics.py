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
for name in ('native_metrics.c','native_metrics.h','patch_native_metrics.py'):
    digest.update(name.encode()+b'\0'+(here/name).read_bytes())
(source/'NATIVE_METRICS_SHA256').write_text(digest.hexdigest()+'\n')
