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
exports=source/'util/libssl.num'; export_text=exports.read_text()
number=max(int(line.split()[1]) for line in export_text.splitlines()
           if line.strip() and not line.startswith('#'))
for offset,name in enumerate(('mtc_native_components_reset',
                              'mtc_native_component_begin',
                              'mtc_native_component_end',
                              'mtc_native_authentication_begin',
                              'mtc_native_authentication_end',
                              'mtc_native_components_snapshot',
                              'mtc_native_authentication_snapshot'),1):
    export_text+=f'{name:40} {number+offset}\t3_4_0\tEXIST::FUNCTION:\n'
exports.write_text(export_text)

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
         authentication_end=False):
    start,brace,end=function(text,name); signature=text[start:brace].strip()
    kind=signature.removeprefix('static ').split(' ',1)[0]
    implementation=signature.replace(name+'(',name+'_native_impl(',1)
    if not implementation.startswith('static '): implementation='static '+implementation
    body=text[brace:end]
    auth_begin=(f'    mtc_native_authentication_begin({ssl});\n'
                if authentication_begin else '')
    auth_end=(f'    mtc_native_authentication_end({ssl});\n'
              if authentication_end else '')
    wrapper=(f'\n{signature}\n{{\n    {kind} result;\n'
             f'{auth_begin}'
             f'    mtc_native_component_begin({ssl}, {component});\n'
             f'    result = {name}_native_impl({args});\n'
             f'    mtc_native_component_end({ssl}, {component});\n'
             f'{auth_end}    return result;\n}}')
    return text[:start]+implementation+'\n'+body+wrapper+text[end:]

for filename,name,args,ssl,component,auth_begin,auth_end in (
    ('ssl/ssl_cert.c','ssl_verify_internal','s, sk, rpk','s',
     'MTC_NATIVE_X509_VERIFY',True,True),
    ('ssl/statem/statem_lib.c','tls_process_cert_verify','s, pkt','s',
     'MTC_NATIVE_CERTIFICATE_VERIFY',True,True)):
    target=source/filename; wrapped=target.read_text()
    prefix='../' if '/statem/' in filename else ''
    wrapped='#include "'+prefix+'native_components.h"\n'+wrapped
    target.write_text(wrap(wrapped,name,args,'SSL_CONNECTION_GET_SSL('+ssl+')',
                           component,auth_begin,auth_end))
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
for name in ('native_metrics.c','native_metrics.h','native_components.c','native_components.h','patch_native_metrics.py'):
    digest.update(name.encode()+b'\0'+(here/name).read_bytes())
(source/'NATIVE_METRICS_SHA256').write_text(digest.hexdigest()+'\n')
