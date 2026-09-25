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
    s+=f'{name:40} {number+i}\t3_4_0\tEXIST::FUNCTION:\n'
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

# The current MTC source already has native client timing. Keep its option and
# hook; chain endpoint metrics after native timing without changing TLS policy.
shutil.copyfile(here/'metrics.c', source/'apps/metrics.c')
p=source/'apps/build.info'
p.write_text(p.read_text()+'\nSOURCE[openssl]=metrics.c\n')
for app in ('s_client', 's_server'):
    p=source/'apps'/f'{app}.c'
    s=p.read_text()
    s=once(s, '#include "s_apps.h"', '#include "s_apps.h"\n#include "ssl/profile.h"')
    if app == 's_client':
        s=once(s, 'if (native_metrics && !mtc_native_metrics_enable(ctx)) goto end;',
               'if (native_metrics && !mtc_native_metrics_enable(ctx)) goto end;\n'
               '    if (native_metrics && !lab_metrics_enable(ctx)) goto end;')
        s=once(s, '    mtc_native_connect_start(con);',
               '    lab_metrics_connect_start(con);\n    mtc_native_connect_start(con);')
        s=once(s, '        mtc_native_connect_done(con, 0);',
               '        lab_metrics_connect_done(con, 0);\n        mtc_native_connect_done(con, 0);')
        s=once(s, '    mtc_native_connect_done(con, 1);',
               '    lab_metrics_connect_done(con, 1);\n    mtc_native_connect_done(con, 1);')
    else:
        s=once(s, '    OPT_COMMON,', '    OPT_COMMON,\n    OPT_PROFILE_METRICS,')
        s=once(s, 'static int mtc_landmark_mode=0;',
               'static int mtc_landmark_mode=0;\nstatic int profile_metrics=0;')
        s=once(s, '    { "help", OPT_HELP,',
               '    {"lab_metrics", OPT_PROFILE_METRICS, \'-\', "Emit endpoint and component metrics"},\n'
               '    { "help", OPT_HELP,')
        s=once(s, '        case OPT_HELP:',
               '        case OPT_PROFILE_METRICS: profile_metrics=1; break;\n        case OPT_HELP:')
        s=once(s, '    SSL_CTX_set_verify(ctx, s_server_verify, verify_callback);',
               '    if (profile_metrics && !lab_metrics_enable(ctx)) goto end;\n'
               '    SSL_CTX_set_verify(ctx, s_server_verify, verify_callback);')
    p.write_text(s)
h=hashlib.sha256()
for name in ('profile.c', 'profile.h', 'metrics.c', 'patch_profile_metrics.py'):
    h.update(name.encode()+b'\0'+(here/name).read_bytes())
(source/'PROFILE_SHA256').write_text(h.hexdigest()+'\n')
