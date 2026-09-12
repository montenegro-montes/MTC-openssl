from pathlib import Path
import sys,shutil,hashlib
root=Path(sys.argv[1]);here=Path(__file__).resolve().parent

def once(s,a,b):
    if s.count(a)!=1:raise ValueError('Source drift: '+a)
    return s.replace(a,b,1)
for name in ['mtc.h','mtc.c','tls.c']:shutil.copyfile(here/name,root/'apps'/('mtc_tls.c' if name=='tls.c' else name))
p=root/'apps/build.info';p.write_text(p.read_text()+'\nSOURCE[openssl]=mtc_tls.c\n')
for app in ['s_client','s_server']:
    p=root/'apps'/f'{app}.c';s=p.read_text()
    s=once(s,'#include "compact.h"','#include "compact.h"\n#include "mtc.h"\nstatic const char *mtc_file=NULL;\nstatic int mtc_landmark_mode=0;')
    s=once(s,'    OPT_COMMON,','    OPT_COMMON,\n    OPT_MTC_CONFIG, OPT_MTC_LANDMARK,')
    opt='mtc_trust' if app=='s_client' else 'mtc_id'
    s=once(s,'    { "help", OPT_HELP,',f'    {{"{opt}", OPT_MTC_CONFIG, \'s\', "MTC-experimental trust config or server trust anchor ID"}},\n    {{"mtc_landmark", OPT_MTC_LANDMARK, \'-\', "Require MTC-experimental landmark certificate"}},\n    {{ "help", OPT_HELP,')
    s=once(s,'        case OPT_HELP:','        case OPT_MTC_CONFIG: mtc_file=opt_arg(); break;\n        case OPT_MTC_LANDMARK: mtc_landmark_mode=1; break;\n        case OPT_HELP:')
    if app=='s_client':
        anchor='    con = SSL_new(ctx);'
        code='''    if (mtc_file || mtc_landmark_mode) {
        if (!mtc_file || mt_file || compact_a || compact_b || compact_mode || mt_incompatible || enable_server_rpk
            || !mtc_client(ctx,mtc_file,mtc_landmark_mode)) {
            BIO_printf(bio_err,"MTC-experimental configuration rejected\\n"); goto end;
        }
    }
'''
    else:
        anchor='    if (!set_cert_key_stuff(ctx, s_cert, s_key, s_chain, build_chain))'
        code='''    if (mtc_file || mtc_landmark_mode) {
        if (!mtc_file || mt_file || compact_a || compact_b || mt_incompatible || enable_server_rpk || ctx2
            || !mtc_server(ctx,mtc_file)) {
            BIO_printf(bio_err,"MTC-experimental configuration rejected\\n"); goto end;
        }
    }
'''
    s=once(s,anchor,code+anchor);p.write_text(s)
h=hashlib.sha256()
for p in sorted(here.glob('*')):
    if p.is_file():h.update(p.name.encode()+b'\0'+p.read_bytes())
(root/'MTC_SHA256').write_text(h.hexdigest()+'\n')
