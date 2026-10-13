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

    declarations = (
        '#include "mt_tls.h"\n'
        '#include "mtc.h"\n'
        'static const char *mtc_file=NULL;\n'
        'static const char *mtc_ca=NULL;\n'
        'static const char *mtc_ca_root=NULL;\n'
        'static int mtc_landmark_mode=0;'
    )
    if app=='s_server':
        declarations += '\nstatic const char *mtc_client_trust=NULL;'
    else:
        declarations += (
            '\nstatic const char *mtc_client_id=NULL;'
            '\nstatic const char *mtc_trusted_subtrees=NULL;'
        )

    s=once(s,'#include "mt_tls.h"',declarations)

    enums=('    OPT_COMMON,\n    OPT_MTC_CONFIG, OPT_MTC_CA, '
           'OPT_MTC_CA_ROOT, OPT_MTC_LANDMARK,')
    if app=='s_server':
        enums += ' OPT_MTC_CLIENT_TRUST,'
    else:
        enums += ' OPT_MTC_CLIENT_ID, OPT_MTC_TRUSTED_SUBTREES,'
    s=once(s,'    OPT_COMMON,',enums)

    opt='mtc_trust' if app=='s_client' else 'mtc_id'
    options=(
        f'    {{"{opt}", OPT_MTC_CONFIG, \'s\', "MTC-experimental trust config or server trust anchor ID"}},\n'
        '    {"mtc_ca", OPT_MTC_CA, \'s\', "MTC-07 certification authority certificate"},\n'
        '    {"mtc_ca_root", OPT_MTC_CA_ROOT, \'s\', "Trusted MTC representation root certificate"},\n'
        '    {"mtc_landmark", OPT_MTC_LANDMARK, \'-\', "Require MTC-experimental landmark certificate"},\n'
    )
    if app=='s_server':
        options += (
            '    {"mtc_client_trust", OPT_MTC_CLIENT_TRUST, \'s\', '
            '"MTC-experimental trust config for client authentication"},\n'
        )
    else:
        options += (
            '    {"mtc_client_id", OPT_MTC_CLIENT_ID, \'s\', '
            '"MTC-experimental client credential ID"},\n'
            '    {"mtc_trusted_subtrees", OPT_MTC_TRUSTED_SUBTREES, \'s\', '
            '"Load validated MTS1 trusted-subtree configuration"},\n'
        )
    s=once(s,'    { "help", OPT_HELP,',options+'    { "help", OPT_HELP,')

    cases=(
        '        case OPT_MTC_CONFIG: mtc_file=opt_arg(); break;\n'
        '        case OPT_MTC_CA: mtc_ca=opt_arg(); break;\n'
        '        case OPT_MTC_CA_ROOT: mtc_ca_root=opt_arg(); break;\n'
        '        case OPT_MTC_LANDMARK: mtc_landmark_mode=1; break;\n'
    )
    if app=='s_server':
        cases += '        case OPT_MTC_CLIENT_TRUST: mtc_client_trust=opt_arg(); break;\n'
    else:
        cases += (
            '        case OPT_MTC_CLIENT_ID: mtc_client_id=opt_arg(); break;\n'
            '        case OPT_MTC_TRUSTED_SUBTREES: '
            'mtc_trusted_subtrees=opt_arg(); break;\n'
        )
    s=once(s,'        case OPT_HELP:',cases+'        case OPT_HELP:')

    if app=='s_client':
        # A locally presented MTC certificate must install the MTC security
        # callback before set_cert_key_stuff() calls SSL_CTX_use_certificate().
        cert_anchor='    if (!set_cert_key_stuff(ctx, cert, key, chain, build_chain))'
        cert_code='''    if (mtc_client_id) {
        if (mt_file || mt_incompatible || enable_server_rpk
            || !mtc_client_present(ctx,mtc_client_id,mtc_landmark_mode)) {
            BIO_printf(bio_err,"MTC-experimental configuration rejected\\n"); goto end;
        }
    }
'''
        s=once(s,cert_anchor,cert_code+cert_anchor)

        anchor='    con = SSL_new(ctx);'
        code='''    if (mtc_file || mtc_ca || mtc_ca_root || mtc_trusted_subtrees
        || (mtc_landmark_mode && !mtc_client_id)) {
        if (!mtc_file || !mtc_ca || !mtc_ca_root
            || mt_file || mt_incompatible || enable_server_rpk
            || (mtc_trusted_subtrees && !mtc_landmark_mode)
            || !mtc_client(ctx,mtc_file,mtc_landmark_mode,
                           mtc_trusted_subtrees,mtc_ca,mtc_ca_root)) {
            BIO_printf(bio_err,"MTC-experimental configuration rejected\\n"); goto end;
        }
    }
'''
    else:
        # s_server later calls SSL_CTX_set_verify(ctx, s_server_verify, ...).
        # When MTC client authentication is enabled, force that normal
        # s_server configuration to request and require a client certificate.
        verify_anchor='    SSL_CTX_set_verify(ctx, s_server_verify, verify_callback);'
        verify_code='''    if (mtc_client_trust)
        s_server_verify = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
'''
        s=once(s,verify_anchor,verify_code+verify_anchor)

        anchor='    if (!set_cert_key_stuff(ctx, s_cert, s_key, s_chain, build_chain))'
        code='''    if (mtc_file || mtc_client_trust || mtc_ca || mtc_ca_root || mtc_landmark_mode) {
        if ((!mtc_file && !mtc_client_trust)
            || mt_file || mt_incompatible || enable_server_rpk || ctx2
            || ((mtc_ca || mtc_ca_root) && !mtc_client_trust)
            || (mtc_client_trust && (!mtc_ca || !mtc_ca_root))
            || (mtc_file && !mtc_server(ctx,mtc_file))
            || (mtc_client_trust && !mtc_server_verify_client(
                    ctx,mtc_client_trust,mtc_landmark_mode,mtc_ca,mtc_ca_root))) {
            BIO_printf(bio_err,"MTC-experimental configuration rejected\\n"); goto end;
        }
    }
'''

    s=once(s,anchor,code+anchor)
    p.write_text(s)
h=hashlib.sha256()
for p in sorted(here.glob('*')):
    if p.is_file():h.update(p.name.encode()+b'\0'+p.read_bytes())
(root/'MTC_SHA256').write_text(h.hexdigest()+'\n')
