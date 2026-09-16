"""Small deterministic C checks of native timing and emitted JSON; no network."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
PREFIX = Path(os.environ.get('OPENSSL_PREFIX', '/opt/homebrew/opt/openssl@3'))

class NativeTimingTest(unittest.TestCase):
    def test_native_boundaries_and_failure_json(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            (temp/'ssl').mkdir()
            (temp/'ssl/profile.h').symlink_to(HERE/'profile.h')
            harness = r'''
#include <assert.h>
#include <openssl/ssl.h>
#include <time.h>
static double fake_ms;
static int connect_result = 1;
static int fake_clock(clockid_t id, struct timespec *t) {
    double value = id == CLOCK_MONOTONIC ? fake_ms : 0;
    t->tv_sec=(time_t)(value/1000); t->tv_nsec=(long)((value-t->tv_sec*1000)*1000000); return 0;
}
static int fake_connect(BIO *bio) { (void)bio; fake_ms += 3; return connect_result; }
#define clock_gettime fake_clock
#undef BIO_do_connect
#define BIO_do_connect(bio) fake_connect(bio)
#include "metrics.c"
#undef clock_gettime
static SSL *connection(SSL_CTX *ctx) {
    SSL *s=SSL_new(ctx); assert(s); SSL_set_bio(s,BIO_new(BIO_s_mem()),BIO_new(BIO_s_mem())); return s;
}
int main(void) {
    SSL_CTX *ctx=SSL_CTX_new(TLS_client_method()); assert(ctx && lab_metrics_enable(ctx));
    SSL *s=connection(ctx); fake_ms=10; assert(lab_metrics_connect(s,NULL)==1);
    Metrics *m=get(s); assert(m->connect_start==10 && m->connect_wall==3 && !m->establishment_done);
    fake_ms=20; info(s,SSL_CB_HANDSHAKE_START,1); assert(m->connect_start==10 && m->wall==20);
    fake_ms=30; info(s,SSL_CB_HANDSHAKE_DONE,1);
    assert(m->connect_wall==3 && m->establishment_wall==20);
    assert(m->establishment_wall != m->connect_wall + 10); SSL_free(s);
    s=connection(ctx); assert(!get(s)->connect_attempted); connect_result=0; fake_ms=40;
    assert(lab_metrics_connect(s,NULL)==0 && !get(s)->connect_ok && !get(s)->establishment_done); SSL_free(s);
    s=connection(ctx); connect_result=1; fake_ms=50; assert(lab_metrics_connect(s,NULL)==1);
    fake_ms=60; info(s,SSL_CB_HANDSHAKE_START,1);
    assert(get(s)->connect_ok && !get(s)->establishment_done); SSL_free(s); SSL_CTX_free(ctx); return 0;
}
'''
            (temp/'test.c').write_text(harness)
            command=['cc','-Wall','-Wextra','-Werror','-I'+str(PREFIX/'include'),'-I'+str(HERE),'-I'+str(HERE.parent/'compact'),'-I'+str(temp),str(temp/'test.c'),str(HERE/'profile.c'),'-L'+str(PREFIX/'lib'),'-lssl','-lcrypto','-o',str(temp/'test')]
            subprocess.run(command,check=True)
            result=subprocess.run([str(temp/'test')],check=True,capture_output=True,text=True)
            records=[json.loads(line.split(' ',1)[1]) for line in result.stderr.splitlines() if line.startswith('NATIVE_CONNECTION_METRICS ')]
            self.assertEqual(records,[{'tcp_connect_wall_ms_native':3,'connection_establishment_wall_ms_native':20},{'tcp_connect_wall_ms_native':None,'connection_establishment_wall_ms_native':None},{'tcp_connect_wall_ms_native':3,'connection_establishment_wall_ms_native':None}])
            profile=[json.loads(line.split(' ',1)[1]) for line in result.stderr.splitlines() if line.startswith('PROFILE_METRICS ')][0]
            self.assertEqual(profile['handshake_wall_ms'],10)
            self.assertEqual(profile['connection_establishment_wall_ms_native'],20)

if __name__ == '__main__':
    unittest.main()
