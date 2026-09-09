#include "profile.h"
#include <assert.h>
#include <stdio.h>
int main(void) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    SSL *ssl = SSL_new(ctx);
    double w[PROFILE_COUNT], c[PROFILE_COUNT];
    unsigned long n[PROFILE_COUNT];
    assert(ctx && ssl && SSL_profile_reset(ssl, 1));
    SSL_profile_begin(ssl, P_PROOF);
    assert(!SSL_profile_snapshot(ssl,w,c,n,PROFILE_COUNT));
    SSL_profile_begin(ssl, P_PROOF);
    SSL_profile_end(ssl, P_PROOF);
    SSL_profile_end(ssl, P_PROOF);
    assert(SSL_profile_snapshot(ssl,w,c,n,PROFILE_COUNT));
    assert(n[P_PROOF] == 2 && w[P_PROOF] >= 0 && c[P_PROOF] >= 0);
    SSL_profile_end(ssl, P_PROOF);
    assert(!SSL_profile_snapshot(ssl,w,c,n,PROFILE_COUNT));
    assert(SSL_profile_reset(ssl, 0));
    SSL_profile_begin(ssl, P_PROOF); SSL_profile_end(ssl, P_PROOF);
    assert(SSL_profile_snapshot(ssl,w,c,n,PROFILE_COUNT));
    for (int i=0;i<PROFILE_COUNT;i++) assert(n[i]==0 && w[i]==0 && c[i]==0);
    SSL_free(ssl); SSL_CTX_free(ctx);
    puts("Profile timer state: PASS");
    return 0;
}
