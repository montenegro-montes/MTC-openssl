#include "mtc.c"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int main(void){
    MTCConfig *c=OPENSSL_zalloc(sizeof(*c));
    assert(c);

    /* Empty policy revokes nothing. */
    assert(!serial_revoked(c,0));
    assert(!serial_revoked(c,1));
    assert(!serial_revoked(c,UINT64_MAX));

    /* Invalid inclusive ranges are rejected. */
    assert(!mtc_add_revoked_serial_range(NULL,1,2));
    assert(!mtc_add_revoked_serial_range(c,20,10));

    /* Inclusive [10,19], equivalent to draft half-open [10,20). */
    assert(mtc_add_revoked_serial_range(c,10,19));
    assert(!serial_revoked(c,9));
    assert(serial_revoked(c,10));
    assert(serial_revoked(c,19));
    assert(!serial_revoked(c,20));

    /* Single-serial revocation. */
    assert(mtc_add_revoked_serial_range(c,25,25));
    assert(!serial_revoked(c,24));
    assert(serial_revoked(c,25));
    assert(!serial_revoked(c,26));

    /* Multiple, overlapping and adjacent ranges require no normalization. */
    assert(mtc_add_revoked_serial_range(c,30,39));
    assert(mtc_add_revoked_serial_range(c,35,44));
    assert(mtc_add_revoked_serial_range(c,45,49));
    assert(serial_revoked(c,30));
    assert(serial_revoked(c,37));
    assert(serial_revoked(c,44));
    assert(serial_revoked(c,45));
    assert(serial_revoked(c,49));
    assert(!serial_revoked(c,50));

    /* Full uint64 boundary is representable. */
    assert(mtc_add_revoked_serial_range(c,UINT64_MAX-1,UINT64_MAX));
    assert(serial_revoked(c,UINT64_MAX-1));
    assert(serial_revoked(c,UINT64_MAX));

    mtc_free(c);

    /* Capacity is fail-closed: the 65th range is rejected. */
    c=OPENSSL_zalloc(sizeof(*c));
    assert(c);
    for(unsigned i=0;i<MTC_MAX_REVOKED_RANGES;i++)
        assert(mtc_add_revoked_serial_range(
            c,(uint64_t)i*2,(uint64_t)i*2));
    assert(!mtc_add_revoked_serial_range(c,1000,1000));

    mtc_free(c);
    puts("PASS: MTC revoked serial-number ranges");
    return 0;
}
