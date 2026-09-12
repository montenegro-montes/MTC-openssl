/* Include implementation to exercise its private, bounded wire decoders. */
#include "compact.c"
#include <assert.h>
int main(int argc, char **argv)
{
    unsigned char buf[MAX_PAYLOAD], bad[MAX_PAYLOAD + 1]; size_t n, rootlen;
    const unsigned char *root; State s;
    assert(argc == 2 && mt_read_file(argv[1], buf, sizeof(buf), &n));
    assert(bundle_decode(buf, n, &s, &root, &rootlen) && rootlen == 0);
    for (size_t i = 0; i < n; i++) assert(!bundle_decode(buf, i, &s, &root, &rootlen));
    memcpy(bad, buf, n); bad[n] = 0;
    assert(!bundle_decode(bad, n + 1, &s, &root, &rootlen));
    /* Fuzz arbitrary lengths/bytes and exercise successful decodes safely. */
    uint32_t value = 42;
    Config c = {0}; strcpy(c.hostname, "server");
    for (unsigned int i = 0; i < 20000; i++) {
        size_t len = i % (MAX_PAYLOAD + 1);
        for (size_t j = 0; j < len; j++) { value = value * 1664525u + 1013904223u; bad[j] = (unsigned char)(value >> 24); }
        if (bundle_decode(bad, len, &s, &root, &rootlen))
            assert(!credential_verify(&c, &s, NULL));
    }
    assert(dns_name((const unsigned char *)"server", 6));
    assert(!dns_name((const unsigned char *)"-bad", 4));
    assert(!dns_name((const unsigned char *)"bad.", 4));
    assert(!dns_name((const unsigned char *)"Bad", 3));
    assert(!dns_name((const unsigned char *)"*.lab", 5));
    puts("Compact parser: PASS (truncations, trailing bytes, 20000 deterministic fuzz inputs)");
}
