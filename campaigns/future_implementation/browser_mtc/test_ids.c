/* ID construction only. Include the matching local verifier implementation. */
#include "mtc.c"
#include <assert.h>
static void expect(const unsigned char *actual,size_t n,const char *text){
    unsigned char expected[80];size_t size;
    assert(id_encode(text,expected,&size));assert(n==size&&!memcmp(actual,expected,n));
}
int main(void){
    MTCConfig c={0};strcpy(c.caid,"32473.101");c.log=1;c.number=1;
    assert(config_signals(&c));
    expect(c.signal,c.signal_len,"32473.101");
    expect(c.request_signal,c.request_signal_len,"32473.101");
    c.landmark=1;assert(config_signals(&c));
    expect(c.signal,c.signal_len,"32473.101.1.1.1");
    expect(c.request_signal,c.request_signal_len,"32473.101.2.1.1");
    c.log=7;c.number=129;assert(config_signals(&c));
    expect(c.signal,c.signal_len,"32473.101.1.7.129");
    expect(c.request_signal,c.request_signal_len,"32473.101.2.7.129");
    c.number=0;assert(!config_signals(&c));
    puts("PASS: CA, individual landmark and group ID construction");return 0;
}
