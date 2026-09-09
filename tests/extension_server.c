/* Test-only peer: deliberately sends arbitrary extension bytes without decoding.
 * Never used by the laboratory server or installed as the openssl executable. */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
static unsigned char payload[2048];
static size_t payload_len;
static int add(SSL *s, unsigned int type, unsigned int context,
               const unsigned char **out, size_t *outlen, X509 *x,
               size_t index, int *alert, void *arg)
{
    (void)s; (void)type; (void)x; (void)alert; (void)arg;
    if (context != SSL_EXT_TLS1_3_CERTIFICATE || index != 0) return 0;
    *out = payload; *outlen = payload_len; return 1;
}
static int parse(SSL *s, unsigned int type, unsigned int context,
                 const unsigned char *in, size_t len, X509 *x,
                 size_t index, int *alert, void *arg)
{
    (void)s; (void)type; (void)x; (void)index; (void)arg;
    *alert = SSL_AD_DECODE_ERROR;
    return context == SSL_EXT_CLIENT_HELLO && len == 1 && in[0] == 1;
}
int main(int argc, char **argv)
{
    FILE *f;
    SSL_CTX *ctx;
    int fd, peer, one = 1;
    struct sockaddr_in address = {0};
    if (argc != 5) return 2;
    signal(SIGPIPE, SIG_IGN);
    f = fopen(argv[4], "rb");
    if (!f) return 2;
    payload_len = fread(payload, 1, sizeof(payload), f);
    if (fgetc(f) != EOF || ferror(f)) { fclose(f); return 2; }
    fclose(f);
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx || !SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)
        || !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION)
        || !SSL_CTX_use_certificate_file(ctx, argv[2], SSL_FILETYPE_PEM)
        || !SSL_CTX_use_PrivateKey_file(ctx, argv[3], SSL_FILETYPE_PEM)
        || !SSL_CTX_check_private_key(ctx)
        || !SSL_CTX_add_custom_ext(ctx, 0xffa5,
                SSL_EXT_TLS_ONLY | SSL_EXT_TLS1_3_ONLY | SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_CERTIFICATE,
                add, NULL, NULL, parse, NULL)) { ERR_print_errors_fp(stderr); return 2; }
    SSL_CTX_set_num_tickets(ctx, 0);
    fd = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET; address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((unsigned short)atoi(argv[1]));
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))
        || bind(fd, (struct sockaddr *)&address, sizeof(address)) || listen(fd, 8)) return 2;
    while ((peer = accept(fd, NULL, NULL)) >= 0) {
        SSL *ssl = SSL_new(ctx);
        if (!ssl || !SSL_set_fd(ssl, peer)) return 2;
        if (SSL_accept(ssl) == 1) {
            char request[2048];
            if (SSL_read(ssl, request, sizeof(request)) > 0) {
                const char response[] = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n";
                SSL_write(ssl, response, sizeof(response) - 1);
                SSL_shutdown(ssl);
            }
        }
        SSL_free(ssl); close(peer);
    }
    close(fd); SSL_CTX_free(ctx); return 0;
}
