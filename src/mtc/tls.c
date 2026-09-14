#include "mtc.c"
#define CONTEXT (SSL_EXT_TLS_ONLY|SSL_EXT_TLS1_3_ONLY|SSL_EXT_CLIENT_HELLO|SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS|SSL_EXT_TLS1_3_CERTIFICATE)
typedef int (*SecurityCallback)(const SSL *,const SSL_CTX *,int,int,int,void *,void *);
typedef struct {SecurityCallback previous_security;MTCConfig *trust;unsigned char id[80],group[80],list[83];size_t n;int server,has_group;} TLSConfig;
typedef struct {int matched,available,confirmed;} TLSState;
static int ci=-1,si=-1;
/* Restricted initial single-log group. id_encode supplies canonical components;
   the preceding termination bit ensures .1.1.1 starts at a component boundary. */
static int initial_group(TLSConfig *c){
    if(c->n<4||(c->id[c->n-4]&0x80)||c->id[c->n-3]!=1||c->id[c->n-2]!=1||c->id[c->n-1]!=1)return 0;
    memcpy(c->group,c->id,c->n);c->group[c->n-3]=2;return 1;
}
static void config_free(void *parent,void *ptr,CRYPTO_EX_DATA *ad,int idx,long l,void *arg){TLSConfig *c=ptr;(void)parent;(void)ad;(void)idx;(void)l;(void)arg;if(c){mtc_free(c->trust);OPENSSL_free(c);}}
static void state_free(void *parent,void *ptr,CRYPTO_EX_DATA *ad,int idx,long l,void *arg){(void)parent;(void)ad;(void)idx;(void)l;(void)arg;OPENSSL_free(ptr);}
static TLSState *state(SSL *ssl){TLSState *s=SSL_get_ex_data(ssl,si);if(!s){s=OPENSSL_zalloc(sizeof(*s));if(s&&!SSL_set_ex_data(ssl,si,s)){OPENSSL_free(s);s=NULL;}}return s;}
static int add(SSL *ssl,unsigned type,unsigned context,const unsigned char **out,size_t *len,X509 *x,size_t chainidx,int *alert,void *arg){
    TLSConfig *c=arg;TLSState *s=state(ssl);(void)type;(void)x;
    if(!s){*alert=SSL_AD_INTERNAL_ERROR;return -1;}
    if(context==SSL_EXT_CLIENT_HELLO){*out=c->list;*len=c->n+3;return 1;}
    if(!s->matched){*alert=SSL_AD_HANDSHAKE_FAILURE;return -1;}
    if(context==SSL_EXT_TLS1_3_CERTIFICATE){if(chainidx)return 0;*out=(const unsigned char *)"";*len=0;return 1;}
    *out=c->list;*len=c->n+3;return 1;
}
static int parse(SSL *ssl,unsigned type,unsigned context,const unsigned char *in,size_t n,X509 *x,size_t chainidx,int *alert,void *arg){
    TLSConfig *c=arg;TLSState *s=state(ssl);Slice p={in,n},list,id;int match=0;(void)type;(void)x;
    if(!s)goto bad;
    if(context==SSL_EXT_TLS1_3_CERTIFICATE){if(n||chainidx||!s->available)goto bad;s->confirmed=1;return 1;}
    if(!vector(&p,2,&list)||p.n||!list.n)goto bad;
    while(list.n){if(!vector(&list,1,&id)||!id.n)goto bad;if(id.n==c->n&&(!memcmp(id.p,c->id,id.n)||(context==SSL_EXT_CLIENT_HELLO&&c->server&&c->has_group&&!memcmp(id.p,c->group,id.n))))match=1;}
    if(!match)goto bad;
    if(context==SSL_EXT_CLIENT_HELLO)s->matched=1;else s->available=1;
    return 1;
bad:*alert=SSL_AD_HANDSHAKE_FAILURE;return 0;
}
static int verify(X509_STORE_CTX *store,void *arg){
    TLSConfig *c=arg;SSL *ssl=X509_STORE_CTX_get_ex_data(store,SSL_get_ex_data_X509_STORE_CTX_idx());
    TLSState *s=ssl?state(ssl):NULL;X509 *x=X509_STORE_CTX_get0_cert(store);int ok=0;
    X509_STORE *trust=NULL;X509_STORE_CTX *check=NULL;double begin=tick();
    if(!s||!s->confirmed||!x||!mtc_verify(x,c->trust))goto end;
    if(X509_check_purpose(x,X509_PURPOSE_SSL_SERVER,0)!=1||X509_cmp_current_time(X509_get0_notBefore(x))>=0||X509_cmp_current_time(X509_get0_notAfter(x))<=0)goto end;
    /* Restricted direct-CA profile: MTC authenticates this leaf, then native
       X509 validates its applicable leaf constraints with it locally trusted.
       This is NOT a general MTC PKIX chain-building implementation. */
    trust=X509_STORE_new();check=X509_STORE_CTX_new();
    if(!trust||!check||!X509_STORE_add_cert(trust,x)||!X509_STORE_CTX_init(check,trust,x,NULL)||!X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(check),X509_STORE_CTX_get0_param(store))||!X509_VERIFY_PARAM_set_flags(X509_STORE_CTX_get0_param(check),X509_V_FLAG_PARTIAL_CHAIN)||X509_verify_cert(check)!=1)goto end;
    X509_STORE_CTX_set0_verified_chain(store,X509_STORE_CTX_get1_chain(check));ok=1;
end:
    X509_STORE_CTX_free(check);X509_STORE_free(trust);X509_STORE_CTX_set_error(store,ok?X509_V_OK:X509_V_ERR_APPLICATION_VERIFICATION);
    if(ok)fprintf(stderr,"MTC verification: OK\nMTC_VERIFY {\"mtc_credential_auth_ms\":%.6f}\n",tick()-begin);
    return ok;
}
/* The MTC signatureValue is a proof, not an X.509 CA signature. Allow only
   the local MTC proof OID at the CA-digest gate. Keep key strength, peer-chain,
   CertificateVerify and every other policy decision in the original callback. */
static int proof_algorithm(const X509_ALGOR *alg){
    const ASN1_OBJECT *obj=NULL;char oid[80];
    if(!alg)return 0;
    X509_ALGOR_get0(&obj,NULL,NULL,alg);
    return obj && OBJ_obj2txt(oid,sizeof(oid),obj,1)>0
        && strcmp(oid,"1.3.6.1.4.1.44363.47.0")==0;
}
static int mtc_security(const SSL *ssl,const SSL_CTX *ctx,int op,int bits,int nid,void *other,void *ex){
    const SSL_CTX *active=ctx?ctx:(ssl?SSL_get_SSL_CTX(ssl):NULL);
    TLSConfig *c=ci>=0 && active?SSL_CTX_get_ex_data(active,ci):NULL;
    if(c && c->server && op==SSL_SECOP_CA_MD && other){
        const X509_ALGOR *alg=NULL;X509 *cert=other;
        X509_get0_signature(NULL,&alg,cert);
        if(proof_algorithm(alg) && proof_algorithm(X509_get0_tbs_sigalg(cert)))return 1;
    }
    return c && c->previous_security?c->previous_security(ssl,ctx,op,bits,nid,other,ex):0;
}
static int install(SSL_CTX *ctx,TLSConfig *c){
    if(ci<0)ci=SSL_CTX_get_ex_new_index(0,NULL,NULL,NULL,config_free);
    if(si<0)si=SSL_get_ex_new_index(0,NULL,NULL,NULL,state_free);
    if(ci<0||si<0||!SSL_CTX_set_ex_data(ctx,ci,c))return 0;
    put(c->list,c->n+1,2);c->list[2]=(unsigned char)c->n;memcpy(c->list+3,!c->server&&c->has_group?c->group:c->id,c->n);
    if(!SSL_CTX_add_custom_ext(ctx,MTC_EXT,CONTEXT,add,NULL,c,parse,c))return 0;
    if(!c->server)SSL_CTX_set_cert_verify_callback(ctx,verify,c);
    else {c->previous_security=SSL_CTX_get_security_callback(ctx);SSL_CTX_set_security_callback(ctx,mtc_security);}
    return 1;
}
int mtc_client(SSL_CTX *ctx,const char *path,int landmark){
    TLSConfig *c=OPENSSL_zalloc(sizeof(*c));if(!c)return 0;
    c->trust=mtc_load(path,landmark);if(!c->trust){OPENSSL_free(c);return 0;}
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    c->n=c->trust->signal_len;memcpy(c->id,c->trust->signal,c->n);
    if(landmark){c->has_group=initial_group(c);if(!c->has_group){mtc_free(c->trust);OPENSSL_free(c);return 0;}}
    return install(ctx,c);
}
int mtc_server(SSL_CTX *ctx,const char *id){
    TLSConfig *c=OPENSSL_zalloc(sizeof(*c));if(!c)return 0;c->server=1;
    if(!id_encode(id,c->id,&c->n)){OPENSSL_free(c);return 0;}c->has_group=initial_group(c);return install(ctx,c);
}
