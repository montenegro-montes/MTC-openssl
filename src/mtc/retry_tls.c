/* Opt-in trust-anchor-ids-06 retry subset. Reuse the baseline verifier/policy. */
#include "tls.c"
typedef struct {
    TLSConfig base;
    unsigned char requested[80], request_list[83];
    size_t requested_len;
} RetryConfig;

static int retry_ci=-1;

static void retry_config_free(void *parent,void *ptr,CRYPTO_EX_DATA *ad,
                              int idx,long l,void *arg){
    RetryConfig *r=ptr;
    (void)parent;(void)ad;(void)idx;(void)l;(void)arg;
    if(!r)return;
    mtc_free(r->base.trust);
    OPENSSL_free(r);
}

static TLSState *retry_state(SSL *ssl){
    RetryConfig *r=retry_ci>=0
        ? SSL_CTX_get_ex_data(SSL_get_SSL_CTX(ssl),retry_ci)
        : NULL;
    return r?state(ssl,r->base.role):NULL;
}

static int retry_id_valid(Slice id) {
    size_t pos=0,used;uint64_t value;
    if (!id.n || id.n>32) return 0; /* trust-anchor-ids-06 Section 4 */
    while(pos<id.n){
        if(!oid_uint64_component(id.p+pos,id.n-pos,&used,&value))return 0;
        pos+=used;
    }
    return 1;
}
static void retry_hex(FILE *out,const unsigned char *p,size_t n) {
    for(size_t i=0;i<n;i++) fprintf(out,"%02x",p[i]);
}
static int retry_add(SSL *ssl,unsigned type,unsigned context,const unsigned char **out,
                     size_t *len,X509 *x,size_t chainidx,int *alert,void *arg) {
    RetryConfig *r=arg;TLSState *s=retry_state(ssl);
    if(!s){*alert=SSL_AD_INTERNAL_ERROR;return -1;}
    if(context==SSL_EXT_CLIENT_HELLO){
        fputs("MTC_RETRY_CH {\"requested_id_hex\":\"",stderr);
        retry_hex(stderr,r->requested,r->requested_len);fputs("\"}\n",stderr);
        *out=r->request_list;*len=r->requested_len+3;return 1;
    }
    /* Available paths are sent even when the request cannot be satisfied.
       An unmatched fallback MUST NOT include CertificateEntry confirmation. */
    if(context==SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS){*out=r->base.list;*len=r->base.n+3;return 1;}
    if(!s->matched || chainidx) return 0;
    return add_one(ssl,type,context,out,len,x,chainidx,alert,&r->base);
}
static int retry_parse(SSL *ssl,unsigned type,unsigned context,const unsigned char *in,
                       size_t n,X509 *x,size_t chainidx,int *alert,void *arg) {
    RetryConfig *r=arg;TLSConfig *c=&r->base;TLSState *s=retry_state(ssl);
    Slice p={in,n},list,id;int match=0;
    if(!s){*alert=SSL_AD_INTERNAL_ERROR;return 0;}
    if(context==SSL_EXT_TLS1_3_CERTIFICATE)
        return parse_one(ssl,type,context,in,n,x,chainidx,alert,c);
    if(!vector(&p,2,&list)||p.n)goto malformed;
    if(!list.n){
        if(context!=SSL_EXT_CLIENT_HELLO)goto malformed;
        s->matched=0;
        fprintf(stderr,"MTC_RETRY_SERVER {\"request_satisfied\":false,\"supported_id_hex\":\"");
        retry_hex(stderr,c->id,c->n);fputs("\"}\n",stderr);
        return 1;
    }
    if(context==SSL_EXT_CLIENT_HELLO){
        /* RequestedTrustAnchorList is unordered and may name several IDs.
           The retry controller still sends one ID per connection. */
        while(list.n){
            if(!vector(&list,1,&id)||!wire_id_valid(id))goto malformed;
            if(!retry_id_valid(id))continue;
            if((id.n==c->n&&!memcmp(id.p,c->id,c->n))
               || mtc_group_match(c,id.p,id.n))match=1;
        }
        s->matched=match;
        fprintf(stderr,"MTC_RETRY_SERVER {\"request_satisfied\":%s,\"supported_id_hex\":\"",match?"true":"false");
        retry_hex(stderr,c->id,c->n);fputs("\"}\n",stderr);
        return 1; /* native TLS proceeds to EE and its fallback certificate */
    }
    if(context!=SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS)goto malformed;
    /* EE may list several individual anchors. Only the authenticated local
       anchor can make this attempt compatible with the requested ID. */
    while(list.n){
        if(!vector(&list,1,&id)||!wire_id_valid(id))goto malformed;
        if(!retry_id_valid(id))continue;
        if(id.n==c->n&&!memcmp(id.p,c->id,c->n)
           &&((id.n==r->requested_len
                &&!memcmp(id.p,r->requested,id.n))
              ||(c->has_group && r->requested_len==c->group_n
                 &&!memcmp(r->requested,c->group,c->group_n))))
            match=1;
    }
    fputs("MTC_RETRY_EE {\"available_list_hex\":\"",stderr);retry_hex(stderr,in,n);
    fprintf(stderr,"\",\"reason\":\"%s\"}\n",match?"compatible":"trust_anchor_mismatch");
    if(!match){*alert=SSL_AD_UNKNOWN_CA;return 0;}
    s->available=1;return 1;
malformed:
    fputs("MTC_RETRY_ERROR {\"reason\":\"malformed_trust_anchor_list\"}\n",stderr);
    *alert=SSL_AD_DECODE_ERROR;return 0;
}
static int retry_security(const SSL *ssl,const SSL_CTX *ctx,
                          int op,int bits,int nid,void *other,void *ex){
    const SSL_CTX *active=ctx?ctx:(ssl?SSL_get_SSL_CTX(ssl):NULL);
    RetryConfig *r=retry_ci>=0 && active
        ? SSL_CTX_get_ex_data(active,retry_ci)
        : NULL;
    TLSConfig *c=r?&r->base:NULL;

    if(c && c->role==MTC_ROLE_SERVER_PRESENT
        && op==SSL_SECOP_CA_MD && other){
        const X509_ALGOR *alg=NULL;
        X509 *cert=other;
        X509_get0_signature(NULL,&alg,cert);
        if(proof_algorithm(alg)
            && proof_algorithm(X509_get0_tbs_sigalg(cert)))
            return 1;
    }

    return c && c->previous_security
        ? c->previous_security(ssl,ctx,op,bits,nid,other,ex)
        : 0;
}

static int retry_install(SSL_CTX *ctx,RetryConfig *r) {
    TLSConfig *c=&r->base;
    if(retry_ci<0)
        retry_ci=SSL_CTX_get_ex_new_index(0,NULL,NULL,NULL,retry_config_free);
    if(si<0)
        si=SSL_get_ex_new_index(0,NULL,NULL,NULL,state_free);
    if(retry_ci<0||si<0
        ||!SSL_CTX_set_ex_data(ctx,retry_ci,r))return 0;
    put(c->list,c->n+1,2);c->list[2]=(unsigned char)c->n;memcpy(c->list+3,c->id,c->n);
    c->list_n=c->n+3;
    put(r->request_list,r->requested_len+1,2);r->request_list[2]=(unsigned char)r->requested_len;
    memcpy(r->request_list+3,r->requested,r->requested_len);
    SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_OFF);
    if(!SSL_CTX_set_num_tickets(ctx,0))return 0;
    if(!SSL_CTX_add_custom_ext(ctx,MTC_EXT,CONTEXT,retry_add,NULL,r,retry_parse,r))return 0;
    if(c->role==MTC_ROLE_CLIENT_VERIFY_SERVER){
        SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
        SSL_CTX_set_cert_verify_callback(ctx,verify,c);
    }else{
        c->previous_security=SSL_CTX_get_security_callback(ctx);
        SSL_CTX_set_security_callback(ctx,retry_security);
    }
    return 1;
}
static int retry_configure(SSL_CTX *ctx,const char *trust_path,int landmark,
                           const char *requested,X509 *credential,EVP_PKEY *key) {
    RetryConfig *r=OPENSSL_zalloc(sizeof(*r));TLSConfig *c;
    if(!r)return 0;
    c=&r->base;
    c->trust=landmark?mtc_load_trust_config_v2(trust_path)
                     :mtc_load_authority_config_v2(trust_path);
    if(!c->trust)goto bad;
    c->n=c->trust->signal_len;
    if(!retry_id_valid((Slice){c->trust->signal,c->n}))goto bad;
    memcpy(c->id,c->trust->signal,c->n);
    c->has_group=c->trust->landmark&&initial_group(c);
    c->group_n=c->has_group?c->n:0;
    c->role=credential!=NULL
        ? MTC_ROLE_SERVER_PRESENT
        : MTC_ROLE_CLIENT_VERIFY_SERVER;
    c->purpose=X509_PURPOSE_SSL_SERVER;
    if(c->role==MTC_ROLE_SERVER_PRESENT){
        /* No independently configured advertised ID: derive it from trust
           only after proof/checkpoint and possession-key binding succeed. */
        if(!key||!mtc_verify(credential,c->trust)||!X509_check_private_key(credential,key)
           ||X509_check_purpose(credential,X509_PURPOSE_SSL_SERVER,0)!=1
           ||X509_cmp_current_time(X509_get0_notBefore(credential))>=0
           ||X509_cmp_current_time(X509_get0_notAfter(credential))<=0)goto bad;
    }else if(!requested||!id_encode(requested,r->requested,&r->requested_len)
             ||!retry_id_valid((Slice){r->requested,r->requested_len}))goto bad;
    /* Once attached, SSL_CTX owns r even if a later install operation fails. */
    if(!retry_install(ctx,r)) {
        if(retry_ci<0||SSL_CTX_get_ex_data(ctx,retry_ci)!=r)goto bad;
        return 0;
    }
    return c->role!=MTC_ROLE_SERVER_PRESENT
        || (SSL_CTX_use_certificate(ctx,credential)==1
                         && SSL_CTX_use_PrivateKey(ctx,key)==1&&SSL_CTX_check_private_key(ctx)==1);
bad:
    mtc_free(c->trust);OPENSSL_free(r);return 0;
}
