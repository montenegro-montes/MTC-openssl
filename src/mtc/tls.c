#include "mtc.c"
#define CONTEXT (SSL_EXT_TLS_ONLY|SSL_EXT_TLS1_3_ONLY|SSL_EXT_CLIENT_HELLO|SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS|SSL_EXT_TLS1_3_CERTIFICATE|SSL_EXT_TLS1_3_CERTIFICATE_REQUEST)
typedef int (*SecurityCallback)(const SSL *,const SSL_CTX *,int,int,int,void *,void *);
enum {
    MTC_ROLE_CLIENT_VERIFY_SERVER = 1,
    MTC_ROLE_SERVER_PRESENT,
    MTC_ROLE_SERVER_VERIFY_CLIENT,
    MTC_ROLE_CLIENT_PRESENT
};
typedef struct {
    SecurityCallback previous_security;
    MTCConfig *trust;
    unsigned char id[80], group[80], list[83];
    size_t n;
    int role, has_group, purpose;
} TLSConfig;

typedef struct {
    TLSConfig *present;
    TLSConfig *verify;
    unsigned char client_hello_list[164];
    size_t client_hello_list_len;
} TLSEndpointConfig;

typedef struct {
    int matched, available, confirmed;
} TLSState;

typedef struct {
    TLSState present;
    TLSState verify;
} TLSEndpointState;

static int ci=-1,si=-1;
/* Recognize an individual suffix by components, including multi-byte numbers.
   This maps only the corresponding exact configured landmark, not a range. */
static int initial_group(TLSConfig *c){
    size_t offsets[80],count=0;uint64_t values[80],value=0;int first=1;
    for(size_t i=0;i<c->n;i++){
        if(first){if(c->id[i]==0x80)return 0;offsets[count]=i;value=0;first=0;}
        value=(value<<7)|(c->id[i]&127);
        if(value>0xffffffffULL)return 0;
        if(!(c->id[i]&128)){values[count++]=value;first=1;}
    }
    if(!first||count<4||values[count-3]!=1||!values[count-2]||!values[count-1])return 0;
    memcpy(c->group,c->id,c->n);c->group[offsets[count-3]]=2;return 1;
}
static void tls_config_free(TLSConfig *c){
    if(!c)return;
    mtc_free(c->trust);
    OPENSSL_free(c);
}

static void config_free(void *parent,void *ptr,CRYPTO_EX_DATA *ad,int idx,long l,void *arg){
    TLSEndpointConfig *c=ptr;
    (void)parent;(void)ad;(void)idx;(void)l;(void)arg;
    if(c){
        tls_config_free(c->present);
        tls_config_free(c->verify);
        OPENSSL_free(c);
    }
}

static void state_free(void *parent,void *ptr,CRYPTO_EX_DATA *ad,int idx,long l,void *arg){
    (void)parent;(void)ad;(void)idx;(void)l;(void)arg;
    OPENSSL_free(ptr);
}

static TLSEndpointState *endpoint_state(SSL *ssl){
    TLSEndpointState *s=SSL_get_ex_data(ssl,si);
    if(!s){
        s=OPENSSL_zalloc(sizeof(*s));
        if(s&&!SSL_set_ex_data(ssl,si,s)){
            OPENSSL_free(s);
            s=NULL;
        }
    }
    return s;
}

static TLSState *state(SSL *ssl,int role){
    TLSEndpointState *s=endpoint_state(ssl);
    if(!s)return NULL;

    if(role==MTC_ROLE_SERVER_PRESENT || role==MTC_ROLE_CLIENT_PRESENT)
        return &s->present;

    if(role==MTC_ROLE_CLIENT_VERIFY_SERVER || role==MTC_ROLE_SERVER_VERIFY_CLIENT)
        return &s->verify;

    return NULL;
}
static int add_one(SSL *ssl,unsigned type,unsigned context,const unsigned char **out,size_t *len,X509 *x,size_t chainidx,int *alert,void *arg){
    TLSConfig *c=arg;TLSState *s=state(ssl,c->role);(void)type;(void)x;
    if(!s){*alert=SSL_AD_INTERNAL_ERROR;return -1;}

    if(context==SSL_EXT_CLIENT_HELLO){
        if(c->role!=MTC_ROLE_CLIENT_VERIFY_SERVER
            && c->role!=MTC_ROLE_CLIENT_PRESENT)return 0;
        *out=c->list;*len=c->n+3;return 1;
    }

    if(c->role==MTC_ROLE_CLIENT_PRESENT){
        if(!s->available){*alert=SSL_AD_HANDSHAKE_FAILURE;return -1;}
    }else{
        if(!s->matched){*alert=SSL_AD_HANDSHAKE_FAILURE;return -1;}
    }

    if(context==SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS){
        if(c->role!=MTC_ROLE_SERVER_PRESENT)return 0;
        *out=c->list;*len=c->n+3;return 1;
    }

    if(context==SSL_EXT_TLS1_3_CERTIFICATE_REQUEST){
        if(c->role!=MTC_ROLE_SERVER_VERIFY_CLIENT)return 0;
        *out=c->list;
        *len=c->n+3;
        s->available=1;
        return 1;
    }

    if(context==SSL_EXT_TLS1_3_CERTIFICATE){
        if(chainidx)return 0;
        if(c->role!=MTC_ROLE_SERVER_PRESENT
            && c->role!=MTC_ROLE_CLIENT_VERIFY_SERVER
            && c->role!=MTC_ROLE_CLIENT_PRESENT)return 0;
        *out=(const unsigned char *)"";*len=0;return 1;
    }

    return 0;
}

static int parse_one(SSL *ssl,unsigned type,unsigned context,const unsigned char *in,size_t n,X509 *x,size_t chainidx,int *alert,void *arg){
    TLSConfig *c=arg;TLSState *s=state(ssl,c->role);Slice p={in,n},list,id;int match=0;(void)type;(void)x;
    if(!s)goto bad;

    if(context==SSL_EXT_TLS1_3_CERTIFICATE){
        if(c->role!=MTC_ROLE_CLIENT_VERIFY_SERVER
            && c->role!=MTC_ROLE_SERVER_VERIFY_CLIENT)goto bad;
        if(n||chainidx||!s->available)goto bad;
        s->confirmed=1;return 1;
    }

    if(context==SSL_EXT_CLIENT_HELLO){
        if(c->role!=MTC_ROLE_SERVER_PRESENT
            && c->role!=MTC_ROLE_SERVER_VERIFY_CLIENT)goto bad;
    }else if(context==SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS){
        if(c->role!=MTC_ROLE_CLIENT_VERIFY_SERVER)goto bad;
    }else if(context==SSL_EXT_TLS1_3_CERTIFICATE_REQUEST){
        if(c->role!=MTC_ROLE_CLIENT_VERIFY_SERVER
            && c->role!=MTC_ROLE_CLIENT_PRESENT)goto bad;
    }else{
        goto bad;
    }

    if(!vector(&p,2,&list)||p.n||!list.n)goto bad;
    while(list.n){
        if(!vector(&list,1,&id)||!id.n)goto bad;
        if(id.n==c->n
            && (!memcmp(id.p,c->id,id.n)
                || (context==SSL_EXT_CLIENT_HELLO
                    && (c->role==MTC_ROLE_SERVER_PRESENT
                        || c->role==MTC_ROLE_SERVER_VERIFY_CLIENT)
                    && c->has_group
                    && !memcmp(id.p,c->group,id.n))))
            match=1;
    }
    if(!match)goto bad;

    if(context==SSL_EXT_CLIENT_HELLO)s->matched=1;
    else s->available=1;

    return 1;

bad:
    *alert=SSL_AD_HANDSHAKE_FAILURE;
    return 0;
}


/*
 * Build the single MTC ClientHello extension for an endpoint.
 * Presentation and verification may advertise the same signal; duplicate
 * entries are collapsed. Distinct signals are carried in the same vector.
 */
static int client_hello_list(TLSEndpointConfig *endpoint,
                             unsigned char *out,size_t capacity,
                             size_t *out_n){
    TLSConfig *items[2]={endpoint->verify,endpoint->present};
    size_t pos=2;

    for(size_t i=0;i<2;i++){
        TLSConfig *c=items[i];
        const unsigned char *id;
        size_t n;
        int duplicate=0;

        if(!c)
            continue;

        if(c->role!=MTC_ROLE_CLIENT_VERIFY_SERVER
            && c->role!=MTC_ROLE_CLIENT_PRESENT)
            continue;

        id=c->has_group?c->group:c->id;
        n=c->n;

        for(size_t j=0;j<i;j++){
            TLSConfig *previous=items[j];
            const unsigned char *previous_id;

            if(!previous
                || (previous->role!=MTC_ROLE_CLIENT_VERIFY_SERVER
                    && previous->role!=MTC_ROLE_CLIENT_PRESENT)
                || previous->n!=n)
                continue;

            previous_id=previous->has_group
                ? previous->group : previous->id;

            if(!memcmp(previous_id,id,n)){
                duplicate=1;
                break;
            }
        }

        if(duplicate)
            continue;

        if(n>255 || pos+1+n>capacity)
            return 0;

        out[pos++]=(unsigned char)n;
        memcpy(out+pos,id,n);
        pos+=n;
    }

    if(pos==2 || pos-2>65535)
        return 0;

    put(out,pos-2,2);
    *out_n=pos;
    return 1;
}

static int endpoint_add(SSL *ssl,unsigned type,unsigned context,
                        const unsigned char **out,size_t *len,
                        X509 *x,size_t chainidx,int *alert,void *arg){
    TLSEndpointConfig *endpoint=arg;
    TLSConfig *c=NULL;

    if(!endpoint){
        *alert=SSL_AD_INTERNAL_ERROR;
        return -1;
    }

    if(context==SSL_EXT_CLIENT_HELLO){
        TLSEndpointState *s=endpoint_state(ssl);

        if(!s){
            *alert=SSL_AD_INTERNAL_ERROR;
            return -1;
        }

        if(!client_hello_list(endpoint,
                              endpoint->client_hello_list,
                              sizeof(endpoint->client_hello_list),
                              &endpoint->client_hello_list_len))
            return 0;

        *out=endpoint->client_hello_list;
        *len=endpoint->client_hello_list_len;
        return 1;
    }

    if(context==SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS)
        c=endpoint->present;
    else if(context==SSL_EXT_TLS1_3_CERTIFICATE_REQUEST)
        c=endpoint->verify;
    else if(context==SSL_EXT_TLS1_3_CERTIFICATE){
        /*
         * add_one() itself decides whether the active presentation/
         * verification role emits the empty MTC certificate marker.
         */
        if(endpoint->present)
            c=endpoint->present;
        else
            c=endpoint->verify;
    }

    if(!c)
        return 0;

    return add_one(ssl,type,context,out,len,x,chainidx,alert,c);
}

static int endpoint_parse(SSL *ssl,unsigned type,unsigned context,
                          const unsigned char *in,size_t n,
                          X509 *x,size_t chainidx,int *alert,void *arg){
    TLSEndpointConfig *endpoint=arg;
    int ok=0;

    if(!endpoint)
        goto bad;

    if(context==SSL_EXT_CLIENT_HELLO){
        /*
         * The same ClientHello offer can satisfy the server's presentation
         * and client-verification directions independently.
         */
        if(endpoint->present){
            if(!parse_one(ssl,type,context,in,n,x,chainidx,
                          alert,endpoint->present))
                goto bad;
            ok=1;
        }

        if(endpoint->verify){
            if(!parse_one(ssl,type,context,in,n,x,chainidx,
                          alert,endpoint->verify))
                goto bad;
            ok=1;
        }

        if(ok)
            return 1;

        goto bad;
    }

    if(context==SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS){
        if(!endpoint->verify)
            goto bad;
        return parse_one(ssl,type,context,in,n,x,chainidx,
                         alert,endpoint->verify);
    }

    if(context==SSL_EXT_TLS1_3_CERTIFICATE_REQUEST){
        /*
         * A client presentation role consumes the server's client-auth
         * selection. CLIENT_VERIFY_SERVER may also consume CertificateRequest
         * in the existing single-direction implementation.
         */
        if(endpoint->present)
            return parse_one(ssl,type,context,in,n,x,chainidx,
                             alert,endpoint->present);
        if(endpoint->verify)
            return parse_one(ssl,type,context,in,n,x,chainidx,
                             alert,endpoint->verify);
        goto bad;
    }

    if(context==SSL_EXT_TLS1_3_CERTIFICATE){
        if(!endpoint->verify)
            goto bad;
        return parse_one(ssl,type,context,in,n,x,chainidx,
                         alert,endpoint->verify);
    }

bad:
    *alert=SSL_AD_HANDSHAKE_FAILURE;
    return 0;
}

static int verify(X509_STORE_CTX *store,void *arg){
    TLSConfig *c=arg;SSL *ssl=X509_STORE_CTX_get_ex_data(store,SSL_get_ex_data_X509_STORE_CTX_idx());
    TLSState *s=ssl?state(ssl,c->role):NULL;X509 *x=X509_STORE_CTX_get0_cert(store);int ok=0;
    X509_STORE *trust=NULL;X509_STORE_CTX *check=NULL;double begin=tick();
    if(!s||!s->confirmed||!x||!mtc_verify(x,c->trust))goto end;
    if(X509_check_purpose(x,c->purpose,0)!=1||X509_cmp_current_time(X509_get0_notBefore(x))>=0||X509_cmp_current_time(X509_get0_notAfter(x))<=0)goto end;
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
    TLSEndpointConfig *endpoint=
        ci>=0 && active?SSL_CTX_get_ex_data(active,ci):NULL;
    TLSConfig *c=endpoint?endpoint->present:NULL;

    if(c && op==SSL_SECOP_CA_MD && other){
        const X509_ALGOR *alg=NULL;X509 *cert=other;
        X509_get0_signature(NULL,&alg,cert);
        if(proof_algorithm(alg)
            && proof_algorithm(X509_get0_tbs_sigalg(cert)))
            return 1;
    }

    return c && c->previous_security
        ? c->previous_security(ssl,ctx,op,bits,nid,other,ex)
        : 0;
}

static int install(SSL_CTX *ctx,TLSConfig *c){
    TLSEndpointConfig *endpoint;
    TLSConfig **slot;
    int first;

    if(ci<0)
        ci=SSL_CTX_get_ex_new_index(0,NULL,NULL,NULL,config_free);
    if(si<0)
        si=SSL_get_ex_new_index(0,NULL,NULL,NULL,state_free);
    if(ci<0||si<0)
        return 0;

    endpoint=SSL_CTX_get_ex_data(ctx,ci);
    first=endpoint==NULL;

    if(first){
        endpoint=OPENSSL_zalloc(sizeof(*endpoint));
        if(!endpoint)
            return 0;
        if(!SSL_CTX_set_ex_data(ctx,ci,endpoint)){
            OPENSSL_free(endpoint);
            return 0;
        }
    }

    if(c->role==MTC_ROLE_SERVER_PRESENT
        || c->role==MTC_ROLE_CLIENT_PRESENT)
        slot=&endpoint->present;
    else if(c->role==MTC_ROLE_CLIENT_VERIFY_SERVER
        || c->role==MTC_ROLE_SERVER_VERIFY_CLIENT)
        slot=&endpoint->verify;
    else
        return 0;

    if(*slot)
        return 0;

    put(c->list,c->n+1,2);
    c->list[2]=(unsigned char)c->n;
    memcpy(c->list+3,
        (c->role==MTC_ROLE_CLIENT_VERIFY_SERVER
            || c->role==MTC_ROLE_CLIENT_PRESENT)
            && c->has_group ? c->group : c->id,
        c->n);

    /*
     * Register MTC_EXT exactly once per SSL_CTX.  The callback argument is
     * the endpoint container, so presentation and peer verification can
     * coexist on the same endpoint.
     */
    if(first
        && !SSL_CTX_add_custom_ext(ctx,MTC_EXT,CONTEXT,
                                  endpoint_add,NULL,endpoint,
                                  endpoint_parse,endpoint))
        return 0;

    *slot=c;

    if(c->role==MTC_ROLE_CLIENT_VERIFY_SERVER
        || c->role==MTC_ROLE_SERVER_VERIFY_CLIENT){
        SSL_CTX_set_cert_verify_callback(ctx,verify,c);
    }else{
        c->previous_security=SSL_CTX_get_security_callback(ctx);
        SSL_CTX_set_security_callback(ctx,mtc_security);
    }

    return 1;
}
int mtc_client(SSL_CTX *ctx,const char *path,int landmark,
               const char *trusted_subtrees){
    TLSConfig *c=OPENSSL_zalloc(sizeof(*c));
    if(!c)return 0;

    c->trust=mtc_load(path,landmark);
    if(!c->trust){
        OPENSSL_free(c);
        return 0;
    }

    /*
     * MTS1 is already-validated relying-party state.  Load it once while
     * configuring the SSL_CTX; handshakes only consult MTCConfig in memory.
     */
    if(trusted_subtrees &&
       (!landmark ||
        !mtc_load_trusted_subtrees(c->trust,trusted_subtrees))){
        mtc_free(c->trust);
        OPENSSL_free(c);
        return 0;
    }

    c->role=MTC_ROLE_CLIENT_VERIFY_SERVER;
    c->purpose=X509_PURPOSE_SSL_SERVER;
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    c->n=c->trust->signal_len;
    memcpy(c->id,c->trust->signal,c->n);

    if(landmark){
        c->has_group=initial_group(c);
        if(!c->has_group){
            mtc_free(c->trust);
            OPENSSL_free(c);
            return 0;
        }
    }

    return install(ctx,c);
}
int mtc_server(SSL_CTX *ctx,const char *id){
    TLSConfig *c=OPENSSL_zalloc(sizeof(*c));if(!c)return 0;c->role=MTC_ROLE_SERVER_PRESENT;
    if(!id_encode(id,c->id,&c->n)){OPENSSL_free(c);return 0;}c->has_group=initial_group(c);return install(ctx,c);
}
int mtc_server_verify_client(SSL_CTX *ctx,const char *path,int landmark){
    TLSConfig *c=OPENSSL_zalloc(sizeof(*c));if(!c)return 0;
    c->trust=mtc_load(path,landmark);if(!c->trust){OPENSSL_free(c);return 0;}
    c->role=MTC_ROLE_SERVER_VERIFY_CLIENT;c->purpose=X509_PURPOSE_SSL_CLIENT;
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,NULL);
    c->n=c->trust->signal_len;memcpy(c->id,c->trust->signal,c->n);
    if(landmark){
        c->has_group=initial_group(c);
        if(!c->has_group){mtc_free(c->trust);OPENSSL_free(c);return 0;}
    }
    return install(ctx,c);
}

int mtc_client_present(SSL_CTX *ctx,const char *id,int landmark){
    TLSConfig *c=OPENSSL_zalloc(sizeof(*c));
    if(!c)return 0;
    c->role=MTC_ROLE_CLIENT_PRESENT;
    if(!id_encode(id,c->id,&c->n)){
        OPENSSL_free(c);
        return 0;
    }
    if(landmark){
        c->has_group=initial_group(c);
        if(!c->has_group){
            OPENSSL_free(c);
            return 0;
        }
    }
    return install(ctx,c);
}
