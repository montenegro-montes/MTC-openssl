#include "mtc.c"
#include <errno.h>
#include <sys/stat.h>
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
    size_t n, group_n, list_n;
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
    unsigned char requested[80];
    size_t requested_n;
    int requested_group;
} TLSState;

typedef struct {
    TLSState present;
    TLSState verify;
    size_t server_selected;
    int server_selection_reason;
    unsigned char *server_request;
    size_t server_request_n;
    int server_request_present;
    unsigned char server_available[164];
    size_t server_available_n;
} TLSEndpointState;

static int ci=-1,si=-1;
typedef struct {
    TLSConfig identity;
    X509 *certificate;
    EVP_PKEY *key;
    char id_text[256];
} MTCServerCandidate;
typedef struct {
    MTCServerCandidate items[2];
    size_t count;
    SecurityCallback previous_security;
    unsigned char available[164];
    size_t available_n;
} MTCServerCandidates;
static int candidates_ci=-1;
/* TAI-06 Section 8: wire IDs can contain OID components larger than uint64.
   Validate their encoding without applying the local configuration bound. */
static int wire_id_valid(Slice id){
    int first=1;
    if(!id.p||!id.n||id.n>32)return 0;
    for(size_t i=0;i<id.n;i++){
        unsigned char b=id.p[i];
        if(first&&b==0x80)return 0;
        first=!(b&128);
    }
    return first;
}
static int oid_uint64_component(const unsigned char *p,size_t n,
                                size_t *used,uint64_t *value){
    uint64_t v=0;size_t i;
    if(!p||!n||!used||!value||p[0]==0x80)return 0;
    for(i=0;i<n;i++){
        if(v>=(1ULL<<57))return 0;
        v=(v<<7)|(p[i]&127);
        if(!(p[i]&128)){
            *used=i+1;*value=v;return 1;
        }
    }
    return 0;
}
/* Recognize an individual suffix by components, including multi-byte numbers.
   This maps only the corresponding exact configured landmark, not a range. */
static int initial_group(TLSConfig *c){
    size_t offsets[80],count=0,pos=0,used;
    uint64_t values[80];

    while(pos<c->n){
        if(count>=sizeof(offsets)/sizeof(offsets[0]))return 0;
        offsets[count]=pos;
        if(!oid_uint64_component(c->id+pos,c->n-pos,&used,&values[count]))
            return 0;
        pos+=used;
        count++;
    }

    if(count<4||values[count-3]!=1
       ||!values[count-2]||!values[count-1])return 0;

    memcpy(c->group,c->id,c->n);
    c->group[offsets[count-3]]=2;
    return 1;
}
static int range_contains(const unsigned char *base,size_t base_n,
                          uint64_t min,uint64_t max,
                          const unsigned char *id,size_t id_n){
    size_t used;uint64_t value;
    if(!base||!base_n||!id||base[base_n-1]&128||id_n<=base_n||
       memcmp(base,id,base_n))return 0;
    return oid_uint64_component(id+base_n,id_n-base_n,&used,&value)&&
           used==id_n-base_n&&min<=value&&value<=max;
}
static int last_component(const unsigned char *id,size_t n,
                          size_t *offset,uint64_t *value){
    size_t pos=0,used,start=0;uint64_t component=0;
    if(!id||!n||!offset||!value)return 0;
    while(pos<n){
        start=pos;
        if(!oid_uint64_component(id+pos,n-pos,&used,&component))return 0;
        pos+=used;
    }
    *offset=start;*value=component;return 1;
}
static int mtc_group_match(const TLSConfig *c,
                           const unsigned char *id,size_t id_n){
    unsigned char caid[80];size_t caid_n;
    size_t base_n,used,pos,starts[3]={0};uint64_t min,value,values[3]={0};
    if(!c||!id)return 0;
    if(c->trust
       && id_encode(c->trust->caid,caid,&caid_n)
       && id_n==caid_n&&!memcmp(id,caid,caid_n))
        return 1;
    if(c->has_group){
        pos=0;
        while(pos<c->n){
            starts[0]=starts[1];starts[1]=starts[2];starts[2]=pos;
            values[0]=values[1];values[1]=values[2];
            if(!oid_uint64_component(c->id+pos,c->n-pos,&used,&values[2]))
                return 0;
            pos+=used;
        }
        if(values[0]!=1||!values[1]||!values[2]||!starts[0])
            return 0;
        if(id_n==starts[0]&&!memcmp(id,c->id,id_n))
            return 1;
        if(!last_component(c->group,c->group_n,&base_n,&min))return 0;
        return range_contains(c->group,base_n,min,UINT64_MAX,id,id_n);
    }
    if(id_n<=c->n+1||memcmp(c->id,id,c->n)||id[c->n]!=2)return 0;
    pos=c->n+1;
    if(!oid_uint64_component(id+pos,id_n-pos,&used,&value))return 0;
    pos+=used;
    if(!oid_uint64_component(id+pos,id_n-pos,&used,&value))return 0;
    (void)value;
    return pos+used==id_n;
}

static int landmark_id_parts(const unsigned char *id,size_t id_n,
                             size_t *base_n,uint64_t *kind,
                             uint64_t *log,uint64_t *landmark){
    size_t starts[3]={0},pos=0,used;uint64_t values[3]={0};
    if(!id||!id_n||!base_n||!kind||!log||!landmark)return 0;
    while(pos<id_n){
        starts[0]=starts[1];starts[1]=starts[2];starts[2]=pos;
        values[0]=values[1];values[1]=values[2];
        if(!oid_uint64_component(id+pos,id_n-pos,&used,&values[2]))return 0;
        pos+=used;
    }
    if(!starts[0])return 0;
    *base_n=starts[0];*kind=values[0];*log=values[1];*landmark=values[2];
    return 1;
}

/* MTC-07 Section 8.2.1: caID.2.N.L contains caID and every
   caID.1.N.M for M <= L.  Both inputs are exact canonical wire IDs. */
static int requested_landmark_group_contains(
        const unsigned char *group,size_t group_n,
        const unsigned char *individual,size_t individual_n){
    size_t group_base,individual_base;uint64_t group_kind,group_log,group_l;
    uint64_t individual_kind,individual_log,individual_l;
    if(!landmark_id_parts(group,group_n,&group_base,&group_kind,
                          &group_log,&group_l)
       ||group_kind!=2||!group_log)return 0;
    if(individual_n==group_base
       &&!memcmp(individual,group,group_base))return 1;
    return landmark_id_parts(individual,individual_n,&individual_base,
                             &individual_kind,&individual_log,&individual_l)
           &&individual_base==group_base
           &&!memcmp(individual,group,group_base)
           &&individual_kind==1
           &&individual_log==group_log
           &&individual_l<=group_l;
}

/* A client without retained-landmark metadata advertises the bare CA ID.
   In that case accept only this configuration's exact individual landmark;
   explicit caID.2.N.L requests retain the Section 8.2.1 range semantics. */
static int requested_mtc_group_contains(
        const TLSConfig *c,const unsigned char *requested,size_t requested_n,
        const unsigned char *individual,size_t individual_n){
    size_t configured_base;uint64_t kind,log,landmark;
    if(!c||!requested||!individual)return 0;
    if(landmark_id_parts(c->id,c->n,&configured_base,&kind,&log,&landmark)
       &&kind==1&&log&&landmark
       &&requested_n==configured_base
       &&!memcmp(requested,c->id,configured_base))
        return individual_n==c->n&&!memcmp(individual,c->id,c->n);
    return requested_landmark_group_contains(
        requested,requested_n,individual,individual_n);
}

/* Pair-server selection policy. Candidate order breaks ties within a mode;
 * Landmark takes precedence over Standalone. The single-certificate path
 * remains separate. */
enum {
    MTC_SELECT_INVALID = -1,
    MTC_SELECT_NONE = 0,
    MTC_SELECT_LANDMARK,
    MTC_SELECT_STANDALONE,
    MTC_SELECT_FALLBACK_STANDALONE
};
static inline int select_server_candidate_eligible(TLSConfig *const *candidates,
        size_t count,Slice request,unsigned eligible_mask,size_t *selected){
    Slice p=request,list,id;
    size_t landmark=SIZE_MAX,standalone=SIZE_MAX,fallback=SIZE_MAX;

    if(!selected)
        return MTC_SELECT_INVALID;
    *selected=SIZE_MAX;
    if(!candidates||!vector(&p,2,&list)||p.n)
        return MTC_SELECT_INVALID;
    for(size_t i=0;i<count;i++){
        if(!candidates[i]||!candidates[i]->n)
            return MTC_SELECT_INVALID;
        if((eligible_mask&(1U<<i))
           &&!candidates[i]->has_group&&fallback==SIZE_MAX)
            fallback=i;
    }
    while(list.n){
        if(!vector(&list,1,&id)||!wire_id_valid(id))
            return MTC_SELECT_INVALID;
        if(!id_valid(id))continue; /* valid wire ID outside local MTC bound */
        for(size_t i=0;i<count;i++){
            TLSConfig *c=candidates[i];
            if(!(eligible_mask&(1U<<i)))continue;
            int exact=id.n==c->n&&!memcmp(id.p,c->id,id.n);
            if(c->has_group){
                /* A bare CA ID does not signal trust in a landmark subtree. */
                if(landmark==SIZE_MAX
                   &&(exact||requested_landmark_group_contains(
                       id.p,id.n,c->id,c->n)))
                    landmark=i;
            }else if(standalone==SIZE_MAX
                     &&(exact||requested_landmark_group_contains(
                         id.p,id.n,c->id,c->n))){
                standalone=i;
            }
        }
    }
    if(landmark!=SIZE_MAX){*selected=landmark;return MTC_SELECT_LANDMARK;}
    if(standalone!=SIZE_MAX){*selected=standalone;return MTC_SELECT_STANDALONE;}
    if(fallback!=SIZE_MAX){*selected=fallback;return MTC_SELECT_FALLBACK_STANDALONE;}
    return MTC_SELECT_NONE;
}
static inline int select_server_candidate(TLSConfig *const *candidates,
                                          size_t count,Slice request,
                                          size_t *selected){
    return count<sizeof(unsigned)*8
        ? select_server_candidate_eligible(candidates,count,request,
                 (1U<<count)-1U,selected)
        : MTC_SELECT_INVALID;
}

static void tls_config_free(TLSConfig *c){
    if(!c)return;
    mtc_free(c->trust);
    OPENSSL_free(c);
}

static void candidates_free(void *parent,void *ptr,CRYPTO_EX_DATA *ad,
                            int idx,long l,void *arg){
    MTCServerCandidates *set=ptr;
    (void)parent;(void)ad;(void)idx;(void)l;(void)arg;
    if(!set)return;
    for(size_t i=0;i<set->count;i++){
        X509_free(set->items[i].certificate);
        EVP_PKEY_free(set->items[i].key);
    }
    OPENSSL_free(set);
}

static int same_server_identity(X509 *a,X509 *b){
    int ai=X509_get_ext_by_NID(a,NID_subject_alt_name,-1);
    int bi=X509_get_ext_by_NID(b,NID_subject_alt_name,-1);
    ASN1_OCTET_STRING *as,*bs;
    if(X509_NAME_cmp(X509_get_subject_name(a),X509_get_subject_name(b))
       ||(ai<0)!=(bi<0))return 0;
    if(ai<0)return 1;
    as=X509_EXTENSION_get_data(X509_get_ext(a,ai));
    bs=X509_EXTENSION_get_data(X509_get_ext(b,bi));
    return as&&bs&&ASN1_STRING_cmp(as,bs)==0;
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
    if(ptr)OPENSSL_free(((TLSEndpointState *)ptr)->server_request);
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

static int select_and_install_server_candidate_eligible(SSL *ssl,
        MTCServerCandidates *set,Slice request,unsigned eligible_mask){
    TLSConfig *identities[2];
    TLSEndpointState *s;
    size_t selected;
    int reason;

    if(!ssl||!set||set->count!=2)return MTC_SELECT_INVALID;
    identities[0]=&set->items[0].identity;
    identities[1]=&set->items[1].identity;
    reason=select_server_candidate_eligible(identities,2,request,
                                            eligible_mask,&selected);
    if(reason<=MTC_SELECT_NONE)return reason;
    s=endpoint_state(ssl);
    if(!s||SSL_use_cert_and_key(ssl,set->items[selected].certificate,
                                set->items[selected].key,NULL,1)!=1)
        return MTC_SELECT_INVALID;
    s->server_selected=selected;
    s->server_selection_reason=reason;
    return reason;
}
static int mtc_server_client_hello(SSL *ssl,int *alert,void *arg){
    static const unsigned char empty_request[]={0,0};
    MTCServerCandidates *set=arg;
    const unsigned char *data=empty_request;
    size_t n=sizeof(empty_request);
    TLSConfig *identities[2];
    size_t selected;
    int present,reason;
    TLSEndpointState *s;

    present=SSL_client_hello_get0_ext(ssl,MTC_EXT,&data,&n)==1;
    if(!present){
        data=empty_request;
        n=sizeof(empty_request);
    }
    identities[0]=&set->items[0].identity;
    identities[1]=&set->items[1].identity;
    reason=select_server_candidate(identities,2,(Slice){data,n},&selected);
    if(reason<=MTC_SELECT_NONE){
        *alert=reason==MTC_SELECT_NONE?SSL_AD_HANDSHAKE_FAILURE
                                       :SSL_AD_DECODE_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }
    s=endpoint_state(ssl);
    if(!s){*alert=SSL_AD_INTERNAL_ERROR;return SSL_CLIENT_HELLO_ERROR;}
    OPENSSL_free(s->server_request);
    s->server_request=OPENSSL_memdup(data,n);
    if(!s->server_request){
        s->server_request_n=0;
        *alert=SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }
    s->server_request_n=n;
    s->server_request_present=present;
    return SSL_CLIENT_HELLO_SUCCESS;
}

static int candidates_available_list(MTCServerCandidates *set){
    size_t pos=2;
    if(!set||set->count!=2)return 0;
    for(int mode=1;mode>=0;mode--){
        for(size_t i=0;i<set->count;i++){
            TLSConfig *c=&set->items[i].identity;
            if(c->has_group!=mode)continue;
            if(!c->n||c->n>32||pos+1+c->n>sizeof(set->available))
                return 0;
            set->available[pos++]=(unsigned char)c->n;
            memcpy(set->available+pos,c->id,c->n);
            pos+=c->n;
        }
    }
    if(pos==2)return 0;
    put(set->available,pos-2,2);
    set->available_n=pos;
    return 1;
}

static int candidates_available_for_connection(MTCServerCandidates *set,
        unsigned eligible_mask,TLSEndpointState *s){
    size_t pos=2;
    if(!set||!s||set->count!=2)return 0;
    for(int mode=1;mode>=0;mode--){
        for(size_t i=0;i<set->count;i++){
            TLSConfig *c=&set->items[i].identity;
            if(!(eligible_mask&(1U<<i))||c->has_group!=mode)continue;
            if(!c->n||c->n>32||pos+1+c->n>sizeof(s->server_available))
                return 0;
            s->server_available[pos++]=(unsigned char)c->n;
            memcpy(s->server_available+pos,c->id,c->n);
            pos+=c->n;
        }
    }
    s->server_available_n=pos>2?pos:0;
    if(s->server_available_n)put(s->server_available,pos-2,2);
    return 1;
}

static int mtc_server_certificate_cb(SSL *ssl,void *arg){
    MTCServerCandidates *set=arg;
    TLSEndpointState *s=si>=0?SSL_get_ex_data(ssl,si):NULL;
    unsigned eligible_mask=0;
    int candidate_flags[2]={0,0};
    int reason;
    if(!set||set->count!=2||!s||!s->server_request)return 0;
    for(size_t i=0;i<set->count;i++){
        candidate_flags[i]=SSL_check_chain(ssl,set->items[i].certificate,
                                            set->items[i].key,NULL);
        if(candidate_flags[i]&CERT_PKEY_VALID)eligible_mask|=1U<<i;
    }
    if(!candidates_available_for_connection(set,eligible_mask,s))return 0;
    reason=select_and_install_server_candidate_eligible(ssl,set,
            (Slice){s->server_request,s->server_request_n},eligible_mask);
    if(reason<=MTC_SELECT_NONE){
        fprintf(stderr,"MTC server certificate selection failed: no-eligible-candidate flags=%#x,%#x\n",
                candidate_flags[0],candidate_flags[1]);
        return 0;
    }
    fprintf(stderr,"MTC server certificate selected: id=%s reason=%s\n",
            set->items[s->server_selected].id_text,
            reason==MTC_SELECT_LANDMARK?"requested-landmark":
            reason==MTC_SELECT_STANDALONE?"requested-standalone":
                                          "fallback-standalone");
    return 1;
}

static int candidates_add(SSL *ssl,unsigned type,unsigned context,
                          const unsigned char **out,size_t *len,X509 *x,
                          size_t chainidx,int *alert,void *arg){
    MTCServerCandidates *set=arg;
    TLSEndpointState *s;
    (void)type;
    if(!set||set->count!=2){*alert=SSL_AD_INTERNAL_ERROR;return -1;}
    if(context==SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS){
        s=si>=0?SSL_get_ex_data(ssl,si):NULL;
        if(!s||!s->server_request_present||!s->server_available_n)return 0;
        *out=s->server_available;
        *len=s->server_available_n;
        return 1;
    }
    if(context!=SSL_EXT_TLS1_3_CERTIFICATE||chainidx)return 0;
    s=si>=0?SSL_get_ex_data(ssl,si):NULL;
    if(!s||s->server_selected>=set->count){
        *alert=SSL_AD_INTERNAL_ERROR;return -1;
    }
    if(s->server_selection_reason!=MTC_SELECT_LANDMARK
       &&s->server_selection_reason!=MTC_SELECT_STANDALONE)
        return 0;
    if(!x||X509_cmp(x,set->items[s->server_selected].certificate)){
        *alert=SSL_AD_INTERNAL_ERROR;return -1;
    }
    *out=(const unsigned char *)"";
    *len=0;
    return 1;
}

static int candidates_parse(SSL *ssl,unsigned type,unsigned context,
                            const unsigned char *in,size_t n,X509 *x,
                            size_t chainidx,int *alert,void *arg){
    (void)ssl;(void)type;(void)in;(void)n;(void)x;
    (void)chainidx;(void)arg;
    if(context==SSL_EXT_CLIENT_HELLO)return 1;
    *alert=SSL_AD_UNSUPPORTED_EXTENSION;
    return 0;
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
        *out=c->list;*len=c->list_n;return 1;
    }

    /* AvailableTrustAnchorList advertises candidates independently of
       whether an empty/subset request matched the selected fallback. */
    if(context==SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS){
        if(c->role!=MTC_ROLE_SERVER_PRESENT)return 0;
        *out=c->list;*len=c->list_n;return 1;
    }

    if(c->role==MTC_ROLE_CLIENT_PRESENT){
        if(!s->available){*alert=SSL_AD_HANDSHAKE_FAILURE;return -1;}
    }else{
        if(!s->matched){*alert=SSL_AD_HANDSHAKE_FAILURE;return -1;}
    }

    if(context==SSL_EXT_TLS1_3_CERTIFICATE_REQUEST){
        if(c->role!=MTC_ROLE_SERVER_VERIFY_CLIENT)return 0;
        *out=c->list;
        *len=c->list_n;
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
    TLSConfig *c=arg;TLSState *s=state(ssl,c->role);Slice p={in,n},list,id;int match=0,supported=0;(void)type;(void)x;
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

    if(!vector(&p,2,&list)||p.n)goto bad;
    if(!list.n){
        /* RequestedTrustAnchorList may be empty; AvailableTrustAnchorList
           may not.  An empty request matches no configured candidate. */
        if(context==SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS)goto bad;
        if(context==SSL_EXT_CLIENT_HELLO)s->matched=0;
        else s->available=0;
        return 1;
    }
    while(list.n){
        if(!vector(&list,1,&id)||!wire_id_valid(id))goto bad;
        if(!id_valid(id))continue; /* ignore unsupported, well-formed ID */
        supported=1;
        if((context==SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS
            && s->requested_n
            && ((!s->requested_group
                 && id.n==s->requested_n
                 && !memcmp(id.p,s->requested,id.n))
                || (s->requested_group
                    && requested_mtc_group_contains(
                        c,s->requested,s->requested_n,id.p,id.n))))
           || (context!=SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS
               && id.n==c->n&&!memcmp(id.p,c->id,id.n))
            || (context==SSL_EXT_CLIENT_HELLO
                && (c->role==MTC_ROLE_SERVER_PRESENT
                    || c->role==MTC_ROLE_SERVER_VERIFY_CLIENT)
                && mtc_group_match(c,id.p,id.n)))
            match=1;
    }
    if(!match){
        if(supported)goto bad;
        /* Discarding every unsupported ID is equivalent to an empty
           request or an omitted available list. */
        if(context==SSL_EXT_CLIENT_HELLO)s->matched=0;
        else s->available=0;
        return 1;
    }

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
        n=c->has_group?c->group_n:c->n;

        for(size_t j=0;j<i;j++){
            TLSConfig *previous=items[j];
            const unsigned char *previous_id;

            if(!previous
                || (previous->role!=MTC_ROLE_CLIENT_VERIFY_SERVER
                    && previous->role!=MTC_ROLE_CLIENT_PRESENT)
                || (previous->has_group
                    ? previous->group_n : previous->n)!=n)
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

static int preserve_client_request(SSL *ssl,TLSConfig *c){
    TLSState *s;const unsigned char *id;size_t n;
    if(!c||(c->role!=MTC_ROLE_CLIENT_VERIFY_SERVER
           &&c->role!=MTC_ROLE_CLIENT_PRESENT))return 1;
    s=state(ssl,c->role);if(!s)return 0;
    id=c->has_group?c->group:c->id;n=c->has_group?c->group_n:c->n;
    if(!n||n>sizeof(s->requested))return 0;
    memcpy(s->requested,id,n);s->requested_n=n;s->requested_group=c->has_group;
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
        if(!preserve_client_request(ssl,endpoint->verify)
           ||!preserve_client_request(ssl,endpoint->present)){
            *alert=SSL_AD_INTERNAL_ERROR;
            return -1;
        }

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
    MTCVerificationTiming timing={0};int mtc_attempted=0;
    if(!s||!s->confirmed||!x)goto end;
    mtc_attempted=1;
    if(!mtc_verify_timed(x,c->trust,&timing))goto end;
    if(X509_check_purpose(x,c->purpose,0)!=1||X509_cmp_current_time(X509_get0_notBefore(x))>=0||X509_cmp_current_time(X509_get0_notAfter(x))<=0)goto end;
    /* Restricted direct-CA profile: MTC authenticates this leaf, then native
       X509 validates its applicable leaf constraints with it locally trusted.
       This is NOT a general MTC PKIX chain-building implementation. */
    trust=X509_STORE_new();check=X509_STORE_CTX_new();
    if(!trust||!check||!X509_STORE_add_cert(trust,x)||!X509_STORE_CTX_init(check,trust,x,NULL)||!X509_VERIFY_PARAM_set1(X509_STORE_CTX_get0_param(check),X509_STORE_CTX_get0_param(store))||!X509_VERIFY_PARAM_set_flags(X509_STORE_CTX_get0_param(check),X509_V_FLAG_PARTIAL_CHAIN)||X509_verify_cert(check)!=1)goto end;
    X509_STORE_CTX_set0_verified_chain(store,X509_STORE_CTX_get1_chain(check));ok=1;
end:
    X509_STORE_CTX_free(check);X509_STORE_free(trust);X509_STORE_CTX_set_error(store,ok?X509_V_OK:X509_V_ERR_APPLICATION_VERIFICATION);
    if(mtc_attempted){
        if(ok)fprintf(stderr,"MTC verification: OK\n");
        fputs("MTC_VERIFY {\"timing_schema_version\":2,\"mtc_credential_auth_ms\":",stderr);
        if(ok)fprintf(stderr,"%.6f",tick()-begin);else fputs("null",stderr);
        fputs(",\"merkle_proof_ms\":",stderr);
        if(ok)fprintf(stderr,"%.6f",timing.merkle_proof_ms);else fputs("null",stderr);
        fputs(",\"landmark_validation_ms\":",stderr);
        if(ok&&c->trust->landmark)fprintf(stderr,"%.6f",timing.landmark_validation_ms);else fputs("null",stderr);
        fputs(",\"standalone_validation_ms\":",stderr);
        if(ok&&!c->trust->landmark)fprintf(stderr,"%.6f",timing.standalone_validation_ms);else fputs("null",stderr);
        fputs(",\"mtc_total_ns\":",stderr);
        if(timing.has_mtc_total_ns)fprintf(stderr,"%llu",(unsigned long long)timing.mtc_total_ns);else fputs("null",stderr);
        fputs(",\"merkle_leaf_hash_ns\":",stderr);
        if(timing.has_merkle_leaf_hash_ns)fprintf(stderr,"%llu",(unsigned long long)timing.merkle_leaf_hash_ns);else fputs("null",stderr);
        fputs(",\"merkle_path_ns\":",stderr);
        if(timing.has_merkle_path_ns)fprintf(stderr,"%llu",(unsigned long long)timing.merkle_path_ns);else fputs("null",stderr);
        fputs(",\"merkle_total_ns\":",stderr);
        if(timing.has_merkle_total_ns)fprintf(stderr,"%llu",(unsigned long long)timing.merkle_total_ns);else fputs("null",stderr);
        fputs(",\"landmark_trust_ns\":",stderr);
        if(timing.has_landmark_trust_ns)fprintf(stderr,"%llu",(unsigned long long)timing.landmark_trust_ns);
        else fputs("null",stderr);
        fputs(",\"standalone_signatures_ns\":",stderr);
        if(timing.has_standalone_signatures_ns)
            fprintf(stderr,"\"%llu\"",(unsigned long long)timing.standalone_signatures_ns);
        else fputs("null",stderr);
        fputs(",\"standalone_signature_count\":",stderr);
        if(timing.has_standalone_signatures_ns)
            fprintf(stderr,"%llu",(unsigned long long)timing.standalone_signature_count);
        else fputs("null",stderr);
        fputs(",\"standalone_signature_cache_ns\":null",stderr);
        fputs(",\"standalone_signature_cache_hits\":null",stderr);
        fputs(",\"standalone_signature_cache_misses\":null",stderr);
        fputs(",\"mtc_verification_mode\":",stderr);
        if(timing.has_verification_mode)
            fprintf(stderr,"\"%s\"",timing.verification_mode==MTC_VERIFICATION_MODE_LANDMARK?"landmark":"standalone");
        else fputs("null",stderr);
        fprintf(stderr,",\"mtc_success\":%s}\n",timing.mtc_success?"true":"false");
    }
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
        && strcmp(oid,"1.3.6.1.5.5.7.6.67")==0;
}
static int mtc_security(const SSL *ssl,const SSL_CTX *ctx,int op,int bits,int nid,void *other,void *ex){
    const SSL_CTX *active=ctx?ctx:(ssl?SSL_get_SSL_CTX(ssl):NULL);
    TLSEndpointConfig *endpoint=
        ci>=0 && active?SSL_CTX_get_ex_data(active,ci):NULL;
    TLSConfig *c=endpoint?endpoint->present:NULL;
    MTCServerCandidates *candidates=candidates_ci>=0&&active
        ?SSL_CTX_get_ex_data(active,candidates_ci):NULL;
    SecurityCallback previous=c?c->previous_security:
        candidates?candidates->previous_security:NULL;

    if((c||candidates) && op==SSL_SECOP_CA_MD && other){
        const X509_ALGOR *alg=NULL;X509 *cert=other;
        X509_get0_signature(NULL,&alg,cert);
        if(proof_algorithm(alg)
            && proof_algorithm(X509_get0_tbs_sigalg(cert)))
            return 1;
    }

    return previous
        ? previous(ssl,ctx,op,bits,nid,other,ex)
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

    size_t request_n=(c->role==MTC_ROLE_CLIENT_VERIFY_SERVER
                      || c->role==MTC_ROLE_CLIENT_PRESENT)
                     && c->has_group ? c->group_n : c->n;
    put(c->list,request_n+1,2);
    c->list[2]=(unsigned char)request_n;
    memcpy(c->list+3,
        (c->role==MTC_ROLE_CLIENT_VERIFY_SERVER
            || c->role==MTC_ROLE_CLIENT_PRESENT)
            && c->has_group ? c->group : c->id,
        request_n);
    c->list_n=request_n+3;

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
static void json_space(const unsigned char **p,const unsigned char *end){
    while(*p<end&&(**p==' '||**p=='\t'||**p=='\n'||**p=='\r'))(*p)++;
}
static int json_byte(const unsigned char **p,const unsigned char *end,
                     unsigned char value){
    json_space(p,end);
    if(*p==end||**p!=value)return 0;
    (*p)++;
    return 1;
}
static int json_key(const unsigned char **p,const unsigned char *end,
                    const char **key){
    static const char log_number[]="log_number";
    static const char retained_landmark[]="retained_landmark";
    const unsigned char *start;size_t n;
    if(!json_byte(p,end,'\"'))return 0;
    start=*p;
    while(*p<end&&**p!='\"'){
        if(**p<' '||**p=='\\')return 0;
        (*p)++;
    }
    if(*p==end)return 0;
    n=(size_t)(*p-start);(*p)++;
    if(n==sizeof(log_number)-1&&!memcmp(start,log_number,n))
        *key=log_number;
    else if(n==sizeof(retained_landmark)-1
            &&!memcmp(start,retained_landmark,n))
        *key=retained_landmark;
    else return 0;
    return json_byte(p,end,':');
}
static int json_uint(const unsigned char **p,const unsigned char *end,
                     uint64_t *value){
    uint64_t result=0;const unsigned char *start;
    json_space(p,end);start=*p;
    if(start==end||*start<'0'||*start>'9')return 0;
    if(*start=='0'&&start+1<end&&start[1]>='0'&&start[1]<='9')return 0;
    while(*p<end&&**p>='0'&&**p<='9'){
        unsigned digit=(unsigned)(**p-'0');
        if(result>(UINT64_MAX-digit)/10)return 0;
        result=result*10+digit;(*p)++;
    }
    *value=result;
    return 1;
}
static int retained_landmark_json(const char *path,uint64_t expected_log,
                                  uint64_t *retained){
    unsigned char data[1025];size_t n;FILE *f=fopen(path,"rb");int read_ok;
    const unsigned char *p,*end;
    int have_log=0,have_landmark=0,landmark_is_null=0;
    uint64_t log_number=0,landmark_number=0;
    if(!f)return 0;
    n=fread(data,1,sizeof(data),f);
    read_ok=!ferror(f)&&n<sizeof(data)&&fgetc(f)==EOF;
    if(fclose(f)||!read_ok)return 0;
    p=data;end=data+n;
    if(!json_byte(&p,end,'{'))return 0;
    for(int field=0;field<2;field++){
        const char *key;
        if(field&&!json_byte(&p,end,','))return 0;
        if(!json_key(&p,end,&key))return 0;
        if(!strcmp(key,"log_number")){
            if(have_log||!json_uint(&p,end,&log_number))return 0;
            have_log=1;
        }else{
            json_space(&p,end);
            if(have_landmark)return 0;
            if((size_t)(end-p)>=4&&!memcmp(p,"null",4)){
                p+=4;landmark_is_null=1;
            }
            else if(!json_uint(&p,end,&landmark_number))return 0;
            have_landmark=1;
        }
    }
    if(!json_byte(&p,end,'}'))return 0;
    json_space(&p,end);
    if(p!=end||!have_log||!have_landmark
       ||log_number<1||log_number>65535||log_number!=expected_log
       ||(!landmark_is_null&&!landmark_number)
       ||landmark_number>=(1ULL<<48))return 0;
    *retained=landmark_number;
    return 1;
}
static int rp_landmark_path(const char *mts1,char **metadata){
    const char *file=strrchr(mts1,'/'),*generation,*generations;
    size_t parent_n;char *path;int n;
    *metadata=NULL;
    if(!file||strcmp(file+1,"trusted-subtrees.mts1"))return 0;
    generation=file;
    while(generation>mts1&&generation[-1]!='/')generation--;
    if(generation==mts1||generation==file)return 0;
    generations=generation-1;
    while(generations>mts1&&generations[-1]!='/')generations--;
    if((size_t)((generation-1)-generations)!=11
       ||memcmp(generations,"generations",11))return 0;
    parent_n=(size_t)(file-mts1);
    path=OPENSSL_malloc(parent_n+1+sizeof("retained-landmark.json"));
    if(!path)return -1;
    n=snprintf(path,parent_n+1+sizeof("retained-landmark.json"),
               "%.*s/retained-landmark.json",(int)parent_n,mts1);
    if(n<0||(size_t)n>=parent_n+1+sizeof("retained-landmark.json")){
        OPENSSL_free(path);return -1;
    }
    *metadata=path;
    return 1;
}
static int mtc_client_configure(SSL_CTX *ctx,const char *path,int landmark,
                                const char *trusted_subtrees,
                                const char *certificate,const char *root){
    TLSConfig *c=OPENSSL_zalloc(sizeof(*c));
    char request[120],*canonical=NULL,*metadata=NULL;int request_n,recognized;
    uint64_t retained_landmark=0;struct stat st;
    if(!c)return 0;

    c->trust=landmark?mtc_load_trust_config_with_ca_v2(path,certificate,root)
                     :mtc_load_authority_config_with_ca_v2(path,certificate,root);
    if(!c->trust){
        OPENSSL_free(c);
        return 0;
    }

    /*
     * MTS1 is already-validated relying-party state.  Load it once while
     * configuring the SSL_CTX; handshakes only consult MTCConfig in memory.
     */
    if(trusted_subtrees){
        canonical=realpath(trusted_subtrees,NULL);
        if(!c->trust->landmark||!canonical
           ||!mtc_load_trusted_subtrees(c->trust,canonical))goto error;
        recognized=rp_landmark_path(canonical,&metadata);
        if(recognized<0)goto error;
        if(recognized){
            if(lstat(metadata,&st)){
                if(errno!=ENOENT)goto error;
            }else if(!S_ISREG(st.st_mode)
                     ||!retained_landmark_json(metadata,c->trust->log,
                                               &retained_landmark))goto error;
        }
    }

    c->role=MTC_ROLE_CLIENT_VERIFY_SERVER;
    c->purpose=X509_PURPOSE_SSL_SERVER;
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
    c->n=c->trust->signal_len;
    if(!c->n||c->n>32)goto error;
    memcpy(c->id,c->trust->signal,c->n);

    if(c->trust->landmark){
        if(retained_landmark){
            request_n=snprintf(request,sizeof(request),"%s.2.%llu.%llu",
                c->trust->caid,(unsigned long long)c->trust->log,
                (unsigned long long)retained_landmark);
            if(request_n<=0||request_n>=(int)sizeof(request)
                || !id_encode(request,c->group,&c->group_n)
                || c->group_n>32){
                goto error;
            }
        }else if(!id_encode(c->trust->caid,c->group,&c->group_n)
                 ||c->group_n>32){
            goto error;
        }
        c->has_group=1;
    }

    OPENSSL_free(metadata);
    free(canonical);
    return install(ctx,c);
error:
    OPENSSL_free(metadata);
    free(canonical);
    mtc_free(c->trust);
    OPENSSL_free(c);
    return 0;
}
int mtc_client(SSL_CTX *ctx,const char *path,int landmark,
               const char *trusted_subtrees,const char *certificate,
               const char *root){
    if(!certificate||!root)return 0;
    return mtc_client_configure(ctx,path,landmark,trusted_subtrees,certificate,root);
}
int mtc_server(SSL_CTX *ctx,const char *id){
    if(!ctx||!id||(candidates_ci>=0
       &&SSL_CTX_get_ex_data(ctx,candidates_ci)))return 0;
    TLSConfig *c=OPENSSL_zalloc(sizeof(*c));if(!c)return 0;c->role=MTC_ROLE_SERVER_PRESENT;
    if(!id_encode(id,c->id,&c->n)||c->n>32){OPENSSL_free(c);return 0;}c->has_group=initial_group(c);c->group_n=c->has_group?c->n:0;return install(ctx,c);
}
static int mtc_server_add_candidate_unchecked(SSL_CTX *ctx,const char *id,
                                              X509 *certificate,EVP_PKEY *key){
    MTCServerCandidates *set;
    MTCServerCandidate item={0};
    size_t base_n;uint64_t kind,log,landmark;

    if(!ctx||!id||!certificate||!key||strlen(id)>=sizeof(item.id_text)
       ||(ci>=0&&SSL_CTX_get_ex_data(ctx,ci))
       ||!X509_check_private_key(certificate,key)
       ||!id_encode(id,item.identity.id,&item.identity.n)
       ||item.identity.n>32)
        return 0;
    item.identity.has_group=initial_group(&item.identity);
    if(item.identity.has_group){
        if(!landmark_id_parts(item.identity.id,item.identity.n,
                              &base_n,&kind,&log,&landmark)
           ||kind!=1||!log||!landmark)return 0;
    }
    if(candidates_ci<0)
        candidates_ci=SSL_CTX_get_ex_new_index(0,NULL,NULL,NULL,
                                               candidates_free);
    if(candidates_ci<0)return 0;
    set=SSL_CTX_get_ex_data(ctx,candidates_ci);
    if(set){
        MTCServerCandidate *other;
        if(set->count!=1)return 0;
        other=&set->items[0];
        if(other->identity.has_group==item.identity.has_group
           ||!same_server_identity(other->certificate,certificate))
            return 0;
        /* Both credentials must belong to the same CA ID. */
        if(item.identity.has_group){
            if(base_n!=other->identity.n
               ||memcmp(item.identity.id,other->identity.id,base_n))return 0;
        }else{
            if(!landmark_id_parts(other->identity.id,other->identity.n,
                                  &base_n,&kind,&log,&landmark)
               ||base_n!=item.identity.n
               ||memcmp(item.identity.id,other->identity.id,base_n))return 0;
        }
        if(si<0)si=SSL_get_ex_new_index(0,NULL,NULL,NULL,state_free);
        if(si<0)return 0;
    }
    if(!X509_up_ref(certificate))return 0;
    if(!EVP_PKEY_up_ref(key)){X509_free(certificate);return 0;}
    item.certificate=certificate;
    item.key=key;
    memcpy(item.id_text,id,strlen(id)+1);
    if(!set){
        set=OPENSSL_zalloc(sizeof(*set));
        if(!set||!SSL_CTX_set_ex_data(ctx,candidates_ci,set)){
            OPENSSL_free(set);X509_free(certificate);EVP_PKEY_free(key);
            return 0;
        }
    }
    set->items[set->count++]=item;
    if(set->count==2){
        if(!candidates_available_list(set)
           ||!SSL_CTX_add_custom_ext(ctx,MTC_EXT,CONTEXT,
                                     candidates_add,NULL,set,
                                     candidates_parse,set)){
            set->count=1;
            X509_free(item.certificate);
            EVP_PKEY_free(item.key);
            memset(&set->items[1],0,sizeof(set->items[1]));
            return 0;
        }
        set->previous_security=SSL_CTX_get_security_callback(ctx);
        SSL_CTX_set_security_callback(ctx,mtc_security);
        SSL_CTX_set_client_hello_cb(ctx,mtc_server_client_hello,set);
        SSL_CTX_set_cert_cb(ctx,mtc_server_certificate_cb,set);
    }
    return 1;
}
static int candidate_proof_mode(X509 *certificate,int landmark){
    const ASN1_BIT_STRING *signature=NULL;
    const X509_ALGOR *signature_algorithm=NULL;
    Slice p,extensions,proof,signatures;
    uint64_t start,end;
    size_t signature_count;
    if(!certificate||!algorithm(X509_get0_tbs_sigalg(certificate)))
        return 0;
    X509_get0_signature(&signature,&signature_algorithm,certificate);
    if(!signature||!algorithm(signature_algorithm)
       ||(signature->flags&7)||signature->length<0)return 0;
    p=(Slice){signature->data,(size_t)signature->length};
    if(!vector(&p,2,&extensions)||!mtc_extensions(extensions)
       ||!number(&p,6,&start)||!number(&p,6,&end)
       ||!vector(&p,2,&proof)||!vector(&p,3,&signatures)||p.n
       ||!signature_block_v2(signatures,&signature_count))return 0;
    return landmark?signature_count==0:signature_count>0;
}
int mtc_server_add_candidate(SSL_CTX *ctx,const char *id,
                             X509 *certificate,EVP_PKEY *key,
                             const char *trust_path,const char *mtc_ca_path,
                             const char *representation_root_path){
    unsigned char encoded[80];size_t encoded_n;
    TLSConfig identity={0};
    MTCConfig *trust=NULL;
    int landmark,ok=0;
    if(!ctx||!id||!certificate||!key||!trust_path||!mtc_ca_path
       ||!representation_root_path
       ||!id_encode(id,encoded,&encoded_n)||encoded_n>32)return 0;
    memcpy(identity.id,encoded,encoded_n);
    identity.n=encoded_n;
    landmark=initial_group(&identity);
    trust=landmark
        ?mtc_load_trust_config_with_ca_v2(trust_path,mtc_ca_path,
                                          representation_root_path)
        :mtc_load_authority_config_with_ca_v2(trust_path,mtc_ca_path,
                                              representation_root_path);
    if(trust&&trust->landmark==landmark
       &&trust->signal_len==encoded_n
       &&!memcmp(trust->signal,encoded,encoded_n)
       &&X509_cmp_current_time(X509_get0_notBefore(certificate))<0
       &&X509_cmp_current_time(X509_get0_notAfter(certificate))>0
       &&candidate_proof_mode(certificate,landmark)
       &&mtc_verify(certificate,trust))
        ok=mtc_server_add_candidate_unchecked(ctx,id,certificate,key);
    mtc_free(trust);
    return ok;
}
static int mtc_server_verify_client_configure(SSL_CTX *ctx,const char *path,
                                              int landmark,
                                              const char *certificate,
                                              const char *root){
    TLSConfig *c=OPENSSL_zalloc(sizeof(*c));if(!c)return 0;
    c->trust=landmark?mtc_load_trust_config_with_ca_v2(path,certificate,root)
                     :mtc_load_authority_config_with_ca_v2(path,certificate,root);
    if(!c->trust){OPENSSL_free(c);return 0;}
    c->role=MTC_ROLE_SERVER_VERIFY_CLIENT;c->purpose=X509_PURPOSE_SSL_CLIENT;
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,NULL);
    c->n=c->trust->signal_len;
    if(!c->n||c->n>32){mtc_free(c->trust);OPENSSL_free(c);return 0;}
    memcpy(c->id,c->trust->signal,c->n);
    if(c->trust->landmark){
        c->has_group=initial_group(c);
        if(!c->has_group){mtc_free(c->trust);OPENSSL_free(c);return 0;}
        c->group_n=c->n;
    }
    return install(ctx,c);
}
int mtc_server_verify_client(SSL_CTX *ctx,const char *path,int landmark,
                             const char *certificate,const char *root){
    if(!ctx||!certificate||!root
       ||(candidates_ci>=0&&SSL_CTX_get_ex_data(ctx,candidates_ci)))return 0;
    return mtc_server_verify_client_configure(ctx,path,landmark,certificate,root);
}

int mtc_client_present(SSL_CTX *ctx,const char *id,int landmark){
    TLSConfig *c=OPENSSL_zalloc(sizeof(*c));
    if(!c)return 0;
    c->role=MTC_ROLE_CLIENT_PRESENT;
    if(!id_encode(id,c->id,&c->n)||c->n>32){
        OPENSSL_free(c);
        return 0;
    }
    if(landmark){
        c->has_group=initial_group(c);
        if(!c->has_group){
            OPENSSL_free(c);
            return 0;
        }
        c->group_n=c->n;
    }
    return install(ctx,c);
}
