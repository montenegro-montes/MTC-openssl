#include "mtc.h"
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
typedef struct { const unsigned char *p; size_t n; } Slice;
typedef struct { Slice raw,body; unsigned tag; } TLV;
typedef struct { char id[80]; unsigned char binary[80];size_t idlen; EVP_PKEY *key; } Signer;
typedef struct { uint64_t start,end; unsigned char hash[32]; } Subtree;
typedef struct { uint64_t log,start,end; unsigned char hash[32]; } TrustedSubtree;
typedef struct { uint64_t first,last; } RevokedRange;
typedef struct {
    char id[256];
    unsigned char binary[255];size_t idlen;
    unsigned char *spki;size_t spki_len;
} AuthoritySignerV2;
struct mtc_authority_v2 {
    char caid[256];
    AuthoritySignerV2 *signers;size_t count;
    uint64_t log,min,max;
};
struct mtc_checkpoint_v2 {
    uint64_t size,timestamp;
    unsigned char root[32];
    unsigned char *signatures;size_t signatures_len,signature_count;
    Subtree subs[2];
};
struct mtc_trust_bundle_v2 {
    MTCAuthorityV2 *authority;
    MTCCheckpointV2 *checkpoint;
    int has_landmark;
    uint64_t landmark;
};
#define MTC_MAX_TRUSTED_SUBTREES 64
#define MTC_MAX_REVOKED_RANGES 64
struct mtc_config {
    char caid[80]; Signer signers[2]; unsigned count; int landmark;
    uint64_t log,min,max,number,size,timestamp; unsigned char root[32];
    Subtree subs[2];unsigned nsubs;
    TrustedSubtree trusted[MTC_MAX_TRUSTED_SUBTREES];unsigned ntrusted;
    RevokedRange revoked[MTC_MAX_REVOKED_RANGES];unsigned nrevoked;
    size_t file_bytes;
    unsigned char signal[90];size_t signal_len; /* CA or individual landmark */
    unsigned char request_signal[90];size_t request_signal_len; /* CA or group */
};
static double tick(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000.0+t.tv_nsec/1e6;}
static int elapsed_monotonic_ns(const struct timespec *start,uint64_t *elapsed){
    struct timespec end;uint64_t seconds,nanoseconds;
    if(!start||!elapsed||clock_gettime(CLOCK_MONOTONIC,&end)||
       end.tv_sec<start->tv_sec)return 0;
    seconds=(uint64_t)(end.tv_sec-start->tv_sec);
    if(end.tv_nsec<start->tv_nsec){
        if(!seconds)return 0;
        seconds--;nanoseconds=1000000000ULL+(uint64_t)end.tv_nsec-(uint64_t)start->tv_nsec;
    }else nanoseconds=(uint64_t)(end.tv_nsec-start->tv_nsec);
    if(seconds>UINT64_MAX/1000000000ULL)return 0;
    *elapsed=seconds*1000000000ULL+nanoseconds;return 1;
}
static int take(Slice *s,size_t n,Slice *out){if(n>s->n)return 0;out->p=s->p;out->n=n;s->p+=n;s->n-=n;return 1;}
static int number(Slice *s,unsigned n,uint64_t *v){Slice x;if(!take(s,n,&x))return 0;*v=0;for(unsigned i=0;i<n;i++)*v=(*v<<8)|x.p[i];return 1;}
static int vector(Slice *s,unsigned width,Slice *out){uint64_t n;return number(s,width,&n)&&take(s,(size_t)n,out);}
static int mtc_extensions(Slice extensions){
    uint64_t type,previous=0;Slice value;int first=1;
    while(extensions.n){
        if(!number(&extensions,2,&type)||!vector(&extensions,2,&value)||
           (!first&&type<=previous))return 0;
        first=0;previous=type;
    }
    return 1;
}
static int tlv(Slice *s,TLV *t){
    const unsigned char *begin=s->p;uint64_t tag,n,k;Slice b;
    if(!number(s,1,&tag)||(tag&31)==31||!number(s,1,&n))return 0;
    if(n&128){k=n&127;if(!k||k>4||s->n<k||s->p[0]==0||!number(s,(unsigned)k,&n)||n<128)return 0;}
    if(!take(s,(size_t)n,&b))return 0;
    t->raw=(Slice){begin,(size_t)(s->p-begin)};t->body=b;t->tag=(unsigned)tag;return 1;
}
static int hash(Slice in,unsigned char out[32]){unsigned n;return EVP_Digest(in.p,in.n,out,&n,EVP_sha256(),NULL)&&n==32;}
static int node(const unsigned char *a,const unsigned char *b,unsigned char out[32]){unsigned char in[65];in[0]=1;memcpy(in+1,a,32);memcpy(in+33,b,32);return hash((Slice){in,65},out);}
static int valid_subtree(uint64_t start,uint64_t end){uint64_t k=1;if(start>end||end>=((uint64_t)1<<48))return 0;while(k<end-start)k<<=1;return !(start%k);}
int mtc_eval(const unsigned char leaf[32],uint64_t index,uint64_t start,uint64_t end,const unsigned char *proof,size_t n,unsigned char out[32]){
    uint64_t fn,sn;if(!valid_subtree(start,end)||index<start||index>=end||n%32)return 0;
    fn=index-start;sn=end-start-1;memcpy(out,leaf,32);
    for(size_t i=0;i<n;i+=32){
        if(!sn)return 0;
        if((fn&1)||fn==sn){if(!node(proof+i,out,out))return 0;while(!(fn&1)){fn>>=1;sn>>=1;}}
        else if(!node(out,proof+i,out))return 0;
        fn>>=1;sn>>=1;
    }return sn==0;
}
static void put(unsigned char *p,uint64_t n,unsigned size){while(size){p[--size]=(unsigned char)n;n>>=8;}}
static int id_encode_bounded(const char *s,unsigned char *out,size_t capacity,size_t *n){
    size_t j=0;const char *p=s;*n=0;
    while(*p){char *end;unsigned long long v;unsigned char b[10];unsigned k=0;
        if(*p<'0'||*p>'9'||(*p=='0'&&p[1]&&p[1]!='.'))return 0;
        errno=0;
        v=strtoull(p,&end,10);
        if(errno==ERANGE||end==p||(*end&&*end!='.'))return 0;
        b[k++]=(unsigned char)(v&127);while((v>>=7))b[k++]=(unsigned char)((v&127)|128);
        if(j+k>capacity)return 0;
        while(k)out[j++]=b[--k];
        p=*end?end+1:end;if(*end&&! *p)return 0;
    }*n=j;return j>0;
}
static int id_encode(const char *s,unsigned char *out,size_t *n){return id_encode_bounded(s,out,80,n);}
static int id_valid(Slice id){
    uint64_t value=0;int first=1;
    if(!id.n)return 0;
    for(size_t i=0;i<id.n;i++){
        unsigned char b=id.p[i];
        if(first&&b==0x80)return 0;
        if(value>(UINT64_MAX>>7)||
           (value==(UINT64_MAX>>7)&&(uint64_t)(b&127)>(UINT64_MAX&127)))return 0;
        value=(value<<7)|(b&127);first=!(b&128);
        if(first)value=0;
    }
    return first;
}
/* Keep the exact anchor for EE/confirmation/retry separate from initial CH. */
static int config_signals(MTCConfig *c){
    char id[80];int n;
    if(!c->landmark){
        if(!id_encode(c->caid,c->signal,&c->signal_len))return 0;
        memcpy(c->request_signal,c->signal,c->signal_len);
        c->request_signal_len=c->signal_len;return 1;
    }
    if(!c->log||!c->number||c->log>0xffffffffULL
       ||c->number>=(1ULL<<48))return 0;
    n=snprintf(id,sizeof(id),"%s.1.%llu.%llu",c->caid,
               (unsigned long long)c->log,(unsigned long long)c->number);
    if(n<=0||n>=(int)sizeof(id)||!id_encode(id,c->signal,&c->signal_len))return 0;
    n=snprintf(id,sizeof(id),"%s.2.%llu.%llu",c->caid,
               (unsigned long long)c->log,(unsigned long long)c->number);
    return n>0&&n<(int)sizeof(id)&&id_encode(id,c->request_signal,&c->request_signal_len);
}
static int message_fields(const char *caid,uint64_t log_number,const char *signer_id,
                          uint64_t start,uint64_t end,const unsigned char root[32],
                          uint64_t timestamp,unsigned char *out,size_t *n){
    char cos[300],log[320];int a=snprintf(cos,sizeof(cos),"oid/1.3.6.1.4.1.%s",signer_id),b=snprintf(log,sizeof(log),"oid/1.3.6.1.4.1.%s.0.%llu",caid,(unsigned long long)log_number);size_t pos=0;
    if(a<=0||a>255||b<=0||b>255)return 0;
    memcpy(out,"subtree/v1\n\0",12);pos=12;out[pos++]=(unsigned char)a;memcpy(out+pos,cos,a);pos+=a;
    put(out+pos,timestamp,8);pos+=8;out[pos++]=(unsigned char)b;memcpy(out+pos,log,b);pos+=b;
    put(out+pos,start,8);pos+=8;put(out+pos,end,8);pos+=8;memcpy(out+pos,root,32);*n=pos+32;return 1;
}
static int message(const MTCConfig *c,const Signer *signer,uint64_t start,uint64_t end,const unsigned char root[32],uint64_t timestamp,unsigned char *out,size_t *n){
    return message_fields(c->caid,c->log,signer->id,start,end,root,timestamp,out,n);
}
/* Signer policy only. The Merkle tree and leaf hashes remain SHA-256. */
static const char *ec_signer_digest(EVP_PKEY *key){
    char group[80];size_t length=0;
    if(!key || !EVP_PKEY_is_a(key,"EC") ||
       !EVP_PKEY_get_utf8_string_param(key,OSSL_PKEY_PARAM_GROUP_NAME,group,sizeof(group),&length))return NULL;
    if(!strcmp(group,"prime256v1") || !strcmp(group,"secp256r1") || !strcmp(group,"P-256"))return "SHA256";
    if(!strcmp(group,"secp384r1") || !strcmp(group,"P-384"))return "SHA384";
    if(!strcmp(group,"secp521r1") || !strcmp(group,"P-521"))return "SHA512";
    return NULL;
}
static int supported_signer_key(EVP_PKEY *key){
    static const char *names[]={"mldsa44","ML-DSA-44","mldsa65","ML-DSA-65","mldsa87","ML-DSA-87",
        "slhdsasha2128s","SLH-DSA-SHA2-128s","slhdsasha2192s","SLH-DSA-SHA2-192s","slhdsasha2256s","SLH-DSA-SHA2-256s"};
    if(!key)return 0;
    if(EVP_PKEY_is_a(key,"EC"))return ec_signer_digest(key)!=NULL;
    for(size_t i=0;i<sizeof(names)/sizeof(names[0]);i++)if(EVP_PKEY_is_a(key,names[i]))return 1;
    return 0;
}
static const char *signer_algorithm_oid(EVP_PKEY *key){
    if(!key)return NULL;
    if(EVP_PKEY_is_a(key,"EC")){
        const char *digest=ec_signer_digest(key);
        if(!digest)return NULL;
        if(!strcmp(digest,"SHA256"))return "1.2.840.10045.4.3.2";
        if(!strcmp(digest,"SHA384"))return "1.2.840.10045.4.3.3";
        if(!strcmp(digest,"SHA512"))return "1.2.840.10045.4.3.4";
        return NULL;
    }
    if(EVP_PKEY_is_a(key,"mldsa44")||EVP_PKEY_is_a(key,"ML-DSA-44"))return "2.16.840.1.101.3.4.3.17";
    if(EVP_PKEY_is_a(key,"mldsa65")||EVP_PKEY_is_a(key,"ML-DSA-65"))return "2.16.840.1.101.3.4.3.18";
    if(EVP_PKEY_is_a(key,"mldsa87")||EVP_PKEY_is_a(key,"ML-DSA-87"))return "2.16.840.1.101.3.4.3.19";
    if(EVP_PKEY_is_a(key,"slhdsasha2128s")||EVP_PKEY_is_a(key,"SLH-DSA-SHA2-128s"))return "2.16.840.1.101.3.4.3.20";
    if(EVP_PKEY_is_a(key,"slhdsasha2192s")||EVP_PKEY_is_a(key,"SLH-DSA-SHA2-192s"))return "2.16.840.1.101.3.4.3.22";
    if(EVP_PKEY_is_a(key,"slhdsasha2256s")||EVP_PKEY_is_a(key,"SLH-DSA-SHA2-256s"))return "2.16.840.1.101.3.4.3.24";
    return NULL;
}
static void add_signature_timing(MTCVerificationTiming *timing,uint64_t elapsed){
    if(!timing||timing->standalone_signatures_overflow)return;
    if(timing->standalone_signature_count==UINT64_MAX||
       (timing->has_standalone_signatures_ns&&
        elapsed>UINT64_MAX-timing->standalone_signatures_ns)){
        timing->has_standalone_signatures_ns=0;
        timing->standalone_signatures_overflow=1;
        return;
    }
    if(!timing->has_standalone_signatures_ns){
        timing->standalone_signatures_ns=0;
        timing->has_standalone_signatures_ns=1;
    }
    timing->standalone_signatures_ns+=elapsed;
    timing->standalone_signature_count++;
}
static int sigcheck(MTCConfig *c,Slice sigs,uint64_t start,uint64_t end,const unsigned char root[32],uint64_t timestamp,MTCVerificationTiming *timing){
    Slice prev={NULL,0},id,sig;unsigned valid=0;unsigned char msg[400];size_t n;
    while(sigs.n){
        if(!vector(&sigs,1,&id)||!id.n||!vector(&sigs,2,&sig))return 0;
        if(prev.p&&(id.n<prev.n||(id.n==prev.n&&memcmp(id.p,prev.p,id.n)<=0)))return 0;
        /* A trust-anchor ID is a canonical series of base-128 integers. */
        for(size_t i=0;i<id.n;){if(id.p[i]==128)return 0;do{if(i==id.n)return 0;}while(id.p[i++]&128);}
        prev=id;
        for(unsigned i=0;i<c->count;i++)if(id.n==c->signers[i].idlen&&!memcmp(id.p,c->signers[i].binary,id.n)){
            EVP_MD_CTX *md=EVP_MD_CTX_new();Signer *s=&c->signers[i];int ok=0;
            if(md&&supported_signer_key(s->key)&&message(c,s,start,end,root,timestamp,msg,&n)&&EVP_DigestVerifyInit_ex(md,NULL,ec_signer_digest(s->key),NULL,NULL,s->key,NULL)){
                struct timespec signature_start;uint64_t elapsed;
                int clock_ok=clock_gettime(CLOCK_MONOTONIC,&signature_start)==0;
                ok=EVP_DigestVerify(md,sig.p,sig.n,msg,n)==1;
                if(timing){
                    if(clock_ok&&elapsed_monotonic_ns(&signature_start,&elapsed))
                        add_signature_timing(timing,elapsed);
                    else{
                        timing->has_standalone_signatures_ns=0;
                        timing->standalone_signatures_overflow=1;
                    }
                }
            }
            EVP_MD_CTX_free(md);if(ok)valid|=1u<<i;
        }
    }return valid==((1u<<c->count)-1);
}
void mtc_free(MTCConfig *c){if(c){for(unsigned i=0;i<2;i++)EVP_PKEY_free(c->signers[i].key);OPENSSL_free(c);}}
void mtc_free_authority_v2(MTCAuthorityV2 *authority){
    if(authority){
        if(authority->signers)
            for(size_t i=0;i<authority->count;i++)OPENSSL_free(authority->signers[i].spki);
        OPENSSL_free(authority->signers);OPENSSL_free(authority);
    }
}
void mtc_free_checkpoint_v2(MTCCheckpointV2 *checkpoint){
    if(checkpoint){OPENSSL_free(checkpoint->signatures);OPENSSL_free(checkpoint);}
}
void mtc_free_trust_bundle_v2(MTCTrustBundleV2 *bundle){
    if(bundle){mtc_free_authority_v2(bundle->authority);mtc_free_checkpoint_v2(bundle->checkpoint);OPENSSL_free(bundle);}
}

static int ascii_v2(Slice value,char out[256],unsigned char binary[255],size_t *binary_len){
    if(!value.n||value.n>255||memchr(value.p,0,value.n))return 0;
    memcpy(out,value.p,value.n);out[value.n]=0;
    return id_encode_bounded(out,binary,255,binary_len);
}

static MTCAuthorityV2 *parse_authority_v2(Slice input){
    MTCAuthorityV2 *authority=NULL;Slice s=input,x,spki;uint64_t count;
    unsigned char ca_binary[255];size_t ca_binary_len;
    if(!take(&s,4,&x)||memcmp(x.p,"MCA2",4)||!vector(&s,1,&x))return NULL;
    authority=OPENSSL_zalloc(sizeof(*authority));if(!authority)goto bad;
    if(!ascii_v2(x,authority->caid,ca_binary,&ca_binary_len)||
       !number(&s,2,&count)||s.n<18||count>(s.n-18)/6||
       count>SIZE_MAX/sizeof(*authority->signers))goto bad;
    if(count){
        authority->signers=OPENSSL_zalloc((size_t)count*sizeof(*authority->signers));
        if(!authority->signers)goto bad;
    }
    authority->count=(size_t)count;
    for(size_t i=0;i<authority->count;i++){
        AuthoritySignerV2 *signer=&authority->signers[i];
        if(!vector(&s,1,&x)||!ascii_v2(x,signer->id,signer->binary,&signer->idlen)||
           !vector(&s,3,&spki)||!spki.n)goto bad;
        for(size_t j=0;j<i;j++)if(signer->idlen==authority->signers[j].idlen&&
            !memcmp(signer->binary,authority->signers[j].binary,signer->idlen))goto bad;
        signer->spki=OPENSSL_memdup(spki.p,spki.n);signer->spki_len=spki.n;
        if(!signer->spki)goto bad;
    }
    if(!number(&s,2,&authority->log)||!authority->log||
       !number(&s,8,&authority->min)||!number(&s,8,&authority->max)||
       authority->max<authority->min||s.n)goto bad;
    return authority;
bad:
    mtc_free_authority_v2(authority);return NULL;
}

static int signature_block_v2(Slice signatures,size_t *count){
    Slice previous={NULL,0},identity,signature;size_t found=0;
    while(signatures.n){
        if(!vector(&signatures,1,&identity)||!id_valid(identity)||
           (previous.p&&(identity.n<previous.n||
            (identity.n==previous.n&&memcmp(identity.p,previous.p,identity.n)<=0)))||
           !vector(&signatures,2,&signature))return 0;
        previous=identity;found++;
    }
    *count=found;return 1;
}

static void checkpoint_cover(uint64_t size,uint64_t expected[4]){
    uint64_t mid;
    if(size<=1){expected[0]=0;expected[1]=size;expected[2]=size;expected[3]=size;return;}
    mid=1;while((mid<<1)<=size-1)mid<<=1;
    expected[0]=0;expected[1]=mid;expected[2]=mid;expected[3]=size;
}

static MTCCheckpointV2 *parse_checkpoint_v2(Slice input){
    MTCCheckpointV2 *checkpoint=NULL;Slice s=input,x,signature_block;
    uint64_t expected[4];unsigned char actual[32],empty[32];
    if(!take(&s,4,&x)||memcmp(x.p,"MCP2",4))return NULL;
    checkpoint=OPENSSL_zalloc(sizeof(*checkpoint));if(!checkpoint)goto bad;
    if(!number(&s,6,&checkpoint->size)||!checkpoint->size||
       !number(&s,8,&checkpoint->timestamp)||!take(&s,32,&x)||
       !vector(&s,3,&signature_block)||
       !signature_block_v2(signature_block,&checkpoint->signature_count))goto bad;
    memcpy(checkpoint->root,x.p,32);
    checkpoint->signatures=OPENSSL_memdup(signature_block.p,signature_block.n);
    checkpoint->signatures_len=signature_block.n;
    if(signature_block.n&&!checkpoint->signatures)goto bad;
    for(unsigned i=0;i<2;i++){
        if(!number(&s,6,&checkpoint->subs[i].start)||
           !number(&s,6,&checkpoint->subs[i].end)||!take(&s,32,&x))goto bad;
        memcpy(checkpoint->subs[i].hash,x.p,32);
    }
    if(s.n)goto bad;
    checkpoint_cover(checkpoint->size,expected);
    for(unsigned i=0;i<2;i++)if(checkpoint->subs[i].start!=expected[2*i]||
        checkpoint->subs[i].end!=expected[2*i+1])goto bad;
    if(checkpoint->size==1){
        if(!hash((Slice){(const unsigned char *)"",0},empty)||
           CRYPTO_memcmp(checkpoint->subs[1].hash,empty,32)||
           CRYPTO_memcmp(checkpoint->subs[0].hash,checkpoint->root,32))goto bad;
    }else if(!node(checkpoint->subs[0].hash,checkpoint->subs[1].hash,actual)||
             CRYPTO_memcmp(actual,checkpoint->root,32))goto bad;
    return checkpoint;
bad:
    mtc_free_checkpoint_v2(checkpoint);return NULL;
}

static MTCTrustBundleV2 *parse_trust_bundle_v2(Slice input){
    MTCTrustBundleV2 *bundle=NULL;Slice s=input,x,authority,checkpoint;uint64_t kind;
    if(!take(&s,4,&x)||memcmp(x.p,"MTB2",4)||!vector(&s,4,&authority)||
       !vector(&s,4,&checkpoint)||!number(&s,1,&kind))return NULL;
    bundle=OPENSSL_zalloc(sizeof(*bundle));if(!bundle)return NULL;
    bundle->authority=parse_authority_v2(authority);
    bundle->checkpoint=parse_checkpoint_v2(checkpoint);
    if(!bundle->authority||!bundle->checkpoint)goto bad;
    if(kind==0){if(s.n)goto bad;}
    else if(kind==1){
        if(!number(&s,6,&bundle->landmark)||!bundle->landmark||s.n)goto bad;
        bundle->has_landmark=1;
    }else goto bad;
    return bundle;
bad:
    mtc_free_trust_bundle_v2(bundle);return NULL;
}

static int read_v2_file(const char *path,unsigned char **data,size_t *length){
    FILE *file=NULL;long size;unsigned char *buffer=NULL;int ok=0;
    if(!path||!data||!length||(file=fopen(path,"rb"))==NULL)return 0;
    if(fseek(file,0,SEEK_END)||(size=ftell(file))<=0||
       (uint64_t)size>UINT32_MAX||fseek(file,0,SEEK_SET))goto end;
    buffer=OPENSSL_malloc((size_t)size);
    if(!buffer||fread(buffer,1,(size_t)size,file)!=(size_t)size)goto end;
    *data=buffer;*length=(size_t)size;buffer=NULL;ok=1;
end:
    OPENSSL_free(buffer);fclose(file);return ok;
}

MTCAuthorityV2 *mtc_load_authority_v2(const char *path){
    unsigned char *data=NULL;size_t length=0;MTCAuthorityV2 *result=NULL;
    if(read_v2_file(path,&data,&length))result=parse_authority_v2((Slice){data,length});
    OPENSSL_free(data);return result;
}
MTCConfig *mtc_load_authority_config_v2(const char *path){
    MTCAuthorityV2 *authority=mtc_load_authority_v2(path);MTCConfig *config=NULL;
    if(!authority)goto end;
    config=OPENSSL_zalloc(sizeof(*config));if(!config)goto end;
    if(!authority||authority->count!=2||strcmp(authority->caid,authority->signers[0].id)||
       !strcmp(authority->signers[0].id,authority->signers[1].id)||
       strlen(authority->caid)>=sizeof(((MTCConfig *)0)->caid)||
       strlen(authority->signers[0].id)>=sizeof(((Signer *)0)->id)||
       strlen(authority->signers[1].id)>=sizeof(((Signer *)0)->id)||
       authority->signers[0].idlen>sizeof(((Signer *)0)->binary)||
       authority->signers[1].idlen>sizeof(((Signer *)0)->binary)||
       authority->min!=(authority->log<<48)||authority->max<authority->min||
       authority->max-authority->min>=1024)goto invalid;
    memcpy(config->caid,authority->caid,strlen(authority->caid)+1);
    config->count=2;config->log=authority->log;config->min=authority->min;config->max=authority->max;
    for(unsigned i=0;i<2;i++){
        const AuthoritySignerV2 *source=&authority->signers[i];const unsigned char *p=source->spki;
        memcpy(config->signers[i].id,source->id,strlen(source->id)+1);
        memcpy(config->signers[i].binary,source->binary,source->idlen);
        config->signers[i].idlen=source->idlen;
        config->signers[i].key=d2i_PUBKEY(NULL,&p,(long)source->spki_len);
        if(!config->signers[i].key||p!=source->spki+source->spki_len||
           !supported_signer_key(config->signers[i].key)){
            goto invalid;
        }
    }
    if(!config_signals(config))goto invalid;
    goto end;
invalid:
    mtc_free(config);config=NULL;
end:
    mtc_free_authority_v2(authority);return config;
}

static int name_matches_id(X509_NAME *name,const char *id){
    static const unsigned char oid[]={0x2b,0x06,0x01,0x05,0x05,0x07,0x19,0x03};
    unsigned char expected[255],*der=NULL;size_t length;int ok=0,n;Slice s;TLV t;
    if(!name||!id||(n=i2d_X509_NAME(name,&der))<=0||
       !id_encode_bounded(id,expected,sizeof(expected),&length))goto end;
    s=(Slice){der,(size_t)n};
    if(!tlv(&s,&t)||s.n||t.tag!=0x30)goto end;
    s=t.body;
    if(!tlv(&s,&t)||s.n||t.tag!=0x31)goto end;
    s=t.body;
    if(!tlv(&s,&t)||s.n||t.tag!=0x30)goto end;
    s=t.body;
    if(!tlv(&s,&t)||t.tag!=6||t.body.n!=sizeof(oid)||memcmp(t.body.p,oid,sizeof(oid)))goto end;
    if(!tlv(&s,&t)||s.n||t.tag!=0x0d||t.body.n!=length||memcmp(t.body.p,expected,length))goto end;
    ok=1;
end:
    OPENSSL_free(der);return ok;
}

static int positive_integer_u64(TLV value,uint64_t *out){
    uint64_t result=0;size_t offset=0;
    if(value.tag!=2||!value.body.n||value.body.n>9||(value.body.p[0]&0x80))return 0;
    if(value.body.n>1&&value.body.p[0]==0&&!(value.body.p[1]&0x80))return 0;
    if(value.body.n==9){if(value.body.p[0]!=0)return 0;offset=1;}
    for(size_t i=offset;i<value.body.n;i++)result=(result<<8)|value.body.p[i];
    *out=result;return 1;
}

static int exact_critical_extension(X509 *certificate,const char *oid,
                                    const unsigned char *value,size_t length){
    ASN1_OBJECT *object=OBJ_txt2obj(oid,1);int index=-1,next;X509_EXTENSION *extension;
    const ASN1_OCTET_STRING *data;int ok=0;
    if(!object)goto end;
    index=X509_get_ext_by_OBJ(certificate,object,-1);
    if(index<0||(next=X509_get_ext_by_OBJ(certificate,object,index))>=0)goto end;
    extension=X509_get_ext(certificate,index);
    if(!extension)goto end;
    data=X509_EXTENSION_get_data(extension);
    if(!data||!X509_EXTENSION_get_critical(extension)||
       ASN1_STRING_length(data)!=(int)length||
       CRYPTO_memcmp(ASN1_STRING_get0_data(data),value,length))goto end;
    ok=1;
end:
    ASN1_OBJECT_free(object);return ok;
}

static int mtc_ca_extension(X509 *certificate,EVP_PKEY *key,
                            uint64_t *minimum,uint64_t *maximum){
    ASN1_OBJECT *object=OBJ_txt2obj("1.3.6.1.5.5.7.1.38",1);X509_EXTENSION *extension;
    const ASN1_OCTET_STRING *data;const unsigned char *p;X509_ALGOR *algorithm=NULL;
    const ASN1_OBJECT *algorithm_object;int parameter_type,index=-1,next,n,ok=0;char text[80];
    Slice s;TLV sequence,encoded_algorithm,min_value,max_value;const char *expected;
    if(!object||!key||(index=X509_get_ext_by_OBJ(certificate,object,-1))<0||
       (next=X509_get_ext_by_OBJ(certificate,object,index))>=0)goto end;
    extension=X509_get_ext(certificate,index);
    if(!extension)goto end;
    data=X509_EXTENSION_get_data(extension);
    if(!data||!X509_EXTENSION_get_critical(extension))goto end;
    s=(Slice){ASN1_STRING_get0_data(data),(size_t)ASN1_STRING_length(data)};
    if(!tlv(&s,&sequence)||s.n||sequence.tag!=0x30)goto end;
    s=sequence.body;
    if(!tlv(&s,&encoded_algorithm)||encoded_algorithm.tag!=0x30||
       !tlv(&s,&min_value)||!tlv(&s,&max_value)||s.n||
       !positive_integer_u64(min_value,minimum)||
       !positive_integer_u64(max_value,maximum)||
       *minimum<((uint64_t)1<<48)||*maximum<*minimum)goto end;
    p=encoded_algorithm.raw.p;n=(int)encoded_algorithm.raw.n;
    algorithm=d2i_X509_ALGOR(NULL,&p,n);
    if(!algorithm||p!=encoded_algorithm.raw.p+encoded_algorithm.raw.n)goto end;
    X509_ALGOR_get0(&algorithm_object,&parameter_type,NULL,algorithm);
    expected=signer_algorithm_oid(key);
    if(!expected||parameter_type!=V_ASN1_UNDEF||
       OBJ_obj2txt(text,sizeof(text),algorithm_object,1)<=0||strcmp(text,expected))goto end;
    ok=1;
end:
    X509_ALGOR_free(algorithm);ASN1_OBJECT_free(object);return ok;
}

static X509 *load_certificate(const char *path){
    BIO *bio=NULL;X509 *certificate=NULL;unsigned char *data=NULL;size_t length=0;
    const unsigned char *p;
    if(!path||(bio=BIO_new_file(path,"rb"))==NULL)return NULL;
    certificate=PEM_read_bio_X509(bio,NULL,NULL,NULL);BIO_free(bio);
    if(certificate)return certificate;
    if(read_v2_file(path,&data,&length)){
        p=data;certificate=d2i_X509(NULL,&p,(long)length);
        if(!certificate||p!=data+length){X509_free(certificate);certificate=NULL;}
    }
    OPENSSL_free(data);return certificate;
}

static int verify_mtc_ca_chain(X509 *certificate,const char *root_path){
    X509_STORE *store=NULL;X509_STORE_CTX *context=NULL;int ok=0;
    if(!certificate||!root_path||(store=X509_STORE_new())==NULL||
       !X509_STORE_load_locations(store,root_path,NULL)||
       (context=X509_STORE_CTX_new())==NULL||
       !X509_STORE_CTX_init(context,store,certificate,NULL)||
       !X509_VERIFY_PARAM_set_flags(X509_STORE_CTX_get0_param(context),
                                    X509_V_FLAG_IGNORE_CRITICAL))goto end;
    ok=X509_verify_cert(context)==1;
end:
    X509_STORE_CTX_free(context);X509_STORE_free(store);return ok;
}

static int supported_critical_extensions(X509 *certificate){
    static const char *allowed[]={"2.5.29.19","2.5.29.15","1.3.6.1.5.5.7.1.38"};
    int count=X509_get_ext_count(certificate);
    if(count<0)return 0;
    for(int i=0;i<count;i++){
        X509_EXTENSION *extension=X509_get_ext(certificate,i);char text[80];int known=0;
        if(!extension)return 0;
        if(!X509_EXTENSION_get_critical(extension))continue;
        if(OBJ_obj2txt(text,sizeof(text),X509_EXTENSION_get_object(extension),1)<=0)return 0;
        for(size_t j=0;j<sizeof(allowed)/sizeof(allowed[0]);j++)
            if(!strcmp(text,allowed[j])){known=1;break;}
        if(!known)return 0;
    }
    return 1;
}

static int authority_matches_mtc_ca(const MTCAuthorityV2 *authority,
                                    const char *certificate_path,
                                    const char *root_path){
    static const unsigned char basic_constraints[]={0x30,0x03,0x01,0x01,0xff};
    static const unsigned char key_usage[]={0x03,0x02,0x02,0x04};
    X509 *certificate=NULL;EVP_PKEY *certificate_key=NULL,*authority_key=NULL;
    const unsigned char *p;uint64_t minimum=0,maximum=0;int ok=0;
    certificate=load_certificate(certificate_path);
    if(!authority||!certificate||!supported_critical_extensions(certificate)||
       !verify_mtc_ca_chain(certificate,root_path)||!authority->count||
       strcmp(authority->caid,authority->signers[0].id)||
       !name_matches_id(X509_get_subject_name(certificate),authority->caid)||
       !exact_critical_extension(certificate,"2.5.29.19",basic_constraints,sizeof(basic_constraints))||
       !exact_critical_extension(certificate,"2.5.29.15",key_usage,sizeof(key_usage)))goto end;
    certificate_key=X509_get_pubkey(certificate);
    p=authority->signers[0].spki;
    authority_key=d2i_PUBKEY(NULL,&p,(long)authority->signers[0].spki_len);
    if(!certificate_key||!authority_key||p!=authority->signers[0].spki+authority->signers[0].spki_len||
       EVP_PKEY_eq(certificate_key,authority_key)!=1||
       !mtc_ca_extension(certificate,certificate_key,&minimum,&maximum)||
       minimum!=authority->min||maximum!=authority->max)goto end;
    ok=1;
end:
    EVP_PKEY_free(authority_key);EVP_PKEY_free(certificate_key);X509_free(certificate);return ok;
}

MTCConfig *mtc_load_authority_config_with_ca_v2(const char *path,
                                                const char *certificate_path,
                                                const char *root_path){
    MTCAuthorityV2 *authority=NULL;MTCConfig *config=NULL;
    authority=mtc_load_authority_v2(path);
    config=mtc_load_authority_config_v2(path);
    if(!config||!authority_matches_mtc_ca(authority,certificate_path,root_path))goto bad;
    goto end;
bad:
    mtc_free(config);config=NULL;
end:
    mtc_free_authority_v2(authority);return config;
}
MTCCheckpointV2 *mtc_load_checkpoint_v2(const char *path){
    unsigned char *data=NULL;size_t length=0;MTCCheckpointV2 *result=NULL;
    if(read_v2_file(path,&data,&length))result=parse_checkpoint_v2((Slice){data,length});
    OPENSSL_free(data);return result;
}
MTCTrustBundleV2 *mtc_load_trust_bundle_v2(const char *path){
    unsigned char *data=NULL;size_t length=0;MTCTrustBundleV2 *result=NULL;
    if(read_v2_file(path,&data,&length))result=parse_trust_bundle_v2((Slice){data,length});
    OPENSSL_free(data);return result;
}
int mtc_authenticate_checkpoint_v2(const MTCAuthorityV2 *authority,
                                   const MTCCheckpointV2 *checkpoint){
    unsigned char message_data[700];size_t message_len;
    if(!authority||!checkpoint||!authority->count)return 0;
    for(size_t i=0;i<authority->count;i++){
        const AuthoritySignerV2 *signer=&authority->signers[i];
        const unsigned char *key_data=signer->spki;EVP_PKEY *key=NULL;
        Slice records={checkpoint->signatures,checkpoint->signatures_len},identity,signature;
        int found=0,valid=0;
        key=d2i_PUBKEY(NULL,&key_data,(long)signer->spki_len);
        if(!key||key_data!=signer->spki+signer->spki_len||!supported_signer_key(key))goto signer_end;
        while(records.n){
            if(!vector(&records,1,&identity)||!vector(&records,2,&signature))goto signer_end;
            if(identity.n==signer->idlen&&!memcmp(identity.p,signer->binary,identity.n)){
                EVP_MD_CTX *md=EVP_MD_CTX_new();found=1;
                if(md&&message_fields(authority->caid,authority->log,signer->id,
                        0,checkpoint->size,checkpoint->root,checkpoint->timestamp,
                        message_data,&message_len)&&
                   EVP_DigestVerifyInit_ex(md,NULL,ec_signer_digest(key),NULL,NULL,key,NULL))
                    valid=EVP_DigestVerify(md,signature.p,signature.n,message_data,message_len)==1;
                EVP_MD_CTX_free(md);break;
            }
        }
signer_end:
        EVP_PKEY_free(key);
        if(!found||!valid)return 0;
    }
    return 1;
}
MTCConfig *mtc_load_trust_config_v2(const char *path){
    double begin=tick(),validation=0;MTCTrustBundleV2 *bundle=NULL;
    MTCConfig *config=NULL;FILE *file=NULL;long file_size=0;
    bundle=mtc_load_trust_bundle_v2(path);
    if(!bundle||!bundle->authority||!bundle->checkpoint)goto end;
    config=OPENSSL_zalloc(sizeof(*config));if(!config)goto end;
    {
        const MTCAuthorityV2 *authority=bundle->authority;
        const MTCCheckpointV2 *checkpoint=bundle->checkpoint;
        if(authority->count!=2||strcmp(authority->caid,authority->signers[0].id)||
           !strcmp(authority->signers[0].id,authority->signers[1].id)||
           strlen(authority->caid)>=sizeof(config->caid)||
           authority->min!=(authority->log<<48)||authority->max<authority->min||
           authority->max-authority->min>=1024||!checkpoint->size||
           checkpoint->size>1024||authority->max!=authority->min+checkpoint->size-1||
           !checkpoint->timestamp||checkpoint->timestamp>(uint64_t)time(NULL))goto invalid;
        memcpy(config->caid,authority->caid,strlen(authority->caid)+1);
        config->count=2;config->log=authority->log;
        config->min=authority->min;config->max=authority->max;
        for(unsigned i=0;i<2;i++){
            const AuthoritySignerV2 *source=&authority->signers[i];
            const unsigned char *key_data=source->spki;
            if(strlen(source->id)>=sizeof(config->signers[i].id)||
               source->idlen>sizeof(config->signers[i].binary))goto invalid;
            memcpy(config->signers[i].id,source->id,strlen(source->id)+1);
            memcpy(config->signers[i].binary,source->binary,source->idlen);
            config->signers[i].idlen=source->idlen;
            config->signers[i].key=d2i_PUBKEY(NULL,&key_data,(long)source->spki_len);
            if(!config->signers[i].key||key_data!=source->spki+source->spki_len||
               !supported_signer_key(config->signers[i].key))goto invalid;
        }
        {
            double verify_begin=tick();
            if(!mtc_authenticate_checkpoint_v2(authority,checkpoint))goto invalid;
            validation=tick()-verify_begin;
        }
        config->size=checkpoint->size;config->timestamp=checkpoint->timestamp;
        memcpy(config->root,checkpoint->root,32);
        config->nsubs=2;
        for(unsigned i=0;i<2;i++)config->subs[i]=checkpoint->subs[i];
        config->landmark=bundle->has_landmark;
        config->number=bundle->has_landmark?bundle->landmark:0;
        if(!config_signals(config))goto invalid;
    }
    file=fopen(path,"rb");
    if(!file||fseek(file,0,SEEK_END)||(file_size=ftell(file))<=0)goto invalid;
    config->file_bytes=(size_t)file_size;
    fclose(file);file=NULL;
    fprintf(stderr,"MTC_SETUP {\"mtc_setup_ms\":%.6f,\"mtc_trust_validation_ms\":%.6f,\"mtc_predistributed_bytes\":%zu,\"mtc_trust_file_bytes\":%zu}\n",tick()-begin,validation,config->landmark?config->file_bytes:0,config->file_bytes);
    goto end;
invalid:
    if(file)fclose(file);
    mtc_free(config);config=NULL;
end:
    mtc_free_trust_bundle_v2(bundle);return config;
}
MTCConfig *mtc_load_trust_config_with_ca_v2(const char *path,
                                            const char *certificate_path,
                                            const char *root_path){
    MTCTrustBundleV2 *bundle=mtc_load_trust_bundle_v2(path);
    MTCConfig *config=NULL;
    if(bundle&&authority_matches_mtc_ca(bundle->authority,certificate_path,root_path))
        config=mtc_load_trust_config_v2(path);
    mtc_free_trust_bundle_v2(bundle);return config;
}
int mtc_add_trusted_subtree(MTCConfig *c,uint64_t log_number,
                            uint64_t start,uint64_t end,
                            const unsigned char hash_value[32]){
    TrustedSubtree *sub;
    if(!c||!c->landmark||!hash_value||!log_number||log_number>0xffff||
       log_number!=c->log||!valid_subtree(start,end)||
       c->ntrusted>=MTC_MAX_TRUSTED_SUBTREES)
        return 0;
    for(unsigned i=0;i<c->ntrusted;i++)
        if(c->trusted[i].log==log_number&&
           c->trusted[i].start==start&&c->trusted[i].end==end)
            return 0;
    sub=&c->trusted[c->ntrusted++];
    sub->log=log_number;sub->start=start;sub->end=end;
    memcpy(sub->hash,hash_value,32);
    return 1;
}

static int mts_read_number(const unsigned char **p,size_t *remaining,
                           unsigned width,uint64_t *value){
    uint64_t result=0;

    if(!p||!*p||!remaining||!value||!width||width>8||*remaining<width)
        return 0;

    for(unsigned i=0;i<width;i++)
        result=(result<<8)|(*p)[i];

    *p+=width;
    *remaining-=width;
    *value=result;
    return 1;
}

int mtc_load_trusted_subtrees(MTCConfig *c,const char *path){
    FILE *f=NULL;
    unsigned char *buf=NULL;
    const unsigned char *p;
    long size;
    size_t remaining;
    uint64_t count,log_number,start,end;
    unsigned original_count;
    int ok=0;

    if(!c||!c->landmark||!path)
        return 0;

    f=fopen(path,"rb");
    if(!f)
        return 0;

    if(fseek(f,0,SEEK_END)||
       (size=ftell(f))<6||
       size>6+(long)MTC_MAX_TRUSTED_SUBTREES*46||
       fseek(f,0,SEEK_SET))
        goto end;

    buf=OPENSSL_malloc((size_t)size);
    if(!buf||fread(buf,1,(size_t)size,f)!=(size_t)size)
        goto end;

    p=buf;
    remaining=(size_t)size;

    if(remaining<4||memcmp(p,"MTS1",4))
        goto end;
    p+=4;
    remaining-=4;

    if(!mts_read_number(&p,&remaining,2,&count)||
       count>MTC_MAX_TRUSTED_SUBTREES||
       remaining!=(size_t)count*46)
        goto end;

    /*
     * Loading is atomic with respect to the configuration: malformed input
     * must not leave a partially installed trusted-subtree set.
     */
    original_count=c->ntrusted;

    for(uint64_t i=0;i<count;i++){
        const unsigned char *hash_value;

        if(!mts_read_number(&p,&remaining,2,&log_number)||
           !mts_read_number(&p,&remaining,6,&start)||
           !mts_read_number(&p,&remaining,6,&end)||
           remaining<32)
            goto rollback;

        hash_value=p;
        p+=32;
        remaining-=32;

        if(!mtc_add_trusted_subtree(
                c,log_number,start,end,hash_value))
            goto rollback;
    }

    if(remaining)
        goto rollback;

    ok=1;
    goto end;

rollback:
    c->ntrusted=original_count;

end:
    if(f)
        fclose(f);
    OPENSSL_free(buf);
    return ok;
}

int mtc_add_revoked_serial_range(MTCConfig *c,uint64_t first,uint64_t last){
    if(!c||first>last||c->nrevoked>=MTC_MAX_REVOKED_RANGES)return 0;
    c->revoked[c->nrevoked++]=(RevokedRange){first,last};
    return 1;
}
static int serial_revoked(const MTCConfig *c,uint64_t serial){
    for(unsigned i=0;i<c->nrevoked;i++)
        if(serial>=c->revoked[i].first&&serial<=c->revoked[i].last)return 1;
    return 0;
}
static int algorithm(const X509_ALGOR *a){const ASN1_OBJECT *o;int type;char text[80];X509_ALGOR_get0(&o,&type,NULL,a);return type==V_ASN1_UNDEF&&OBJ_obj2txt(text,sizeof(text),o,1)>0&&!strcmp(text,"1.3.6.1.5.5.7.6.67");}
static int issuer(X509 *x,const char *id){
    return x&&name_matches_id(X509_get_issuer_name(x),id);
}
static int leaf_hash(X509 *x,Slice extensions,unsigned char out[32]){
    unsigned char *der=NULL,keyhash[32],header[3],octet[2]={4,32};int n=i2d_re_X509_tbs(x,&der),ok=0;unsigned count=0,size;
    Slice s;TLV outer,fields[12],spki,alg;EVP_MD_CTX *md=NULL;
    if(n<=0)goto end;
    s=(Slice){der,(size_t)n};if(!tlv(&s,&outer)||s.n||outer.tag!=48)goto end;s=outer.body;
    while(s.n){if(count>=12||!tlv(&s,&fields[count++]))goto end;}
    if(count<7||fields[0].tag!=160||fields[1].tag!=2||fields[2].tag!=48||fields[3].tag!=48||fields[4].tag!=48||fields[5].tag!=48||fields[6].tag!=48)goto end;
    spki=fields[6];s=spki.body;if(!tlv(&s,&alg)||alg.tag!=48||!hash(spki.raw,keyhash))goto end;
    md=EVP_MD_CTX_new();if(!md||!EVP_DigestInit_ex(md,EVP_sha256(),NULL))goto end;
    header[0]=0;put(header+1,extensions.n,2);
    if(!EVP_DigestUpdate(md,header,3)||!EVP_DigestUpdate(md,extensions.p,extensions.n)||!EVP_DigestUpdate(md,"\0\1",2))goto end;
    for(unsigned i=0;i<6;i++)if(i!=1&&i!=2&&!EVP_DigestUpdate(md,fields[i].raw.p,fields[i].raw.n))goto end;
    if(!EVP_DigestUpdate(md,alg.raw.p,alg.raw.n)||!EVP_DigestUpdate(md,octet,2)||!EVP_DigestUpdate(md,keyhash,32))goto end;
    for(unsigned i=7;i<count;i++)if(!EVP_DigestUpdate(md,fields[i].raw.p,fields[i].raw.n))goto end;
    ok=EVP_DigestFinal_ex(md,out,&size)&&size==32;
end:EVP_MD_CTX_free(md);OPENSSL_free(der);return ok;
}
static int merkle_verify_timed(X509 *x,Slice extensions,uint64_t index,
                               uint64_t start,uint64_t end,Slice proof,
                               unsigned char leaf[32],unsigned char root[32],
                               MTCVerificationTiming *timing){
    struct timespec total_start,leaf_start,path_start;int total_clock,leaf_clock,path_clock;
    int leaf_ok,path_ok;
    total_clock=timing&&clock_gettime(CLOCK_MONOTONIC,&total_start)==0;
    if(total_clock){leaf_start=total_start;leaf_clock=1;}
    else leaf_clock=timing&&clock_gettime(CLOCK_MONOTONIC,&leaf_start)==0;
    leaf_ok=leaf_hash(x,extensions,leaf);
    if(timing&&leaf_clock)
        timing->has_merkle_leaf_hash_ns=
            elapsed_monotonic_ns(&leaf_start,&timing->merkle_leaf_hash_ns);
    if(!leaf_ok){
        if(timing&&total_clock)
            timing->has_merkle_total_ns=
                elapsed_monotonic_ns(&total_start,&timing->merkle_total_ns);
        return 0;
    }
    path_clock=timing&&clock_gettime(CLOCK_MONOTONIC,&path_start)==0;
    path_ok=mtc_eval(leaf,index,start,end,proof.p,proof.n,root);
    if(timing&&path_clock)
        timing->has_merkle_path_ns=
            elapsed_monotonic_ns(&path_start,&timing->merkle_path_ns);
    if(timing&&total_clock)
        timing->has_merkle_total_ns=
            elapsed_monotonic_ns(&total_start,&timing->merkle_total_ns);
    return path_ok;
}
static int mtc_verify_timed_impl(X509 *x,MTCConfig *c,MTCVerificationTiming *timing){
    const ASN1_BIT_STRING *signature;const X509_ALGOR *alg;Slice p,extensions,proof,sigs;
    uint64_t serial,start,end,index;unsigned char leaf[32],root[32];double begin;
    if(!x||!c||X509_get_version(x)!=2||!issuer(x,c->caid)||!algorithm(X509_get0_tbs_sigalg(x)))return 0;
    X509_get0_signature(&signature,&alg,x);
    if(!algorithm(alg)||(signature->flags&7)||signature->length<0||!ASN1_INTEGER_get_uint64(&serial,X509_get_serialNumber(x))||serial<c->min||serial>c->max||serial_revoked(c,serial)||(serial>>48)!=c->log)return 0;
    index=serial&0xffffffffffffULL;p=(Slice){signature->data,(size_t)signature->length};
    if(!vector(&p,2,&extensions)||!mtc_extensions(extensions)||!number(&p,6,&start)||!number(&p,6,&end)||!vector(&p,2,&proof)||!vector(&p,3,&sigs)||p.n)return 0;
    begin=tick();
    if(!merkle_verify_timed(x,extensions,index,start,end,proof,leaf,root,timing))return 0;
    if(timing)timing->merkle_proof_ms=tick()-begin;
    if(c->landmark){
        if(timing){timing->has_verification_mode=1;timing->verification_mode=MTC_VERIFICATION_MODE_LANDMARK;}
        size_t ignored_signature_count;
        begin=tick();
        if(!signature_block_v2(sigs,&ignored_signature_count))return 0;
        for(unsigned i=0;i<c->ntrusted;i++)
            if(c->trusted[i].log==c->log&&
               c->trusted[i].start==start&&c->trusted[i].end==end){
                int ok=!CRYPTO_memcmp(root,c->trusted[i].hash,32);
                if(timing)timing->landmark_validation_ms=tick()-begin;
                return ok;
            }
        for(unsigned i=0;i<c->nsubs;i++)
            if(c->subs[i].start==start&&c->subs[i].end==end){
                int ok=!CRYPTO_memcmp(root,c->subs[i].hash,32);
                if(timing)timing->landmark_validation_ms=tick()-begin;
                return ok;
            }
        if(timing)timing->landmark_validation_ms=tick()-begin;
        return 0;
    }
    if(timing){timing->has_verification_mode=1;timing->verification_mode=MTC_VERIFICATION_MODE_STANDALONE;}
    begin=tick();
    {
        int ok=sigcheck(c,sigs,start,end,root,0,timing);
        if(timing)timing->standalone_validation_ms=tick()-begin;
        return ok;
    }
}
int mtc_verify_timed(X509 *x,MTCConfig *c,MTCVerificationTiming *timing){
    struct timespec start;int clock_ok,result;
    if(timing)memset(timing,0,sizeof(*timing));
    clock_ok=timing&&clock_gettime(CLOCK_MONOTONIC,&start)==0;
    result=mtc_verify_timed_impl(x,c,timing);
    if(timing){
        timing->mtc_success=result;
        if(clock_ok)timing->has_mtc_total_ns=
            elapsed_monotonic_ns(&start,&timing->mtc_total_ns);
    }
    return result;
}
int mtc_verify(X509 *x,MTCConfig *c){
    return mtc_verify_timed(x,c,NULL);
}
