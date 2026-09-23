/* Isolated BoringSSL port of src/mtc/mtc.c; see README.md. */
#include "mtc.h"
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/mem.h>
#ifndef OPENSSL_IS_BORINGSSL
#error "This isolated port requires BoringSSL"
#endif
#include <openssl/x509v3.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
typedef struct { const unsigned char *p; size_t n; } Slice;
typedef struct { Slice raw,body; unsigned tag; } TLV;
typedef struct { char id[80]; unsigned char binary[80];size_t idlen; EVP_PKEY *key; } Signer;
typedef struct { uint64_t start,end; unsigned char hash[32]; } Subtree;
struct mtc_config {
    char caid[80]; Signer signers[2]; unsigned count; int landmark;
    uint64_t log,min,max,number,size,timestamp; unsigned char root[32];
    Subtree subs[2];unsigned nsubs; size_t file_bytes;
    unsigned char signal[90];size_t signal_len;
};
static double tick(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1000.0+t.tv_nsec/1e6;}
static int take(Slice *s,size_t n,Slice *out){if(n>s->n)return 0;out->p=s->p;out->n=n;s->p+=n;s->n-=n;return 1;}
static int number(Slice *s,unsigned n,uint64_t *v){Slice x;if(!take(s,n,&x))return 0;*v=0;for(unsigned i=0;i<n;i++)*v=(*v<<8)|x.p[i];return 1;}
static int vector(Slice *s,unsigned width,Slice *out){uint64_t n;return number(s,width,&n)&&take(s,(size_t)n,out);}
static int tlv(Slice *s,TLV *t){
    const unsigned char *begin=s->p;uint64_t tag,n,k;Slice b;
    if(!number(s,1,&tag)||(tag&31)==31||!number(s,1,&n))return 0;
    if(n&128){k=n&127;if(!k||k>4||s->n<k||s->p[0]==0||!number(s,(unsigned)k,&n)||n<128)return 0;}
    if(!take(s,(size_t)n,&b))return 0;
    t->raw=(Slice){begin,(size_t)(s->p-begin)};t->body=b;t->tag=(unsigned)tag;return 1;
}
static int hash(Slice in,unsigned char out[32]){unsigned n;return EVP_Digest(in.p,in.n,out,&n,EVP_sha256(),NULL)&&n==32;}
static int node(const unsigned char *a,const unsigned char *b,unsigned char out[32]){unsigned char in[65];in[0]=1;memcpy(in+1,a,32);memcpy(in+33,b,32);return hash((Slice){in,65},out);}
static int valid_subtree(uint64_t start,uint64_t end){uint64_t k=1;if(start>=end||end>=((uint64_t)1<<48))return 0;while(k<end-start)k<<=1;return !(start%k);}
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
static int id_encode(const char *s,unsigned char *out,size_t *n){
    size_t j=0;const char *p=s;*n=0;
    while(*p){char *end;unsigned long v;unsigned char b[10];unsigned k=0;
        if(*p<'0'||*p>'9'||(*p=='0'&&p[1]&&p[1]!='.'))return 0;
        v=strtoul(p,&end,10);if(end==p||(*end&&*end!='.')||v>0xffffffffUL)return 0;
        b[k++]=(unsigned char)(v&127);while((v>>=7))b[k++]=(unsigned char)((v&127)|128);
        if(j+k>80)return 0;
        while(k)out[j++]=b[--k];
        p=*end?end+1:end;if(*end&&! *p)return 0;
    }*n=j;return j>0;
}
static int ascii(Slice x,char *s){if(!x.n||x.n>=80||memchr(x.p,0,x.n))return 0;memcpy(s,x.p,x.n);s[x.n]=0;unsigned char b[80];size_t n;return id_encode(s,b,&n);}
static int message(const MTCConfig *c,const Signer *signer,uint64_t start,uint64_t end,const unsigned char root[32],uint64_t timestamp,unsigned char *out,size_t *n){
    char cos[120],log[140];int a=snprintf(cos,sizeof(cos),"oid/1.3.6.1.4.1.%s",signer->id),b=snprintf(log,sizeof(log),"oid/1.3.6.1.4.1.%s.0.%llu",c->caid,(unsigned long long)c->log);size_t pos=0;
    if(a<=0||a>=120||b<=0||b>=140)return 0;
    memcpy(out,"subtree/v1\n\0",12);pos=12;out[pos++]=(unsigned char)a;memcpy(out+pos,cos,a);pos+=a;
    put(out+pos,timestamp,8);pos+=8;out[pos++]=(unsigned char)b;memcpy(out+pos,log,b);pos+=b;
    put(out+pos,start,8);pos+=8;put(out+pos,end,8);pos+=8;memcpy(out+pos,root,32);*n=pos+32;return 1;
}
/* Signer policy only. The Merkle tree and leaf hashes remain SHA-256. */
static const EVP_MD *ec_signer_digest(EVP_PKEY *key){
    const EC_KEY *ec;const EC_GROUP *group;
    if(!key || EVP_PKEY_id(key)!=EVP_PKEY_EC)return NULL;
    ec=EVP_PKEY_get0_EC_KEY(key);
    if(!ec || !(group=EC_KEY_get0_group(ec)))return NULL;
    switch(EC_GROUP_get_curve_name(group)){
        case NID_X9_62_prime256v1:return EVP_sha256();
        case NID_secp384r1:return EVP_sha384();
        case NID_secp521r1:return EVP_sha512();
        default:return NULL;
    }
}
static int supported_signer_key(EVP_PKEY *key){
    if(!key)return 0;
    switch(EVP_PKEY_id(key)){
        case EVP_PKEY_EC:return ec_signer_digest(key)!=NULL;
        case EVP_PKEY_ML_DSA_44:
        case EVP_PKEY_ML_DSA_65:
        case EVP_PKEY_ML_DSA_87:return 1;
        /* SLH-DSA and all other key types remain unsupported. */
        default:return 0;
    }
}
static int sigcheck(MTCConfig *c,Slice sigs,uint64_t start,uint64_t end,const unsigned char root[32],uint64_t timestamp){
    Slice prev={NULL,0},id,sig;unsigned valid=0;unsigned char msg[400];size_t n;
    while(sigs.n){
        if(!vector(&sigs,1,&id)||!id.n||!vector(&sigs,2,&sig))return 0;
        if(prev.p&&(id.n<prev.n||(id.n==prev.n&&memcmp(id.p,prev.p,id.n)<=0)))return 0;
        /* A trust-anchor ID is a canonical series of base-128 integers. */
        for(size_t i=0;i<id.n;){if(id.p[i]==128)return 0;do{if(i==id.n)return 0;}while(id.p[i++]&128);}
        prev=id;
        for(unsigned i=0;i<c->count;i++)if(id.n==c->signers[i].idlen&&!memcmp(id.p,c->signers[i].binary,id.n)){
            EVP_MD_CTX *md=EVP_MD_CTX_new();Signer *s=&c->signers[i];int ok=0;
            if(md&&supported_signer_key(s->key)&&message(c,s,start,end,root,timestamp,msg,&n)&&EVP_DigestVerifyInit(md,NULL,ec_signer_digest(s->key),NULL,s->key))
                ok=EVP_DigestVerify(md,sig.p,sig.n,msg,n)==1;
            EVP_MD_CTX_free(md);if(ok)valid|=1u<<i;
        }
    }return valid==((1u<<c->count)-1);
}
void mtc_free(MTCConfig *c){if(c){for(unsigned i=0;i<2;i++)EVP_PKEY_free(c->signers[i].key);OPENSSL_free(c);}}
MTCConfig *mtc_load(const char *path,int landmark){
    double begin=tick(),validation=0;FILE *f=fopen(path,"rb");unsigned char *buf=NULL;long size;MTCConfig *c=NULL;
    Slice s,x,sigs;uint64_t v;unsigned char actual[32];int ok=0;
    if(!f)return NULL;
    if(fseek(f,0,SEEK_END)||(size=ftell(f))<=0||size>MTC_MAX||fseek(f,0,SEEK_SET))goto end;
    buf=OPENSSL_malloc(size);c=OPENSSL_zalloc(sizeof(*c));if(!buf||!c||fread(buf,1,size,f)!=(size_t)size)goto end;
    c->landmark=landmark;c->file_bytes=(size_t)size;s=(Slice){buf,(size_t)size};
    if(!take(&s,4,&x)||memcmp(x.p,"MCF1",4)||!vector(&s,1,&x)||!ascii(x,c->caid)||!number(&s,1,&v)||v!=2)goto end;
    c->count=(unsigned)v;
    for(unsigned i=0;i<c->count;i++){
        const unsigned char *p;
        if(!vector(&s,1,&x)||!ascii(x,c->signers[i].id)||!id_encode(c->signers[i].id,c->signers[i].binary,&c->signers[i].idlen)||!vector(&s,2,&x))goto end;
        p=x.p;c->signers[i].key=d2i_PUBKEY(NULL,&p,(long)x.n);
        if(!c->signers[i].key||p!=x.p+x.n||!supported_signer_key(c->signers[i].key))goto end;
    }
    if(strcmp(c->caid,c->signers[0].id)||!strcmp(c->signers[0].id,c->signers[1].id))goto end;
    if(!number(&s,2,&c->log)||c->log!=1||!number(&s,8,&c->min)||!number(&s,8,&c->max)||c->min!=(1ULL<<48)||c->max<c->min||c->max-c->min>=1024)goto end;
    if(!landmark){
        if(s.n||!id_encode(c->caid,c->signal,&c->signal_len))goto end;
        ok=1;goto end;
    }
    if(!number(&s,4,&c->number)||c->number!=1||!number(&s,6,&c->size)||!c->size||c->size>1024||!number(&s,8,&c->timestamp)||!c->timestamp||c->timestamp>(uint64_t)time(NULL)||!take(&s,32,&x))goto end;
    memcpy(c->root,x.p,32);
    if(c->min!=(1ULL<<48)||c->max!=c->min+c->size-1||!vector(&s,2,&sigs)||!number(&s,1,&v)||v<1||v>2)goto end;
    c->nsubs=(unsigned)v;
    for(unsigned i=0;i<c->nsubs;i++){
        Subtree *sub=&c->subs[i];
        if(!number(&s,6,&sub->start)||!number(&s,6,&sub->end)||!valid_subtree(sub->start,sub->end)||!take(&s,32,&x))goto end;
        memcpy(sub->hash,x.p,32);
    }
    if(s.n||c->subs[0].start||c->subs[c->nsubs-1].end!=c->size)goto end;
    if(c->nsubs==1){if(c->size!=1)goto end;memcpy(actual,c->subs[0].hash,32);}
    else {uint64_t split=1;while((split<<1)<c->size)split<<=1;
        if(c->subs[0].end!=split||c->subs[1].start!=split||!node(c->subs[0].hash,c->subs[1].hash,actual))goto end;}
    if(CRYPTO_memcmp(actual,c->root,32))goto end;
    /* Trust config is supplied by the operator. Authenticate checkpoint before
       installing its covered landmark subtrees. Standalone ignores cached subtrees. */
    if(landmark){double t=tick();if(!sigcheck(c,sigs,0,c->size,c->root,c->timestamp))goto end;validation=tick()-t;}
    {char id[80];int n=snprintf(id,sizeof(id),landmark?"%s.1.1.1":"%s",c->caid);
     if(n<=0||n>=80||!id_encode(id,c->signal,&c->signal_len))goto end;}
    ok=1;
end:
    fclose(f);OPENSSL_free(buf);
    if(!ok){mtc_free(c);return NULL;}
    fprintf(stderr,"MTC_SETUP {\"mtc_setup_ms\":%.6f,\"mtc_trust_validation_ms\":%.6f,\"mtc_predistributed_bytes\":%zu,\"mtc_trust_file_bytes\":%zu}\n",tick()-begin,validation,landmark?c->file_bytes:0,c->file_bytes);
    return c;
}
static int algorithm(const X509_ALGOR *a){const ASN1_OBJECT *o;int type;char text[80];X509_ALGOR_get0(&o,&type,NULL,a);return type==V_ASN1_UNDEF&&OBJ_obj2txt(text,sizeof(text),o,1)>0&&!strcmp(text,"1.3.6.1.4.1.44363.47.0");}
static int issuer(X509 *x,const char *id){
    X509_NAME *name=X509_get_issuer_name(x);X509_NAME_ENTRY *e;char oid[80];ASN1_STRING *v;
    if(X509_NAME_entry_count(name)!=1)return 0;
    e=X509_NAME_get_entry(name,0);v=X509_NAME_ENTRY_get_data(e);
    return OBJ_obj2txt(oid,sizeof(oid),X509_NAME_ENTRY_get_object(e),1)>0&&!strcmp(oid,"1.3.6.1.4.1.44363.47.1")&&ASN1_STRING_type(v)==V_ASN1_UTF8STRING&&ASN1_STRING_length(v)==(int)strlen(id)&&!memcmp(ASN1_STRING_get0_data(v),id,strlen(id));
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
int mtc_verify(X509 *x,MTCConfig *c){
    const ASN1_BIT_STRING *signature;const X509_ALGOR *alg;Slice p,extensions,proof,sigs;
    uint64_t serial,start,end,index;unsigned char leaf[32],root[32];
    if(!x||!c||X509_get_version(x)!=2||!issuer(x,c->caid)||!algorithm(X509_get0_tbs_sigalg(x)))return 0;
    X509_get0_signature(&signature,&alg,x);
    if(!algorithm(alg)||(signature->flags&7)||signature->length<0||!ASN1_INTEGER_get_uint64(&serial,X509_get_serialNumber(x))||serial<c->min||serial>c->max||(serial>>48)!=c->log)return 0;
    index=serial&0xffffffffffffULL;p=(Slice){signature->data,(size_t)signature->length};
    if(!vector(&p,2,&extensions)||extensions.n||!number(&p,6,&start)||!number(&p,6,&end)||!vector(&p,2,&proof)||!vector(&p,2,&sigs)||p.n)return 0;
    if(!leaf_hash(x,extensions,leaf)||!mtc_eval(leaf,index,start,end,proof.p,proof.n,root))return 0;
    if(c->landmark){
        if(sigs.n)return 0;
        for(unsigned i=0;i<c->nsubs;i++)if(c->subs[i].start==start&&c->subs[i].end==end)return !CRYPTO_memcmp(root,c->subs[i].hash,32);
        return 0;
    }
    return sigcheck(c,sigs,start,end,root,0);
}
