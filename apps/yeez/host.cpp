/* Bounded host fixture for the original analyzer and key-manager ECALLs.
 * Independent wire encoder/oracles; no application or SDK state is stubbed. */
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/cmac.h>
#include <openssl/sha.h>
#include <sgx_urts.h>
extern "C" void yeez_loaded_permissions(const char *);
extern "C" __attribute__((noinline, used)) void yeez_c15_ready(void) { static volatile int marker; marker++; }
#include "eparser_u.h"
#define stbox_common_version keymgr_stbox_common_version
#include "ekeymgr_u.h"
#undef stbox_common_version
extern "C" {
#include "ypc/stbox/keccak/keccak.h"
#include "ypc/stbox/tsgx/secp256k1/secp256k1.h"
#include "ypc/stbox/tsgx/secp256k1/secp256k1_ecdh.h"
#include "ypc/stbox/tsgx/secp256k1/secp256k1_recovery.h"
}
using Bytes=std::vector<uint8_t>;
static sgx_enclave_id_t worker,manager;
static unsigned calls,checks,handshakes,key_requests,batches;
static bool verbose;
static secp256k1_context *secp;
static std::map<Bytes,Bytes> sealed_keys;
static std::map<Bytes,std::vector<Bytes>> streams;
static std::map<Bytes,size_t> cursors;
static std::vector<Bytes> keep_alive;
/* Optional C13/C14 hostile control. The host callback returns an
 * application-chosen enclave address instead of a host batch buffer. */
static bool hostile;
static bool hostile_served;
static uint8_t *hostile_ptr;
static uint32_t hostile_len;
#define VERIFY(c) do{++checks;if(!(c)){fprintf(stderr,"verify failed %s:%d: %s\n",__FILE__,__LINE__,#c);std::abort();}}while(0)
#define ECALL(fn,...) do{uint32_t r=~0u;auto s=fn(__VA_ARGS__);++calls;VERIFY(s==SGX_SUCCESS);VERIFY(r==0);}while(0)
static Bytes join(Bytes a,const Bytes &b){a.insert(a.end(),b.begin(),b.end());return a;}
static Bytes str(const std::string &s){return Bytes(s.begin(),s.end());}
static void u32(Bytes &b,uint32_t v){for(int i=0;i<4;++i)b.push_back(uint8_t(v>>(8*i)));}
static void u64(Bytes &b,uint64_t v){for(int i=0;i<8;++i)b.push_back(uint8_t(v>>(8*i)));}
static void blob(Bytes &b,const Bytes &v){u64(b,v.size());b.insert(b.end(),v.begin(),v.end());}
static Bytes hash(const Bytes &b){sha3_context c;sha3_Init256(&c);sha3_SetFlags(&c,SHA3_FLAGS_KECCAK);sha3_Update(&c,b.data(),b.size());const auto *p=(const uint8_t *)sha3_Finalize(&c);return Bytes(p,p+32);}
static Bytes message_hash(const Bytes &b){Bytes m=str(std::string("\x19" "Ethereum Signed Message:\n32"));return hash(join(m,hash(b)));}
static void endian(Bytes &b){VERIFY(b.size()==64);std::reverse(b.begin(),b.begin()+32);std::reverse(b.begin()+32,b.end());}
static Bytes pub(const Bytes &key){secp256k1_pubkey p;VERIFY(secp256k1_ec_pubkey_create(secp,&p,key.data()));Bytes b(p.data,p.data+64);endian(b);return b;}
static Bytes sign(const Bytes &key,const Bytes &message){auto h=message_hash(message);secp256k1_ecdsa_recoverable_signature s;VERIFY(secp256k1_ecdsa_sign_recoverable(secp,&s,h.data(),key.data(),nullptr,nullptr));Bytes out(65);int id;VERIFY(secp256k1_ecdsa_recoverable_signature_serialize_compact(secp,out.data(),&id,&s));out[64]=uint8_t(id+27);return out;}
static void verify_signature(const Bytes &pkey,const Bytes &message,const Bytes &sig){VERIFY(sig.size()==65);Bytes p=pkey;endian(p);secp256k1_pubkey pk;memcpy(pk.data,p.data(),64);secp256k1_ecdsa_recoverable_signature rs;secp256k1_ecdsa_signature ss;VERIFY(secp256k1_ecdsa_recoverable_signature_parse_compact(secp,&rs,sig.data(),sig[64]-27));VERIFY(secp256k1_ecdsa_recoverable_signature_convert(secp,&ss,&rs));auto h=message_hash(message);VERIFY(secp256k1_ecdsa_verify(secp,&ss,h.data(),&pk));}
static Bytes cmac(const Bytes &key,const Bytes &data){Bytes out(16);size_t n=0;auto *c=CMAC_CTX_new();VERIFY(c);VERIFY(CMAC_Init(c,key.data(),key.size(),EVP_aes_128_cbc(),nullptr));VERIFY(CMAC_Update(c,data.data(),data.size()));VERIFY(CMAC_Final(c,out.data(),&n)&&n==16);CMAC_CTX_free(c);return out;}
static int ecdh_hash(unsigned char *out,const unsigned char *x,const unsigned char *y,void*){uint8_t b[33];b[0]=(y[31]&1)|2;memcpy(b+1,x,32);SHA256(b,33,out);return 1;}
static Bytes shared(const Bytes &key,const Bytes &pkey){Bytes p=pkey;endian(p);secp256k1_pubkey pk;memcpy(pk.data,p.data(),64);Bytes dh(32);VERIFY(secp256k1_ecdh(secp,dh.data(),&pk,key.data(),ecdh_hash,nullptr));Bytes k(16);const char *v="yeez.tech.stbox";memcpy(k.data(),v,strlen(v));auto kd=cmac(k,dh);Bytes label{1};auto s=str("tech.yeez.key.manager");label.insert(label.end(),s.begin(),s.end());label.push_back(0);label.push_back(0x80);label.push_back(0);return cmac(kd,label);}
static Bytes encrypt(const Bytes &pkey,const Bytes &data,uint32_t prefix){Bytes ephemeral(32);ephemeral[31]=7;Bytes iv(12);for(size_t j=0;j<iv.size();++j)iv[j]=uint8_t(0x40+j);auto k=shared(ephemeral,pkey);Bytes aad(64);memcpy(aad.data(),"tech.yeez.key.manager",21);memcpy(aad.data()+24,&prefix,4);Bytes out(data.size()+92);auto *c=EVP_CIPHER_CTX_new();int n=0,last=0;VERIFY(c);VERIFY(EVP_EncryptInit_ex(c,EVP_aes_128_gcm(),nullptr,nullptr,nullptr));VERIFY(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,12,nullptr));VERIFY(EVP_EncryptInit_ex(c,nullptr,nullptr,k.data(),iv.data()));VERIFY(EVP_EncryptUpdate(c,nullptr,&n,aad.data(),64));VERIFY(EVP_EncryptUpdate(c,out.data(),&n,data.data(),data.size()));VERIFY(EVP_EncryptFinal_ex(c,out.data()+n,&last));VERIFY(size_t(n+last)==data.size());memcpy(out.data()+data.size(),iv.data(),12);auto pk=pub(ephemeral);memcpy(out.data()+data.size()+12,pk.data(),64);VERIFY(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,out.data()+data.size()+76));EVP_CIPHER_CTX_free(c);return out;}
static Bytes decrypt(const Bytes &key,const Bytes &cipher,uint32_t prefix){VERIFY(cipher.size()>=92);size_t n=cipher.size()-92;Bytes pk(cipher.begin()+n+12,cipher.begin()+n+76);auto k=shared(key,pk);Bytes aad(64);memcpy(aad.data(),"tech.yeez.key.manager",21);memcpy(aad.data()+24,&prefix,4);Bytes out(n+16);auto *c=EVP_CIPHER_CTX_new();int count=0,last=0;VERIFY(c);VERIFY(EVP_DecryptInit_ex(c,EVP_aes_128_gcm(),nullptr,nullptr,nullptr));VERIFY(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,12,nullptr));VERIFY(EVP_DecryptInit_ex(c,nullptr,nullptr,k.data(),cipher.data()+n));VERIFY(EVP_DecryptUpdate(c,nullptr,&count,aad.data(),64));VERIFY(EVP_DecryptUpdate(c,out.data(),&count,cipher.data(),n));VERIFY(EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,const_cast<uint8_t *>(cipher.data()+n+76)));VERIFY(EVP_DecryptFinal_ex(c,out.data()+count,&last));out.resize(count+last);EVP_CIPHER_CTX_free(c);return out;}
extern "C" void ocall_print_string(const char *s){if(verbose)fprintf(stderr,"[YeeZ] %s",s);}
extern "C" void ocall_log_string(uint32_t rank,const char *s){if(verbose || rank>=2)fprintf(stderr,"[YeeZ %u] %s\n",rank,s);}
extern "C" uint32_t km_session_request_ocall(sgx_dh_msg1_t *m,uint32_t *id){uint32_t r=~0u;auto s=msession_request(manager,&r,m,id);++calls;if(s!=SGX_SUCCESS)return s;++handshakes;return r;}
extern "C" uint32_t km_exchange_report_ocall(sgx_dh_msg2_t *a,sgx_dh_msg3_t *b,uint32_t id){uint32_t r=~0u;auto s=mexchange_report(manager,&r,a,b,id);++calls;return s==SGX_SUCCESS?r:s;}
extern "C" uint32_t km_send_request_ocall(uint32_t id,secure_message_t *req,size_t rn,size_t max,secure_message_t *resp,size_t sn){uint32_t r=~0u;auto s=mgenerate_response(manager,&r,req,rn,max,resp,sn,id);++calls;++key_requests;return s==SGX_SUCCESS?r:s;}
extern "C" uint32_t km_end_session_ocall(uint32_t id){uint32_t r=~0u;auto s=mend_session(manager,&r,id);++calls;return s==SGX_SUCCESS?r:s;}
extern "C" uint32_t ocall_load_key_pair(const char*,uint32_t,uint8_t *pk,uint32_t pn,uint8_t *out,uint32_t n){Bytes k(pk,pk+pn);auto it=sealed_keys.find(k);if(it==sealed_keys.end()||it->second.size()!=n)return 1;memcpy(out,it->second.data(),n);return 0;}
extern "C" uint32_t next_data_batch(const uint8_t *h,uint32_t n,uint8_t **out,uint32_t *len){
 if(hostile){if(hostile_served)return 1;hostile_served=true;*out=hostile_ptr;*len=hostile_len;++batches;return 0;}
 Bytes key(h,h+n);auto it=streams.find(key);VERIFY(it!=streams.end());size_t &index=cursors[key];if(index==it->second.size())return 1;keep_alive.push_back(it->second[index++]);*out=keep_alive.back().data();*len=keep_alive.back().size();++batches;return 0;}
/* Unselected imported file/KV endpoints fail visibly if reached. The selected
 * first-match workflow uses only data/key-manager/log OCALLs. */
static void unselected(){fprintf(stderr,"unselected YeeZ file/KV endpoint reached\n");std::abort();}
extern "C" uint32_t fopen_ocall(const char*,size_t,uint32_t){unselected();return 0;}
extern "C" void fclose_ocall(uint32_t){unselected();}
extern "C" void fflush_ocall(uint32_t){unselected();}
extern "C" void fread_ocall(void*,size_t,uint32_t){unselected();}
extern "C" void fwrite_ocall(const void*,size_t,uint32_t){unselected();}
extern "C" void fseekg_ocall(uint32_t,int64_t,uint8_t){unselected();}
extern "C" void fseekp_ocall(uint32_t,int64_t,uint8_t){unselected();}
extern "C" int64_t ftellg_ocall(uint32_t){unselected();return 0;}
extern "C" int64_t ftellp_ocall(uint32_t){unselected();return 0;}
extern "C" uint8_t feof_ocall(uint32_t){unselected();return 0;}
extern "C" uint8_t fgood_ocall(uint32_t){unselected();return 0;}
extern "C" uint8_t ffail_ocall(uint32_t){unselected();return 0;}
extern "C" uint8_t fbad_ocall(uint32_t){unselected();return 0;}
extern "C" void clear_ocall(uint32_t){unselected();}
extern "C" uint8_t has_key_ocall(const uint8_t*){unselected();return 0;}
extern "C" uint32_t remove_key_ocall(const uint8_t*){unselected();return 0;}
extern "C" uint32_t write_to_storage_ocall(const uint8_t*,const uint8_t*,size_t){unselected();return 0;}
extern "C" uint32_t read_from_storage_ocall(const uint8_t*,uint8_t*,size_t){unselected();return 0;}

struct Reader{const Bytes &b;size_t p=0;uint64_t number(size_t n){VERIFY(p+n<=b.size());uint64_t v=0;for(size_t i=0;i<n;++i)v|=uint64_t(b[p++])<<(8*i);return v;}Bytes bytes(){size_t n=number(8);VERIFY(p+n<=b.size());Bytes v(b.begin()+p,b.begin()+p+n);p+=n;return v;}};
static Bytes row(const std::string &name,const std::string &id){Bytes b;u32(b,0);for(unsigned j=0;j<26;++j)blob(b,str(j==1?name:j==7?id:""));return b;}
static Bytes batch(const std::vector<Bytes> &items){Bytes b;u32(b,0x82c4e8d8);u64(b,items.size());for(const auto &item:items)blob(b,item);return b;}
static Bytes data_hash(const std::vector<Bytes> &items){Bytes h=hash(str("Fidelius"));for(const auto &item:items)h=hash(join(h,item));return h;}
static Bytes create_master(){uint32_t pn=0,sn=0;VERIFY(get_ecc_public_key_size(manager,&pn)==SGX_SUCCESS);++calls;VERIFY(get_ecc_sealed_private_key_size(manager,&sn)==SGX_SUCCESS);++calls;Bytes pk(pn),sealed(sn);uint32_t r;VERIFY(generate_ecc_key_pair(manager,&r,pk.data(),pn,sealed.data(),sn)==SGX_SUCCESS && r==0);++calls;sealed_keys[pk]=sealed;return pk;}
static void provision(const Bytes &master,const Bytes &key){auto pk=pub(key);auto any=hash(str("any enclave"));auto cipher=encrypt(master,key,1);auto signature=sign(key,join(master,any));uint32_t r;VERIFY(forward_private_key(manager,&r,cipher.data(),cipher.size(),master.data(),master.size(),any.data(),any.size(),signature.data(),signature.size())==SGX_SUCCESS && r==0);++calls;}
static void scenario(const char *analyzer,const char *keymgr,int mode)
{
 VERIFY(sgx_create_enclave(keymgr,SGX_DEBUG_FLAG,nullptr,nullptr,&manager,nullptr)==SGX_SUCCESS);
 VERIFY(sgx_create_enclave(analyzer,SGX_DEBUG_FLAG,nullptr,nullptr,&worker,nullptr)==SGX_SUCCESS);
 VERIFY(setenv("ENCBOUND_TEST_BASE",getenv("YEEZ_MANAGER_BASE"),1)==0);yeez_loaded_permissions(keymgr);
 VERIFY(setenv("ENCBOUND_TEST_BASE",getenv("YEEZ_ANALYZER_BASE"),1)==0);yeez_loaded_permissions(analyzer);
 auto master=create_master();Bytes secret(32);secret[31]=3;auto pk=pub(secret);provision(master,secret);
 Bytes eh(32);uint32_t r=~0u;VERIFY(get_enclave_hash(worker,&r,eh.data(),32)==SGX_SUCCESS&&r==0);++calls;
 std::vector<Bytes> records={row("Alice","ID-7"),row("Bob","ID-8"),row("Carol","ID-7")};
 if(mode==2)records.clear();
 auto expected_hash=data_hash(records);auto serialized=batch(records);
 streams.clear();cursors.clear();keep_alive.clear();
 bool sealed=mode==1;Bytes route=sealed?join(expected_hash,pk):expected_hash;
 streams[route]={sealed?encrypt(pk,serialized,2):serialized};
 Bytes sources;u32(sources,0);u64(sources,1);u32(sources,0);blob(sources,expected_hash);blob(sources,sealed?pk:Bytes{});u32(sources,0);
 VERIFY(init_data_source(worker,&r,sources.data(),sources.size())==SGX_SUCCESS&&r==0);++calls;
 VERIFY(begin_parse_data_item(worker,&r)==SGX_SUCCESS&&r==0);++calls;
 Bytes query;u32(query,0);blob(query,str("ID-7"));
 auto encrypted=encrypt(pk,query,2);Bytes param;u32(param,0);blob(param,encrypted);blob(param,pk);
 u64(param,sealed?1:0);
 if(sealed){Bytes zero_gas(8);auto allowance=sign(secret,join(join(join(hash(query),eh),master),expected_hash));
  u32(param,0);blob(param,allowance);blob(param,pk);blob(param,expected_hash);}
 u32(param,0);blob(param,{});blob(param,{});blob(param,{});
 VERIFY(parse_data_item(worker,&r,param.data(),param.size())==SGX_SUCCESS&&r==0);++calls;
 VERIFY(end_parse_data_item(worker,&r)==SGX_SUCCESS&&r==0);++calls;
 uint32_t size=0;VERIFY(get_analyze_result_size(worker,&size)==SGX_SUCCESS && size>0);++calls;
 Bytes result(size);VERIFY(get_analyze_result(worker,&r,result.data(),result.size())==SGX_SUCCESS&&r==0);++calls;
 Reader rr{result};VERIFY(rr.number(4)==0xf13e1f40);auto enc=rr.bytes(),h=rr.bytes(),sig=rr.bytes(),cost=rr.bytes();VERIFY(rr.p==result.size());
 auto plain=decrypt(secret,enc,2);VERIFY(plain==str(records.empty()?"":"Alice : ID-7 .Carol : ID-7 ."));
 auto aggregate=hash(expected_hash);VERIFY(h==aggregate);Bytes gas(8);auto message=join(join(join(encrypted,aggregate),eh),gas);
 verify_signature(pk,message,cost);verify_signature(pk,join(message,enc),sig);
 VERIFY(sgx_destroy_enclave(worker)==SGX_SUCCESS);VERIFY(sgx_destroy_enclave(manager)==SGX_SUCCESS);
 fprintf(stdout,"YEEZ scenario=%s pass result_bytes=%zu\n",mode==1?"sealed":mode==2?"empty":"raw",plain.size());
}

/* One selected raw/sealed parse through the original public ECALLs. The host
 * supplies an enclave address for the first next_data_batch result. The
 * provider's original allocation/copy/parse or decrypt path is unchanged. */
static void hostile_scenario(const char *analyzer,const char *keymgr,bool sealed)
{
 VERIFY(sgx_create_enclave(keymgr,SGX_DEBUG_FLAG,nullptr,nullptr,&manager,nullptr)==SGX_SUCCESS);
 VERIFY(sgx_create_enclave(analyzer,SGX_DEBUG_FLAG,nullptr,nullptr,&worker,nullptr)==SGX_SUCCESS);
 VERIFY(setenv("ENCBOUND_TEST_BASE",getenv("YEEZ_MANAGER_BASE"),1)==0);yeez_loaded_permissions(keymgr);
 VERIFY(setenv("ENCBOUND_TEST_BASE",getenv("YEEZ_ANALYZER_BASE"),1)==0);yeez_loaded_permissions(analyzer);
 auto master=create_master();Bytes secret(32);secret[31]=3;auto pk=pub(secret);provision(master,secret);
 Bytes eh(32);uint32_t r=~0u;VERIFY(get_enclave_hash(worker,&r,eh.data(),32)==SGX_SUCCESS&&r==0);++calls;
 streams.clear();cursors.clear();keep_alive.clear();
 Bytes expected_hash=hash(str("hostile.c13"));
 Bytes sources;u32(sources,0);u64(sources,1);u32(sources,0);blob(sources,expected_hash);blob(sources,sealed?pk:Bytes{});u32(sources,0);
 VERIFY(init_data_source(worker,&r,sources.data(),sources.size())==SGX_SUCCESS&&r==0);++calls;
 VERIFY(begin_parse_data_item(worker,&r)==SGX_SUCCESS&&r==0);++calls;
 Bytes query;u32(query,0);blob(query,str("ID-7"));
 auto encrypted=encrypt(pk,query,2);Bytes param;u32(param,0);blob(param,encrypted);blob(param,pk);
 u64(param,sealed?1:0);
 if(sealed){auto allowance=sign(secret,join(join(join(hash(query),eh),master),expected_hash));
  u32(param,0);blob(param,allowance);blob(param,pk);blob(param,expected_hash);}
 u32(param,0);blob(param,{});blob(param,{});blob(param,{});
 hostile=true;hostile_served=false;
 auto ec=parse_data_item(worker,&r,param.data(),param.size());++calls;
 fprintf(stdout,"YEEZ HOSTILE mode=%s parse_status=%u parse_ret=%u ptr=0x%llx len=%u\n",
   sealed?"sealed":"raw",(unsigned)ec,r,(unsigned long long)(uintptr_t)hostile_ptr,hostile_len);
 hostile=false;
 VERIFY(sgx_destroy_enclave(worker)==SGX_SUCCESS);VERIFY(sgx_destroy_enclave(manager)==SGX_SUCCESS);
 fprintf(stdout,"YEEZ HOSTILE SURVIVED mode=%s\n",sealed?"sealed":"raw");
}
/* C15 boundary-metadata controls on the original key-manager ECALLs. */
static void c15_scenario(const char *keymgr,const char *mode)
{
 VERIFY(sgx_create_enclave(keymgr,SGX_DEBUG_FLAG,nullptr,nullptr,&manager,nullptr)==SGX_SUCCESS);
 VERIFY(setenv("ENCBOUND_TEST_BASE",getenv("YEEZ_MANAGER_BASE"),1)==0);yeez_loaded_permissions(keymgr);
 yeez_c15_ready();
 uint32_t r=~0u;
 if(strcmp(mode,"oversized")==0){
  Bytes data(32,0x11),sig(65,0x22),pkey(128,0x33);
  auto ec=verify_signature(manager,&r,data.data(),data.size(),sig.data(),sig.size(),pkey.data(),pkey.size());++calls;
  fprintf(stdout,"YEEZ C15 mode=oversized status=%u ret=%u pkey_size=%zu\n",(unsigned)ec,r,pkey.size());
 }else if(strcmp(mode,"generate")==0){
  uint32_t pn=0,sn=0;VERIFY(get_ecc_public_key_size(manager,&pn)==SGX_SUCCESS);++calls;
  VERIFY(get_ecc_sealed_private_key_size(manager,&sn)==SGX_SUCCESS);++calls;
  Bytes pub(1),sealed(sn);auto ec=generate_ecc_key_pair(manager,&r,pub.data(),1,sealed.data(),sealed.size());++calls;
  fprintf(stdout,"YEEZ C15 mode=generate status=%u ret=%u pkey_size=1 sealed_size=%u\n",(unsigned)ec,r,sn);
 }else if(strcmp(mode,"sign")==0){
  auto master=create_master();auto sealed=sealed_keys.at(master);Bytes data(32,0x11),sig(1);
  auto ec=sign_message(manager,&r,sealed.data(),sealed.size(),data.data(),data.size(),sig.data(),1);++calls;
  fprintf(stdout,"YEEZ C15 mode=sign status=%u ret=%u sig_size=1\n",(unsigned)ec,r);
 }else VERIFY(false);
 VERIFY(sgx_destroy_enclave(manager)==SGX_SUCCESS);
 fprintf(stdout,"YEEZ C15 SURVIVED mode=%s\n",mode);
}
int main(int argc,char **argv)
{
 if(argc!=3)return 1;verbose=getenv("YEEZ_VERBOSE");
 secp=secp256k1_context_create(SECP256K1_CONTEXT_SIGN|SECP256K1_CONTEXT_VERIFY);VERIFY(secp);
 const char *c15=getenv("YEEZ_C15");
 if(c15){c15_scenario(argv[2],c15);printf("YEEZ ORIGINAL ANALYZER SDK SIM PASS calls=%u checks=%u handshakes=%u key_requests=%u batches=%u\n",calls,checks,handshakes,key_requests,batches);secp256k1_context_destroy(secp);return 0;}
 const char *mode=getenv("YEEZ_HOSTILE");
 if(mode){
  const char *pointer=getenv("YEEZ_HOSTILE_PTR");const char *length=getenv("YEEZ_HOSTILE_LEN");
  VERIFY(pointer!=nullptr);hostile_ptr=(uint8_t*)(uintptr_t)strtoull(pointer,nullptr,0);
  hostile_len=length?(uint32_t)strtoul(length,nullptr,0):32;VERIFY(hostile_ptr&&hostile_len);
  VERIFY(strcmp(mode,"raw")==0||strcmp(mode,"sealed")==0);
  hostile_scenario(argv[1],argv[2],strcmp(mode,"sealed")==0);
 }else for(int m=0;m<3;++m)scenario(argv[1],argv[2],m);
 printf("YEEZ ORIGINAL ANALYZER SDK SIM PASS calls=%u checks=%u handshakes=%u key_requests=%u batches=%u\n",calls,checks,handshakes,key_requests,batches);
 secp256k1_context_destroy(secp);return 0;
}
