/* SDK SIM driver. Original user_check block pointers remain host buffers.
 * Expected plaintext is generated independently; check all 512 bytes, guards,
 * untouched input buffers, ciphertext tampering, and session persistence. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "../four_app_permissions.h"

static unsigned calls, comparisons, reads, writes, creates, deletes;
static struct { unsigned char *data; int size, width; } storage[NUM_STRUCTURES];
static void require(int ok, int line) {
    if (!ok) { fprintf(stderr,"FAIL line %d\n",line);exit(10); }
}
#define REQUIRE(x) require((x),__LINE__)
static void status(sgx_status_t s, int result, int expected, int line) {
    ++calls;
    if(s || result!=expected) {
        fprintf(stderr,"ECALL line %d: transport=%#x result=%d expected=%d\n",line,s,result,expected);
        exit(11);
    }
}
#define CALL(expr,want) do { int result=-99;sgx_status_t transport=(expr);status(transport,result,want,__LINE__); } while(0)
void ocall_print(const char *s) { fprintf(stderr,"ObliDB: %s\n",s); }
void ocall_newStructure(int id, Obliv_Type type, int size) {
    REQUIRE(id>=0 && id<NUM_STRUCTURES && !storage[id].data && size>0);
    REQUIRE(type==TYPE_LINEAR_SCAN);
    storage[id].size=size;
    storage[id].width=sizeof(Encrypted_Linear_Scan_Block);
    storage[id].data=calloc(size,storage[id].width);
    REQUIRE(storage[id].data!=NULL);
    ++creates;
}
void ocall_deleteStructure(int id) {
    REQUIRE(id>=0 && id<NUM_STRUCTURES && storage[id].data);
    free(storage[id].data);memset(&storage[id],0,sizeof storage[id]);++deletes;
}
static unsigned char *block(int id,int index,int width) {
    REQUIRE(id>=0 && id<NUM_STRUCTURES && storage[id].data);
    REQUIRE(index>=0 && index<storage[id].size && width==storage[id].width);
    return storage[id].data+index*width;
}
void ocall_read_block(int id,int index,int width,void *buffer) {
    memcpy(buffer,block(id,index,width),width);++reads;
}
void ocall_write_block(int id,int index,int width,void *buffer) {
    memcpy(block(id,index,width),buffer,width);++writes;
}
static void pattern(Linear_Scan_Block *b,int index,int round) {
    for(int i=0;i<BLOCK_DATA_SIZE;++i)b->data[i]=(unsigned char)(i*17+index*31+round*43);
}
__attribute__((noinline)) void oblidb_ready(void) { __asm__ volatile("" ::: "memory"); }
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    sgx_enclave_id_t eid=0;
    sgx_status_t s=sgx_create_enclave(argv[1],SGX_DEBUG_FLAG,NULL,NULL,&eid,NULL);
    if(s) { fprintf(stderr,"create=%#x\n",s);return 3; }
    four_app_permissions(argv[1]);
    oblidb_ready();
    CALL(total_init(eid,(sgx_status_t *)&result),0);
    const int sizes[]={1,7,64};
    for(int round=0;round<3;++round) for(unsigned fixture=0;fixture<3;++fixture) {
        int id=(round+fixture)%NUM_STRUCTURES,n=sizes[fixture];
        CALL(setupPerformanceTest(eid,(sgx_status_t *)&result,id,n,TYPE_LINEAR_SCAN),0);
        for(int i=0;i<n;++i) {
            struct { uint64_t before;Linear_Scan_Block value;uint64_t after; } b;
            b.before=b.after=0x1122334455667788ULL;memset(&b.value,0xa5,sizeof b.value);
            CALL(opOneLinearScanBlock(eid,&result,id,i,&b.value,0),0);
            REQUIRE(b.before==b.after && b.before==0x1122334455667788ULL);
            for(int j=0;j<BLOCK_DATA_SIZE;++j) { REQUIRE(b.value.data[j]==0);++comparisons; }
            pattern(&b.value,i,round);
            Linear_Scan_Block before=b.value;
            CALL(opOneLinearScanBlock(eid,&result,id,i,&b.value,1),0);
            REQUIRE(!memcmp(&b.value,&before,sizeof before));
            REQUIRE(b.before==b.after && b.before==0x1122334455667788ULL);
        }
        // Revisit in reverse order, and overwrite once to exercise versions.
        for(int pass=0;pass<2;++pass) for(int i=n-1;i>=0;--i) {
            Linear_Scan_Block actual,expected;memset(&actual,0x5a,sizeof actual);
            pattern(&expected,i,round+pass);
            CALL(opOneLinearScanBlock(eid,&result,id,i,&actual,0),0);
            REQUIRE(!memcmp(&actual,&expected,sizeof expected));comparisons+=BLOCK_DATA_SIZE;
            if(!pass) {
                pattern(&actual,i,round+1);
                CALL(opOneLinearScanBlock(eid,&result,id,i,&actual,1),0);
            }
        }
        // Real SDK GCM failure followed by recovery in the same enclave.
        Linear_Scan_Block actual;memset(&actual,0x6b,sizeof actual);
        storage[id].data[sizeof(Real_Linear_Scan_Block)]^=1;
        CALL(opOneLinearScanBlock(eid,&result,id,0,&actual,0),1);
        for(int j=0;j<BLOCK_DATA_SIZE;++j)REQUIRE(actual.data[j]==0x6b);
        storage[id].data[sizeof(Real_Linear_Scan_Block)]^=1;
        CALL(opOneLinearScanBlock(eid,&result,id,0,&actual,0),0);
        Linear_Scan_Block expected;pattern(&expected,0,round+1);
        REQUIRE(!memcmp(&actual,&expected,sizeof expected));comparisons+=BLOCK_DATA_SIZE;
        CALL(free_structure(eid,(sgx_status_t *)&result,id),0);
    }
    REQUIRE(creates==9 && deletes==9);
    REQUIRE(sgx_destroy_enclave(eid)==SGX_SUCCESS);
    printf("{\"result\":\"PASS\",\"calls\":%u,\"byte_comparisons\":%u,\"reads\":%u,\"writes\":%u,\"structures\":%u,\"tamper_recoveries\":9}\n",
           calls,comparisons,reads,writes,creates);
    return 0;
}
