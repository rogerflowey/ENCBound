#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "bench.h"
#ifndef NATIVE
#include "sgx_urts.h"
#include "enclave_u.h"
#endif

static uint64_t now(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) exit(2);
    return (uint64_t)t.tv_sec*1000000000u + t.tv_nsec;
}
int main(int argc, char **argv)
{
#ifdef ENCBOUND_HOST_REQUIRE_AES
    __builtin_cpu_init();
    if (!__builtin_cpu_supports("aes")) {
        fputs("AES-NI required by this experimental enclave\n",stderr);
        return 77;
    }
#endif

    unsigned char output[OUTPUT_BYTES], expected[OUTPUT_BYTES];
    int which, n = 0, scanned, app = -1;
    uint64_t start, elapsed, create_ns = 0;
    if (argc != 3) return 2;
    char *end;
    long parsed = strtol(argv[1], &end, 10);
    if (end == argv[1] || *end || parsed < 0 || parsed > 4) return 2;
    which = (int)parsed;
    size_t length = bench_output_size(which);
    FILE *ref = fopen(argv[2], "rb");
    if (!ref) return 2;
    if (fread(expected,1,length,ref) != length || fgetc(ref) != EOF)
        return 2;
    fclose(ref);
#ifndef NATIVE
    sgx_enclave_id_t eid = 0;
    start = now();
    sgx_status_t st = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG,
                                       NULL, NULL, &eid, NULL);
    create_ns = now()-start;
    if (st != SGX_SUCCESS) { fprintf(stderr,"create failed: %x\n",st); return 3; }
#endif
    printf("{\"ready\":true,\"create_ns\":%" PRIu64 "}\n",create_ns);
    fflush(stdout);
    while ((scanned = scanf("%d", &n)) == 1 && n != 0) {
        if (n < 1 || n > 100000) return 2;
        memset(output,0,sizeof(output));
        start = now();
#ifdef NATIVE
        app = bench_run(which,n,output,length);
#else
        st = bench_run(eid,&app,which,n,output,length);
        if (st != SGX_SUCCESS) { fprintf(stderr,"transport failed: %x\n",st); return 3; }
#endif
        elapsed = now()-start;
        if (app || memcmp(output,expected,length)) {
            fprintf(stderr,"incorrect result: case=%d app=%d\n",which,app);
            for (size_t i=0;i<length;i++) if(output[i]!=expected[i]) {
                fprintf(stderr,"first differing byte %zu: %u != %u\n",i,output[i],expected[i]); break;
            }
            return 4;
        }
        printf("{\"case\":%d,\"iterations\":%d,\"ns\":%" PRIu64 ",\"correct\":true}\n",which,n,elapsed);
        fflush(stdout);
    }
    if (scanned == 0) return 2;
    start = now();
#ifndef NATIVE
    if (sgx_destroy_enclave(eid) != SGX_SUCCESS) return 3;
#endif
    printf("{\"destroy_ns\":%" PRIu64 "}\n",now()-start);
    return 0;
}
