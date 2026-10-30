/* Finite SDK SIM integration host. Loaded-page checks derive from the local
 * STL service host. No protection/hardware/performance result is asserted.
 */
#include <assert.h>
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_urts.h"
#include "enclave_u.h"

static unsigned calls, snapshots, comparisons;

static void permissions(const char *image)
{
    FILE *f = fopen(image, "rb"); assert(f);
    Elf64_Ehdr eh; assert(fread(&eh, 1, sizeof eh, f) == sizeof eh);
    Elf64_Shdr *sh = malloc(eh.e_shnum*sizeof(*sh)); assert(sh);
    assert(fseek(f, eh.e_shoff, SEEK_SET) == 0);
    assert(fread(sh, sizeof(*sh), eh.e_shnum, f) == eh.e_shnum);
    char *names = malloc(sh[eh.e_shstrndx].sh_size); assert(names);
    assert(fseek(f, sh[eh.e_shstrndx].sh_offset, SEEK_SET) == 0);
    assert(fread(names, 1, sh[eh.e_shstrndx].sh_size, f) == sh[eh.e_shstrndx].sh_size);
    fclose(f);
    const char *configured = getenv("ENCBOUND_TEST_BASE"); assert(configured);
    uintptr_t base = strtoull(configured, NULL, 0);
    unsigned text_verified = 0, data_verified = 0;
    for (unsigned i = 0; i < eh.e_shnum; ++i) {
        const char *name = names+sh[i].sh_name;
        int text = !strcmp(name, ".text");
        int ro = !strcmp(name, ".encbound.appdata") || !strcmp(name, ".encbound.apprelro");
        int data = ro || !strcmp(name, ".encbound.apprw") || !strcmp(name, ".encbound.appbss") ||
            !strcmp(name, ".encbound.globalrw") || !strcmp(name, ".encbound.globalbss") ||
            !strcmp(name, ".encbound.gcaps") || !strcmp(name, ".encbound.gfix");
        if (!sh[i].sh_size || (!text && !data)) continue;
        uintptr_t start = base+sh[i].sh_addr, end = start+sh[i].sh_size;
        FILE *maps = fopen("/proc/self/maps", "r"); assert(maps);
        char line[512]; int found = 0;
        while (fgets(line, sizeof line, maps)) {
            unsigned long lo, hi; char perm[5];
            if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perm) == 3 && start >= lo && end <= hi) {
                assert(perm[0] == 'r' && (perm[1] == 'w') == (!text && !ro) && (perm[2] == 'x') == text);
                found = 1; break;
            }
        }
        fclose(maps); assert(found);
        if (text) ++text_verified; else ++data_verified;
    }
    assert(text_verified == 1 && data_verified >= 3);
    free(names); free(sh);
    fprintf(stderr, "loaded app page permissions: PASS (%u data ranges, text RX)\n", data_verified);
}

static void transfer(sgx_enclave_id_t eid, uint32_t key, const uint8_t *data,
                     size_t total, size_t bytes, size_t offset)
{
    crust_status_t value = CRUST_UNEXPECTED_ERROR;
    sgx_status_t transport = ecall_safe_store2(eid, &value, ECALL_RESTORE_FROM_UPGRADE,
                                               data, total, bytes, offset, key);
    ++calls;
    if (transport != SGX_SUCCESS || value != CRUST_SUCCESS)
        fprintf(stderr, "transfer %u: transport=%x application=%x\n", calls, transport, value);
    assert(transport == SGX_SUCCESS && value == CRUST_SUCCESS);
}

static void snapshot(sgx_enclave_id_t eid, uint32_t key, const uint8_t *expected,
                     size_t bytes, int entries)
{
    uint8_t observed[4096]; assert(bytes <= sizeof observed);
    memset(observed, 0xa5, sizeof observed);
    int value = -99;
    assert(crust_selected_snapshot(eid, &value, key, observed, bytes) == SGX_SUCCESS);
    ++calls; ++snapshots;
    assert(value == entries);
    assert(memcmp(observed, expected, bytes) == 0);
    comparisons += bytes;
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) return 2;
    sgx_enclave_id_t eid;
    sgx_status_t status = sgx_create_enclave(argv[1], SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL);
    if (status) { fprintf(stderr, "create: %x\n", status); return 3; }
    permissions(argv[1]);
    int result = -99;
    assert(layout_checks(eid, &result) == SGX_SUCCESS && result == 0); ++calls;
    assert(crust_selected_serial_check(eid, &result) == SGX_SUCCESS && result == 0); ++calls;
    fprintf(stderr, "runtime region isolation and serial gate: PASS\n");

    if (argc == 3) {
        assert(strcmp(argv[2], "completion") == 0);
        uint8_t byte = 42;
        transfer(eid, 9000, &byte, 1, 1, 0);
        return 99; /* The terminal restore stub must stop before any return. */
    }

    uint8_t expected[4096] = {0}, bytes[4096];
    for (unsigned i = 0; i < sizeof bytes; ++i) bytes[i] = (uint8_t)(i*29+7);
    assert(crust_selected_snapshot(eid, &result, 123456, bytes, 0) == SGX_SUCCESS && result == -1); ++calls;

    /* Three retained buffers, with empty, tiny and largest finite input cases. */
    transfer(eid, 10, NULL, 256, 0, 0);
    snapshot(eid, 10, expected, 256, 1);
    transfer(eid, 10, bytes, 256, 1, 0); expected[0] = bytes[0];
    snapshot(eid, 10, expected, 256, 1);
    /* A larger declared total must reuse the first buffer. The write stays
     * within the original allocation; snapshots prove old bytes survive. */
    transfer(eid, 10, bytes+32, 4096, 64, 32); memcpy(expected+32, bytes+32, 64);
    snapshot(eid, 10, expected, 256, 1);
    for (unsigned round = 0; round < 32; ++round) {
        size_t offset = (round*13)%200;
        transfer(eid, 10, bytes+round, 256, 16, offset);
        memcpy(expected+offset, bytes+round, 16);
        snapshot(eid, 10, expected, 256, 1);
    }

    uint8_t second[1024] = {0};
    transfer(eid, 20, bytes, sizeof second, 1023, 0); memcpy(second, bytes, 1023);
    snapshot(eid, 20, second, sizeof second, 2);
    snapshot(eid, 10, expected, 256, 2);
    transfer(eid, 20, bytes+32, sizeof second, 300, 200); memcpy(second+200, bytes+32, 300);
    snapshot(eid, 20, second, sizeof second, 2);

    uint8_t third[4096] = {0};
    transfer(eid, 30, bytes, sizeof third, 4095, 0); memcpy(third, bytes, 4095);
    snapshot(eid, 30, third, sizeof third, 3);
    snapshot(eid, 10, expected, 256, 3);
    snapshot(eid, 20, second, sizeof second, 3);

    /* Above both configured application arenas: ordinary allocation failure
     * must return without inserting a pool entry or losing existing state. */
    crust_status_t failure = CRUST_SUCCESS;
    assert(ecall_safe_store2(eid, &failure, ECALL_RESTORE_FROM_UPGRADE, NULL,
        0x2000000, 0, 0, 4000) == SGX_SUCCESS && failure == CRUST_MALLOC_FAILED); ++calls;
    assert(crust_selected_snapshot(eid, &result, 4000, bytes, 0) == SGX_SUCCESS && result == -1); ++calls;
    /* Intel's copied-buffer overflow validation, followed by a valid call. */
    assert(ecall_safe_store2(eid, &failure, ECALL_RESTORE_FROM_UPGRADE,
        (const uint8_t *)(UINTPTR_MAX-7), 256, 16, 0, 4000) == SGX_ERROR_INVALID_PARAMETER); ++calls;
    transfer(eid, 10, NULL, 256, 0, 0);
    snapshot(eid, 10, expected, 256, 3);
    snapshot(eid, 20, second, sizeof second, 3);
    snapshot(eid, 30, third, sizeof third, 3);
    assert(crust_selected_serial_check(eid, &result) == SGX_SUCCESS && result == 0); ++calls;
    assert(sgx_destroy_enclave(eid) == SGX_SUCCESS);
    printf("{\"result\":\"PASS\",\"calls\":%u,\"snapshots\":%u,\"compared_bytes\":%u,\"retained_buffers\":3}\n",
           calls, snapshots, comparisons);
    return 0;
}
