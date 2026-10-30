/* Direct [user_check] confused-deputy control for the selected ConFlow ECALLs.
 *
 * The original EDL is, for example:
 *   public void ecall_encrypt([user_check]float *input,int N,[user_check]float *output);
 *   public void ecall_decrypt([user_check]float *input,int N,[user_check]float *output);
 *
 * [user_check] passes the host-chosen raw pointer with no bridge copy, length,
 * null, canonical or range check.  BASELINE (stock Intel bridge, no ENCBound
 * instrumentation) therefore lets the host point input/output at enclave
 * memory.  RADIX_ONLY/MAC27 insert encbound_require at each access and should
 * reject the same call.
 *
 * This probe only uses the unchanged public ECALLs.  It does not modify the
 * application, EDL or bridge.
 *
 *   cd       ecall_encrypt writes 20 shares at an enclave-internal address,
 *            then ecall_decrypt reads that address back into a host buffer.
 *            BASELINE must recover the four input floats; protected profiles
 *            must reject the first enclave-internal access.
 *   control  the same two ECALLs using only host buffers.  This must pass in
 *            every profile and shows the operator pair is functional.
 *
 * The enclave target is read from the image's own .encbound.appbss section and
 * checked against /proc/self/maps before use.  No fixed scratch offset is
 * assumed.  SIM-only read-back is used to verify the baseline write.
 */
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sgx_urts.h"
#include "Enclave_u.h"

#define N 4
#define SHARES 5
#define WRITE_FLOATS (SHARES * N)
#define SPAN_BYTES ((uint64_t)WRITE_FLOATS * sizeof(float))

__attribute__((noinline)) void conflow_cd_ready(void)
{
    __asm__ volatile("" ::: "memory");
}

void ocall_print(const char *message) { fprintf(stderr, "%s\n", message); }

static int find_writable_section(const char *image, const char *const *wants,
                                 int nwants, uint64_t *addr, uint64_t *size,
                                 const char **found_name)
{
    FILE *f = fopen(image, "rb");
    if (!f) return 0;
    Elf64_Ehdr eh;
    if (fread(&eh, 1, sizeof eh, f) != sizeof eh || eh.e_shnum == 0) {
        fclose(f); return 0;
    }
    Elf64_Shdr *sh = calloc(eh.e_shnum, sizeof(*sh));
    if (!sh) { fclose(f); return 0; }
    if (fseek(f, eh.e_shoff, SEEK_SET) != 0 ||
        fread(sh, sizeof(*sh), eh.e_shnum, f) != eh.e_shnum) {
        free(sh); fclose(f); return 0;
    }
    char *names = malloc(sh[eh.e_shstrndx].sh_size);
    if (!names ||
        fseek(f, sh[eh.e_shstrndx].sh_offset, SEEK_SET) != 0 ||
        fread(names, 1, sh[eh.e_shstrndx].sh_size, f) !=
            sh[eh.e_shstrndx].sh_size) {
        free(names); free(sh); fclose(f); return 0;
    }
    int found = 0;
    for (int w = 0; w < nwants && !found; ++w) {
        for (unsigned i = 0; i < eh.e_shnum; ++i) {
            const char *name = names + sh[i].sh_name;
            if (strcmp(name, wants[w]) != 0) continue;
            if (!(sh[i].sh_flags & SHF_WRITE) ||
                sh[i].sh_size < SPAN_BYTES)
                continue;
            *addr = sh[i].sh_addr;
            *size = sh[i].sh_size;
            if (found_name) *found_name = wants[w];
            found = 1;
            break;
        }
    }
    free(names); free(sh); fclose(f);
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

static void fill(float *in)
{
    in[0] = 1.25f; in[1] = 2.5f; in[2] = 3.75f; in[3] = 5.0f;
}

static int same(const float *a, const float *b, int n)
{
    for (int i = 0; i < n; ++i) {
        float d = a[i] - b[i];
        if (d < 0) d = -d;
        if (d > 1e-4f) return 0;
    }
    return 1;
}

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

    sgx_enclave_id_t eid = 0;
    sgx_status_t status = sgx_create_enclave(image, SGX_DEBUG_FLAG, NULL, NULL,
                                             &eid, NULL);
    if (status) {
        fprintf(stderr, "create=%#x\n", (unsigned)status);
        return 3;
    }
    conflow_cd_ready();

    float in[N], out[N];
    fill(in);
    for (int i = 0; i < N; ++i) out[i] = -1.0f;

    if (do_control) {
        float shares[WRITE_FLOATS];
        status = ecall_encrypt(eid, in, N, shares);
        if (status) { fprintf(stderr, "control encrypt=%#x\n", (unsigned)status); return 20; }
        status = ecall_decrypt(eid, shares, N, out);
        if (status) { fprintf(stderr, "control decrypt=%#x\n", (unsigned)status); return 20; }
        printf("{\"mode\":\"control\",\"status\":0,\"readback\":\"%s\"}\n",
               same(in, out, N) ? "PASS" : "FAIL");
        return same(in, out, N) ? 0 : 21;
    }

    /* Prefer the dedicated application BSS; protected images keep it in the
     * protected global/BSS segments instead.  The protection check rejects the
     * raw enclave pointer before any protected-profile store, so only BASELINE
     * actually writes these bytes. */
    static const char *const wants[] = {
        ".encbound.appbss", ".bss", ".encbound.globalbss"
    };
    uint64_t saddr = 0, ssize = 0;
    const char *sname = NULL;
    if (!find_writable_section(image, wants,
                               (int)(sizeof wants / sizeof wants[0]),
                               &saddr, &ssize, &sname)) {
        fprintf(stderr, "no suitable writable section in %s\n", image);
        return 4;
    }
    uintptr_t target = (uintptr_t)(base + saddr + ssize - SPAN_BYTES);
    target &= ~(uintptr_t)3;
    if (!mapped_rw(target, SPAN_BYTES)) {
        fprintf(stderr, "target %#lx (%s) is not mapped rw\n",
                (unsigned long)target, sname);
        return 5;
    }

    /* Step 1: the host names an enclave-internal address as the output. */
    status = ecall_encrypt(eid, in, N, (float *)target);
    if (status) {
        fprintf(stderr, "cd encrypt=%#x\n", (unsigned)status);
        return 20;
    }
    /* Step 2: the host names the same enclave address as the input.  A
     * functional decrypt proving the enclave actually wrote the shares there
     * and can read them back. */
    status = ecall_decrypt(eid, (float *)target, N, out);
    if (status) {
        fprintf(stderr, "cd decrypt=%#x\n", (unsigned)status);
        return 20;
    }
    printf("{\"mode\":\"cd\",\"status\":0,\"target\":\"%#lx\","
           "\"readback\":\"%s\",\"first\":%.9g}\n",
           (unsigned long)target, same(in, out, N) ? "PASS" : "FAIL", out[0]);
    return same(in, out, N) ? 0 : 21;
}
