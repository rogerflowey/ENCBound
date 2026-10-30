/* Reused from tests/early-bootstrap/host.c; SIM-only page inspection. */
#include <elf.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
/* Loaded-page check reduced from apps/pre-stl/host.c (this repository).
 * This is SDK SIM host inspection, not an SGX hardware permission claim. */
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
    unsigned verified = 0;
    for (unsigned i = 0; i < eh.e_shnum; ++i) {
        const char *name = names+sh[i].sh_name;
        if (!sh[i].sh_size || (strcmp(name, ".encbound.appdata") &&
            strcmp(name, ".encbound.apprelro") && strcmp(name, ".encbound.apprw") &&
            strcmp(name, ".encbound.appbss") && strcmp(name, ".encbound.globalrw") &&
            strcmp(name, ".encbound.globalbss") && strcmp(name, ".encbound.gcaps") &&
            strcmp(name, ".encbound.gfix"))) continue;
        int writable = strcmp(name, ".encbound.appdata") && strcmp(name, ".encbound.apprelro");
        uintptr_t start = base+sh[i].sh_addr, end = start+sh[i].sh_size;
        FILE *maps = fopen("/proc/self/maps", "r"); assert(maps);
        char line[512]; int found = 0;
        while (fgets(line, sizeof line, maps)) {
            unsigned long lo, hi; char perm[5];
            if (sscanf(line, "%lx-%lx %4s", &lo, &hi, perm) == 3 && start >= lo && end <= hi) {
                assert(perm[0] == 'r' && (perm[1] == 'w') == writable && perm[2] != 'x');
                found = 1; break;
            }
        }
        fclose(maps); assert(found); ++verified;
    }
    assert(verified >= 2);
    free(names); free(sh);
}

