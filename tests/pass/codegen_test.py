#!/usr/bin/env python3
"""Execute the O0/O2 code generators against an independent check-call oracle.

This is a compiler test, not a native ENCBound protection result: a test-only
checker maps synthetic capability bits to ordinary storage and records every
check's bits, width and kind. SDK tests cover the real runtime and real stack.
"""
from pathlib import Path
import os
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'build/pass/codegen'
OUT.mkdir(parents=True, exist_ok=True)
DRIVER = ROOT / 'tools/encbound-cc.sh'

SOURCE = r'''
#include <stddef.h>
#include <stdint.h>
typedef uint32_t vector4 __attribute__((vector_size(16)));
uintptr_t cg_offset(unsigned char *p, ptrdiff_t n) { return (uintptr_t)(p + n); }
uint64_t cg_load(const uint64_t *p) { return *p; }
void cg_store(uint64_t *p, uint64_t v) { *p = v; }
void cg_vector(vector4 *p, vector4 v) { *p = v; }
void cg_copy(void *d, const void *s, size_t n) { __builtin_memcpy(d, s, n); }
void cg_move(void *d, const void *s, size_t n) { __builtin_memmove(d, s, n); }
void cg_set(void *d, int c, size_t n) { __builtin_memset(d, c, n); }
'''

HARNESS = r'''
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t vector4 __attribute__((vector_size(16)));
extern uintptr_t cg_offset(unsigned char *, ptrdiff_t);
extern uint64_t cg_load(const uint64_t *);
extern void cg_store(uint64_t *, uint64_t);
extern void cg_vector(vector4 *, vector4);
extern void cg_copy(void *, const void *, size_t);
extern void cg_move(void *, const void *, size_t);
extern void cg_set(void *, int, size_t);
#define CAP UINT64_C(0x2123456700000000)
#define PTR(n) ((void *)(uintptr_t)(CAP + (n)))
static union { uint64_t words[32]; unsigned char bytes[256]; vector4 vectors[16]; } pool;
static struct { uint64_t cap, width; uint32_t kind; } events[4];
static unsigned count;
uint64_t encbound_require(uint64_t cap, uint64_t width, uint32_t kind) {
    /* The decoder's address is deliberately different from the capability. */
    if (cap < CAP || cap - CAP >= 256 || width > 256 - (cap - CAP)) _Exit(77);
    assert(count < 4 && width != 0 && (kind == 1 || kind == 2));
    events[count].cap = cap; events[count].width = width; events[count++].kind = kind;
    return (uintptr_t)(pool.bytes + (cap - CAP));
}
static void event(unsigned i, unsigned offset, unsigned width, unsigned kind) {
    assert(events[i].cap == CAP + offset && events[i].width == width && events[i].kind == kind);
}
int main(int argc, char **argv) {
    (void)argv;
    if (argc > 1) { cg_store(PTR(256), 42); return 99; }
    assert(cg_offset(PTR(64), -17) == CAP + 47);
    assert(cg_offset(PTR(64), 17) == CAP + 81);
    /* Representation arithmetic only; not a claim about undefined C accesses. */
    assert(cg_offset((void *)(uintptr_t)UINT64_C(0x21234567fffffff8), 16)
           == UINT64_C(0x2123456800000008));
    assert(count == 0);
    cg_store(PTR(32), UINT64_C(0xfedcba9876543210));
    assert(pool.words[4] == UINT64_C(0xfedcba9876543210));
    assert(count == 1); event(0, 32, 8, 2); count = 0;
    assert(cg_load(PTR(32)) == pool.words[4]);
    assert(count == 1); event(0, 32, 8, 1); count = 0;
    cg_vector(PTR(64), (vector4){11, 22, 33, 44});
    assert(pool.vectors[4][0] == 11 && pool.vectors[4][3] == 44);
    assert(count == 1); event(0, 64, 16, 2); count = 0;
    for (unsigned i = 0; i < 16; ++i) pool.bytes[i] = (unsigned char)(i + 1);
    cg_copy(PTR(128), PTR(0), 16);
    assert(memcmp(pool.bytes + 128, pool.bytes, 16) == 0);
    assert(count == 2); event(0, 128, 16, 2); event(1, 0, 16, 1); count = 0;
    cg_move(PTR(1), PTR(0), 15);
    for (unsigned i = 1; i < 16; ++i) assert(pool.bytes[i] == i);
    assert(count == 2); event(0, 1, 15, 2); event(1, 0, 15, 1); count = 0;
    cg_set(PTR(192), 0x5a, 16);
    for (unsigned i = 192; i < 208; ++i) assert(pool.bytes[i] == 0x5a);
    assert(count == 1); event(0, 192, 16, 2); count = 0;
    cg_copy(PTR(128), PTR(0), 0);
    cg_move(PTR(128), PTR(0), 0);
    cg_set(PTR(192), 0, 0);
    assert(count == 0 && pool.bytes[192] == 0x5a);
    puts("CODEGEN EXECUTION PASS (bits, widths, kinds, decoded addresses, zero length)");
    return 0;
}
'''
src, harness = OUT / 'operations.c', OUT / 'oracle.c'
src.write_text(SOURCE)
harness.write_text(HARNESS)


def run(args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, **kwargs)


def normalized(path):
    return re.sub(r"^; ModuleID = .*\n", '', path.read_text())


for profile in ['RADIX_ONLY', 'MAC27']:
    ir = []
    for cg in ['-O0', '-O2']:
        name = profile + cg
        obj = OUT / (name + '.o')
        env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_CODEGEN_OPT=cg)
        result = run([str(DRIVER), str(src), str(obj), '-O2'], env=env)
        (OUT / (name + '.build.log')).write_text(result.stdout + result.stderr)
        assert result.returncode == 0, result.stderr
        checked = obj.with_suffix('.checked.ll')
        ir.append(normalized(checked))
        assert 'optnone' not in ir[-1]
        exe = OUT / name
        subprocess.run(['clang-21', '-O2', str(harness), str(obj), '-o', str(exe)], check=True)
        result = run([str(exe)])
        (OUT / (name + '.run.log')).write_text(result.stdout + result.stderr)
        assert result.returncode == 0, result.stderr
        rejected = run([str(exe), 'reject'])
        assert rejected.returncode == 77, 'check failed to reject before the store'
        disasm = run(['objdump', '-dr', str(obj)])
        (OUT / (name + '.disasm')).write_text(disasm.stdout)
        # Drive the real publication path on an unsupported operation as well.
        rejected_obj = OUT / (name + '.rejected.o')
        bad = run([str(DRIVER), str(ROOT / 'tests/pass/privileged.c'),
                   str(rejected_obj), '-O2'], env=env)
        assert bad.returncode != 0 and not rejected_obj.exists()
        assert 'ENCBound: unsupported' in bad.stderr
        print(name, 'PASS: executed operations, rejection before store, admission')
    assert ir[0] == ir[1], 'code-generation option altered transformed IR'

bad = run([str(DRIVER), str(src), str(OUT / 'bad-level.o'), '-O2'],
          env=dict(os.environ, ENCBOUND_PROFILE='MAC27', ENCBOUND_CODEGEN_OPT='-O3'))
assert bad.returncode != 0 and 'unsupported ENCBound code-generation level' in bad.stderr
assert not (OUT / 'bad-level.o').exists()
print('CODEGEN MATRIX PASS (two profiles x O0/O2; identical checked IR)')
