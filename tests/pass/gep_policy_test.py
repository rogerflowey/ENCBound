#!/usr/bin/env python3
"""Exercise the GEP experiment switches and fail-closed InstCombine driver."""
from pathlib import Path
import os
import resource
import subprocess

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'build/pass/gep-policy'
OUT.mkdir(parents=True, exist_ok=True)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
DRIVER = ROOT / 'tools/encbound-cc.sh'


def compile_source(name, source, keep, combine):
    src = OUT / (name + '.c')
    obj = OUT / (name + '.o')
    src.write_text(source)
    obj.unlink(missing_ok=True)
    obj.with_suffix('.checked.ll').unlink(missing_ok=True)
    env = dict(os.environ, ENCBOUND_PROFILE='MAC27', ENCBOUND_CODEGEN_OPT='-O2',
               ENCBOUND_KEEP_GEP_FLAGS=str(keep), ENCBOUND_POST_INSTCOMBINE=str(combine))
    result = subprocess.run([DRIVER, src, obj, '-O2'], env=env,
                            capture_output=True, text=True)
    (OUT / (name + '.log')).write_text(result.stdout + result.stderr)
    return result, obj


arithmetic = 'unsigned long offset(char *p, long n) { return (unsigned long)(p+n); }\n'
for keep in (0, 1):
    for combine in (0, 1):
        result, obj = compile_source(f'offset-{keep}-{combine}', arithmetic, keep, combine)
        assert result.returncode == 0, result.stderr
        text = obj.with_suffix('.checked.ll').read_text()
        assert 'getelementptr' in text
        assert ('getelementptr inbounds' in text) == bool(keep)
        assert 'encbound.gep.base' not in text
        if combine:
            assert obj.with_suffix('.pre-instcombine.ll').exists()
            assert obj.with_suffix('.post-instcombine.ll').exists()

# The optimizer sees the outer nonzero condition and folds the inserted guard.
# The current verifier deliberately rejects that different diamond shape. It
# must not publish an unchecked object merely because LLVM verifies the IR.
guarded = ('void guarded(void *p, unsigned long n) {\n'
           '  if (n) __builtin_memset(p, 0, n);\n}\n')
for keep in (0, 1):
    result, obj = compile_source(f'guarded-{keep}-0', guarded, keep, 0)
    assert result.returncode == 0, result.stderr
    result, obj = compile_source(f'guarded-{keep}-1', guarded, keep, 1)
    assert result.returncode != 0
    assert 'memory intrinsic has no checked nonzero path' in result.stderr
    assert not obj.exists() and not obj.with_suffix('.checked.ll').exists()

print('GEP POLICY PASS (four switch combinations; guarded InstCombine rejection before publication)')
