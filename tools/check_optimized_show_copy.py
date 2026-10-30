#!/usr/bin/env python3
"""Machine-code attribution for the original wallet SHOW copy (C4).

docs/legacy/steps/04a-capability-semantics.md C4: for optimized binaries, identify the
original copy's emitted instruction and the enforcing check even when source
frames are optimized away. At frontend -O2 the original ``*wallet =
*unsealed_wallet`` assignment (enclave.cpp:155) is emitted as a ``memcpy`` call
with the 30112-byte length, preceded by the two RANGE checks the ENCBound
transform inserted. This tool asserts that shape structurally, from the object
relocations, so no debug/source frame is required.

It checks the compiled application object only:

  * the original application entry ``ecall_show_wallet`` exists;
  * two ``encbound_require`` calls use ``%esi == width`` with kinds ``%edx == 2``
    (the destination write) and ``%edx == 1`` (the source read), the write check
    before the read check;
  * both checked results flow through registers/spills into memcpy destination
    and source, with the exact length, no clobber and no alternate branch entry.

Only the selected straight-line move/call pattern is admitted. Unsupported
instructions or control flow fail visibly; this is not a general x86 verifier.

Usage: check_optimized_show_copy.py --build <dir> [--width N] [--obj obj]
       check_optimized_show_copy.py --selftest
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

SHOW_SYMBOL = "ecall_show_wallet"
DEFAULT_WIDTH = 30112
DEFAULT_OBJ = "enclave/enclave.o"

INSN_RE = re.compile(r"^\s*([0-9a-f]+):\t[0-9a-f ]+\t(\S+)\s*(.*)$")
RELOC_RE = re.compile(r"^\s*([0-9a-f]+):\s+R_X86_64_\S+\s+(\S+)")


class DisasmError(Exception):
    pass


def parse_disasm(text: str):
    """Return a list of instruction dicts with an optional call reloc target.

    Each item: {addr, mnemonic, operands, reloc}. Relocation lines attach to
    the most recent instruction.
    """
    insns = []
    for raw in text.splitlines():
        m = INSN_RE.match(raw)
        if m:
            insns.append(
                {
                    "addr": int(m.group(1), 16),
                    "mnemonic": m.group(2),
                    "operands": m.group(3).strip(),
                    "reloc": None,
                }
            )
            continue
        r = RELOC_RE.match(raw)
        if r and insns:
            sym = r.group(2)
            # objdump renders call relocations as ``memcpy-0x4``.
            insns[-1]["reloc"] = sym.split("-")[0].split("+")[0]
    return insns


# Bounded x86-64 proof for the selected -O0 backend: a straight-line window
# containing two checks and the copy, with explicit register/spill data flow.
# Unknown instructions, alternate entries or stack-base changes fail closed.
REGS = {r: r for r in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp']}
REGS.update({r: r for r in [f'r{i}' for i in range(8, 16)]})
for short, full in [('eax', 'rax'), ('ebx', 'rbx'), ('ecx', 'rcx'),
                    ('edx', 'rdx'), ('esi', 'rsi'), ('edi', 'rdi'),
                    ('ebp', 'rbp'), ('esp', 'rsp')]:
    REGS[short] = full
for i in range(8, 16):
    REGS[f'r{i}d'] = f'r{i}'
STACK_RE = re.compile(r'^(-?0x[0-9a-f]+)?\(%(rsp|rbp)\)$')
CALLER_SAVED = {'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'}


def verify_disasm(text: str, width: int) -> list:
    insns = parse_disasm(text)
    copies = [i for i, v in enumerate(insns)
              if v['mnemonic'] == 'call' and v['reloc'] == 'memcpy']
    if len(copies) != 1:
        raise DisasmError('expected exactly one original memcpy in SHOW')
    copy = copies[0]
    calls = [i for i in range(copy) if insns[i]['mnemonic'] == 'call']
    if len(calls) < 2:
        raise DisasmError('missing the two enforcing calls')
    write, read = calls[-2:]
    if any(insns[i]['reloc'] != 'encbound_require' for i in [write, read]):
        raise DisasmError('the two calls before memcpy must be the checks')

    # Begin after the previous call or control transfer. All facts start unknown.
    start = calls[-3] + 1 if len(calls) > 2 else 0
    for i in range(start, write):
        m = insns[i]['mnemonic']
        if m.startswith('j') or m.startswith('loop') or m.startswith('ret'):
            start = i + 1
    lo, hi = insns[start]['addr'], insns[copy]['addr']
    for v in insns:
        m = v['mnemonic']
        if m.startswith('j') or m.startswith('loop'):
            target = re.match(r'^([0-9a-f]+)\s', v['operands'])
            if not target:
                raise DisasmError('indirect/unrecognized branch in SHOW')
            if lo < int(target.group(1), 16) <= hi:
                raise DisasmError('branch can bypass check/operand setup')

    regs, spills = {}, {}
    stack_base = None

    def reg(operand):
        return REGS.get(operand[1:]) if operand.startswith('%') else None

    def stack(operand):
        nonlocal stack_base
        m = STACK_RE.fullmatch(operand)
        if not m:
            return None
        base = m.group(2)
        if stack_base is not None and base != stack_base:
            raise DisasmError('mixed stack bases require an alias proof')
        stack_base = base
        return int(m.group(1) or '0', 16)

    for i in range(start, copy + 1):
        v = insns[i]
        m, operands = v['mnemonic'], v['operands']
        if m == 'call':
            if i in [write, read]:
                kind = 2 if i == write else 1
                if regs.get('rsi') != width or regs.get('rdx') != kind:
                    raise DisasmError('check width/kind is unknown or clobbered')
                for r in CALLER_SAVED:
                    regs.pop(r, None)
                regs['rax'] = ('checked', kind, v['addr'])
            elif i == copy:
                if (regs.get('rdi') != ('checked', 2, insns[write]['addr']) or
                        regs.get('rsi') != ('checked', 1, insns[read]['addr']) or
                        regs.get('rdx') != width):
                    raise DisasmError('copy operands/length do not carry both check results')
            else:
                raise DisasmError('unexpected call in proof window')
            continue
        if m in ['nop', 'nopl', 'nopw']:
            continue
        if m not in ['mov', 'movl', 'movq']:
            raise DisasmError(f'unsupported instruction in copy proof: {m}')
        # Memory operands in the admitted window use a single base, no index.
        parts = operands.split(',')
        if len(parts) != 2:
            raise DisasmError('unsupported move operands')
        src, dst = parts
        src_reg, dst_reg = reg(src), reg(dst)
        if dst_reg in ['rsp', 'rbp']:
            raise DisasmError('stack base changed inside proof window')
        bits = 64
        for operand, canonical in [(src, src_reg), (dst, dst_reg)]:
            if canonical and operand != '%' + canonical:
                bits = 32
        if m == 'movl':
            bits = 32
        value = None
        if src.startswith('$'):
            try:
                value = int(src[1:], 0)
            except ValueError as exc:
                raise DisasmError('unrecognized immediate') from exc
        elif src_reg:
            value = regs.get(src_reg)
        else:
            slot = stack(src)
            if slot is not None and bits == 64:
                value = spills.get(slot)
            # An ordinary memory load is unknown; it cannot create a check token.
        if bits == 32:
            value = value & 0xffffffff if isinstance(value, int) else None
        if dst_reg:
            regs[dst_reg] = value
        else:
            slot = stack(dst)
            if slot is None:
                raise DisasmError('unclassified store may overwrite checked spill')
            size = bits // 8
            for old in list(spills):
                if slot < old + 8 and old < slot + size:
                    del spills[old]
            if bits == 64:
                spills[slot] = value

    return [
        f"write check addr=0x{insns[write]['addr']:x} width={width} kind=2",
        f"read check addr=0x{insns[read]['addr']:x} width={width} kind=1",
        f"original copy addr=0x{insns[copy]['addr']:x} memcpy length={width}",
        'both checked addresses reach memcpy in one block with no bypass entry',
    ]


def load_disasm(obj: Path) -> str:
    out = subprocess.run(
        ["objdump", "-dr", f"--disassemble={SHOW_SYMBOL}", str(obj)],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        raise DisasmError(f"objdump failed on {obj}: {out.stderr.strip()}")
    text = out.stdout
    if SHOW_SYMBOL not in text:
        raise DisasmError(f"{SHOW_SYMBOL} not found in {obj}")
    return text


def selftest() -> int:
    good = f"""
00000000000001c0 <{SHOW_SYMBOL}>:
 2d3:	48 8b 7c 24 28       	mov    0x28(%rsp),%rdi
 2d8:	be a0 75 00 00       	mov    $0x75a0,%esi
 2dd:	ba 02 00 00 00       	mov    $0x2,%edx
 2e2:	e8 00 00 00 00       	call   2e7 <{SHOW_SYMBOL}+0x127>
			2e3: R_X86_64_PLT32	encbound_require-0x4
 2e7:	48 8b 7c 24 18       	mov    0x18(%rsp),%rdi
 2ec:	48 89 44 24 08       	mov    %rax,0x8(%rsp)
 2f1:	be a0 75 00 00       	mov    $0x75a0,%esi
 2f6:	ba 01 00 00 00       	mov    $0x1,%edx
 2fb:	e8 00 00 00 00       	call   300 <{SHOW_SYMBOL}+0x140>
			2fc: R_X86_64_PLT32	encbound_require-0x4
 300:	48 8b 7c 24 08       	mov    0x8(%rsp),%rdi
 305:	48 89 c6             	mov    %rax,%rsi
 308:	ba a0 75 00 00       	mov    $0x75a0,%edx
 30d:	e8 00 00 00 00       	call   312 <{SHOW_SYMBOL}+0x152>
			30e: R_X86_64_PLT32	memcpy-0x4
"""
    cases = []
    cases.append(("positive", good, True))
    cases.append(("missing_copy", good.replace("memcpy-0x4", "memmove-0x4"),
                  False))
    cases.append(("wrong_kind", good.replace("$0x1,%edx", "$0x2,%edx"), False))
    # wrong width on the copy length preceding memcpy
    bad_width = good.replace(" 308:\tba a0 75 00 00       \tmov    $0x75a0,%edx",
                             " 308:\tba 10 00 00 00       \tmov    $0x10,%edx")
    cases.append(("wrong_copy_width", bad_width, False))
    # a raw widening store before the copy (no checked destination)
    unchecked = good.replace(" 300:\t48 8b 7c 24 08       \tmov    0x8(%rsp),%rdi",
                             " 300:\t48 89 fe             \tmov    %rdi,%rsi")
    cases.append(("unchecked_dest", unchecked, False))
    # return value dropped between a check and the copy
    dropped = good.replace(" 2ec:\t48 89 44 24 08       \tmov    %rax,0x8(%rsp)",
                           " 2ec:\t90                   \tnop")
    cases.append(("dropped_check", dropped, False))
    cases.append(("wrong_spill", good.replace('mov    0x8(%rsp),%rdi',
                                             'mov    0x28(%rsp),%rdi'), False))
    cases.append(("wrong_source", good.replace('mov    %rax,%rsi',
                                              'mov    %rax,%r10'), False))
    for name, instruction in [
            ('clobber_source', 'mov    $0x10,%esi'),
            ('clobber_destination', 'mov    $0x10,%edi'),
            ('clobber_length', 'mov    %r10d,%edx'),
            ('arithmetic_clobber', 'xor    %esi,%esi'),
            ('branch_bypass', 'jne    300 <bypass>'),
            ('extra_call', 'call   300 <unknown>')]:
        # Synthetic assembly text: the parser consumes instructions/relocations,
        # not their encodings. This unique address fits before the copy.
        cases.append((name, good.replace(' 30d:',
                      f' 30c:\t90\t{instruction}\n 30d:'), False))
    cases.append(('overlap_spill', good.replace(' 300:',
                  ' 2ff:\t90\tmovl   $0x0,0xc(%rsp)\n 300:'), False))
    bypass = ' 2c0:\t90\tjne    300 <bypass>\n' + good
    cases.append(('entry_after_write_check', bypass, False))
    cases.append(('stale_check_width', good.replace(' 2e2:',
                  ' 2e1:\t90\tmov    %r10d,%esi\n 2e2:'), False))

    failures = 0
    for name, text, want_ok in cases:
        try:
            verify_disasm(text, DEFAULT_WIDTH)
            got_ok = True
        except DisasmError:
            got_ok = False
        if got_ok != want_ok:
            failures += 1
            print(f"selftest {name}: FAIL (want_ok={want_ok})", file=sys.stderr)
        else:
            print(f"selftest {name}: ok")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--build")
    ap.add_argument("--obj")
    ap.add_argument("--width", type=int, default=DEFAULT_WIDTH)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if args.obj:
        obj = Path(args.obj)
    elif args.build:
        obj = Path(args.build) / DEFAULT_OBJ
    else:
        ap.error("one of --build or --obj is required")
    if not obj.is_file():
        print(f"optimized-copy: FAIL: no object {obj}", file=sys.stderr)
        return 1

    try:
        findings = verify_disasm(load_disasm(obj), args.width)
    except DisasmError as exc:
        print(f"optimized-copy: FAIL: {exc}", file=sys.stderr)
        return 1

    print(f"optimized-copy: object={obj} width={args.width}")
    for line in findings:
        print(f"  {line}")
    print("OPTIMIZED COPY ATTRIBUTION PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
